"""Parse dropped Entra / Okta / Google user-inventory exports.

Parse-only. Does not call Microsoft Graph, Okta, or Google Directory.
Empty / pass-only / missing MFA fields invent nothing.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

STALE_GUEST_DAYS = 90

_PRIVILEGED = (
    "global administrator",
    "company administrator",
    "privileged role administrator",
    "application administrator",
    "super_admin",
    "super admin",
    "org_admin",
    "org admin",
    "app_admin",
)

_MFA_TRUE = frozenset({"true", "1", "yes", "registered", "enrolled", "enabled", "on"})
_MFA_FALSE = frozenset({"false", "0", "no", "not registered", "unenrolled", "disabled", "off", "none"})


def _parse_dt(raw: Any) -> datetime | None:
    text = str(raw or "").strip()
    if not text or text.lower() in {"none", "null", "never", "n/a", "na"}:
        return None
    text = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _as_bool(raw: Any) -> bool | None:
    if raw is True:
        return True
    if raw is False:
        return False
    token = str(raw or "").strip().lower()
    if token in _MFA_TRUE:
        return True
    if token in _MFA_FALSE:
        return False
    return None


def _is_guest(user: dict[str, Any]) -> bool:
    utype = str(user.get("userType") or user.get("user_type") or user.get("type") or "")
    if utype.lower() in {"guest", "external", "b2b"}:
        return True
    if _as_bool(user.get("isGuest") or user.get("is_guest") or user.get("guest")) is True:
        return True
    ou = str(user.get("orgUnitPath") or user.get("org_unit") or "")
    return "guest" in ou.lower()


def _roles(user: dict[str, Any]) -> list[str]:
    raw = (
        user.get("assignedRoles")
        or user.get("assigned_roles")
        or user.get("roles")
        or user.get("directoryRoles")
        or []
    )
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            name = str(item.get("displayName") or item.get("name") or item.get("role") or "")
        else:
            name = str(item or "")
        if name:
            out.append(name)
    if _as_bool(user.get("isAdmin") or user.get("is_admin")) is True and "Global Administrator" not in out:
        out.append("Global Administrator")
    return out


def _privileged(roles: list[str]) -> list[str]:
    hits: list[str] = []
    for role in roles:
        low = role.lower().replace("-", " ")
        if any(p in low for p in _PRIVILEGED):
            hits.append(role)
    return hits


def _mfa_registered(user: dict[str, Any]) -> bool | None:
    for key in (
        "isMfaRegistered",
        "mfaRegistered",
        "isMfaCapable",
        "isEnrolledIn2Sv",
        "is_enrolled_in_2sv",
        "twoStepVerification",
        "mfa",
    ):
        if key in user:
            return _as_bool(user.get(key))
    methods = user.get("authenticationMethods") or user.get("registeredAuthenticators")
    if isinstance(methods, list):
        return len(methods) > 0
    if "factors" in user:
        factors = user.get("factors")
        if isinstance(factors, list):
            return len(factors) > 0
        return _as_bool(factors)
    return None


def _last_sign_in(user: dict[str, Any]) -> datetime | None:
    activity = user.get("signInActivity")
    if isinstance(activity, dict):
        return _parse_dt(
            activity.get("lastSignInDateTime")
            or activity.get("lastSuccessfulSignInDateTime")
            or activity.get("lastNonInteractiveSignInDateTime")
        )
    return _parse_dt(
        user.get("lastSignInDateTime")
        or user.get("lastLoginTime")
        or user.get("lastLogin")
        or user.get("last_login")
    )


def _stale_guest(user: dict[str, Any], now: datetime) -> bool:
    if not _is_guest(user):
        return False
    last = _last_sign_in(user)
    if last is not None:
        return (now - last).days >= STALE_GUEST_DAYS
    # Explicit never-signed-in on a guest that already has an age stamp.
    if "lastSignInDateTime" in user or "lastLoginTime" in user or "lastLogin" in user:
        created = _parse_dt(user.get("createdDateTime") or user.get("created") or user.get("creationTime"))
        if created is None:
            return True
        return (now - created).days >= STALE_GUEST_DAYS
    return False


def _login(user: dict[str, Any]) -> str:
    profile = user.get("profile") if isinstance(user.get("profile"), dict) else {}
    return str(
        user.get("userPrincipalName")
        or user.get("upn")
        or user.get("primaryEmail")
        or user.get("mail")
        or user.get("email")
        or profile.get("login")
        or profile.get("email")
        or user.get("id")
        or ""
    ).strip()


def _normalize_user(user: dict[str, Any], now: datetime) -> dict[str, Any] | None:
    name = _login(user)
    if not name:
        return None
    roles = _roles(user)
    priv = _privileged(roles)
    pim = user.get("pimEligible")
    if pim is None:
        pim = user.get("pimeligible")
    return {
        "name": name,
        "display": str(user.get("displayName") or user.get("name") or name),
        "user_type": "Guest" if _is_guest(user) else str(user.get("userType") or "Member"),
        "mfa_registered": _mfa_registered(user),
        "roles": roles,
        "privileged_roles": priv,
        "pim_eligible": _as_bool(pim),
        "is_guest": _is_guest(user),
        "stale_guest": _stale_guest(user, now),
        "last_sign_in": (_last_sign_in(user).isoformat() if _last_sign_in(user) else None),
    }


def _unwrap(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    for key in ("data", "export", "okta", "google", "workspace", "directory"):
        inner = payload.get(key)
        if isinstance(inner, (dict, list)) and inner:
            return inner
    return payload


def _user_rows(payload: Any) -> tuple[str, list[dict[str, Any]]]:
    raw = _unwrap(payload)
    tenant = ""
    rows: list[Any] = []
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, dict):
        tenant = str(
            raw.get("tenant")
            or raw.get("org")
            or raw.get("okta_org")
            or raw.get("domain")
            or raw.get("primaryDomain")
            or ""
        )
        ctx = str(raw.get("@odata.context") or "")
        if isinstance(raw.get("value"), list) and (
            "users" in ctx or any(isinstance(x, dict) and _login(x) for x in raw["value"][:3])
        ):
            rows = raw["value"]
        elif isinstance(raw.get("users"), list):
            rows = raw["users"]
        elif isinstance(raw.get("Users"), list):
            rows = raw["Users"]
    users = [u for u in rows if isinstance(u, dict)]
    if not tenant and users:
        login = _login(users[0])
        if "@" in login:
            tenant = login.split("@", 1)[1]
    return tenant, users


def is_idp_inventory(payload: Any, *, name: str = "", text: str = "") -> bool:
    """True only for user-inventory exports. Scuba / Maester / directoryRoles stay out."""
    if isinstance(payload, dict):
        if payload.get("Results") or payload.get("results") or payload.get("TestResults") or payload.get("Maester"):
            return False
        if payload.get("directoryRoles") or "directoryRoles" in str(payload.get("@odata.context") or ""):
            return False
        ctx = str(payload.get("@odata.context") or "")
        if "users" in ctx.lower() and "directoryroles" not in ctx.lower():
            return True
        kind = str(payload.get("kind") or "")
        if "directory#users" in kind or "admin#directory#users" in kind:
            return True
        _, users = _user_rows(payload)
        if users:
            sample = users[0]
            if _mfa_registered(sample) is not None:
                return True
            if _is_guest(sample) or sample.get("userType") or sample.get("signInActivity"):
                return True
            if sample.get("assignedRoles") or sample.get("isAdmin") or sample.get("isEnrolledIn2Sv"):
                return True
            if "factors" in sample:
                return True
        elif payload:
            return False
    head = (text or "")[:800].lower().replace(" ", "")
    if "userprincipalname" in head or "primaryemail" in head:
        return "mfa" in head or "2sv" in head or "usertype" in head or "isadmin" in head or "guest" in head
    low_name = (name or "").lower()
    return any(tok in low_name for tok in ("entra-users", "okta-users", "google-users", "idp-users"))


def _csv_users(text: str) -> list[dict[str, Any]]:
    sample = text[:4000]
    dialect = csv.excel
    if "," in sample or ";" in sample or "\t" in sample:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
    reader = csv.DictReader(StringIO(text), dialect=dialect)
    rows: list[dict[str, Any]] = []
    for row in reader:
        if not row:
            continue
        folded: dict[str, Any] = {}
        for key, value in row.items():
            if key is None:
                continue
            folded[str(key).strip()] = (value or "").strip()
        lower = {str(k).lower().replace(" ", "").replace(".", ""): v for k, v in folded.items()}
        mapped = {
            "userPrincipalName": (
                lower.get("userprincipalname")
                or lower.get("upn")
                or lower.get("primaryemail")
                or lower.get("email")
                or lower.get("login")
                or ""
            ),
            "displayName": lower.get("displayname") or lower.get("namefullname") or lower.get("name") or "",
            "userType": lower.get("usertype") or ("Guest" if _as_bool(lower.get("isguest") or lower.get("guest")) else ""),
            "isGuest": lower.get("isguest") or lower.get("guest") or "",
            "isMfaRegistered": (
                lower.get("ismfaregistered")
                or lower.get("mfaregistered")
                or lower.get("isenrolledin2sv")
                or lower.get("twostepverification")
                or ""
            ),
            "isAdmin": lower.get("isadmin") or "",
            "assignedRoles": lower.get("assignedroles") or lower.get("roles") or "",
            "lastLoginTime": lower.get("lastlogintime") or lower.get("lastsignindatetime") or "",
            "createdDateTime": lower.get("createddatetime") or "",
            "pimEligible": lower.get("pimeligible") or "",
            "orgUnitPath": lower.get("orgunitpath") or "",
        }
        if mapped["assignedRoles"] and isinstance(mapped["assignedRoles"], str):
            mapped["assignedRoles"] = [p.strip() for p in mapped["assignedRoles"].split("|") if p.strip()]
        if mapped["userPrincipalName"]:
            rows.append(mapped)
    return rows


def parse_idp_inventory(payload: Any, *, now: datetime | None = None, text: str = "") -> dict[str, Any] | None:
    """Return tenant + normalized users, or None when this is not an IdP inventory."""
    clock = now or datetime.now(timezone.utc)
    users_raw: list[dict[str, Any]] = []
    tenant = ""
    provider = "idp"
    if text and not (isinstance(payload, (dict, list)) and payload):
        if not is_idp_inventory({}, text=text):
            return None
        users_raw = _csv_users(text)
        if users_raw and "@" in str(users_raw[0].get("userPrincipalName") or ""):
            tenant = str(users_raw[0]["userPrincipalName"]).split("@", 1)[1]
        provider = "google" if "2sv" in text[:400].lower() or "primaryemail" in text[:400].lower() else "idp"
    elif is_idp_inventory(payload, text=text):
        tenant, users_raw = _user_rows(payload)
        blob = json.dumps(payload)[:800].lower() if isinstance(payload, (dict, list)) else ""
        if "okta" in blob or (isinstance(payload, dict) and (payload.get("org") or payload.get("okta_org"))):
            provider = "okta"
        elif "google" in blob or (isinstance(payload, dict) and "directory#users" in str(payload.get("kind") or "")):
            provider = "google"
        else:
            provider = "entra"
    else:
        return None
    users = []
    for row in users_raw:
        norm = _normalize_user(row, clock)
        if norm:
            users.append(norm)
    if not users:
        return None
    return {"provider": provider, "tenant": tenant or provider, "users": users}


def parse_idp_file(path: Path, *, now: datetime | None = None) -> dict[str, Any] | None:
    raw = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
    if path.suffix.lower() == ".csv":
        return parse_idp_inventory({}, now=now, text=raw)
    stripped = raw.lstrip()
    if stripped[:1] in "{[":
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return None
        return parse_idp_inventory(payload, now=now, text=raw)
    return parse_idp_inventory({}, now=now, text=raw)
