from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.io_util import discover_input_files, emit, load_structured
from shared.schema import asset, control_extra, evidence, finding

SOURCE = "saas_idp"
PREFIX = "SAAS-"


def _okta_login(user: dict[str, Any]) -> str:
    profile = user.get("profile") if isinstance(user.get("profile"), dict) else {}
    return str(
        profile.get("login")
        or profile.get("email")
        or user.get("login")
        or user.get("email")
        or user.get("id")
        or "okta-user"
    )


def _okta_provider_type(user: dict[str, Any]) -> str:
    creds = user.get("credentials") if isinstance(user.get("credentials"), dict) else {}
    provider = creds.get("provider")
    if isinstance(provider, str):
        return provider.strip().upper()
    if isinstance(provider, dict):
        return str(provider.get("type") or provider.get("name") or "").strip().upper()
    return ""


def _okta_factors(user: dict[str, Any]) -> list[dict[str, Any]]:
    raw = user.get("factors")
    embedded = user.get("_embedded") if isinstance(user.get("_embedded"), dict) else {}
    if raw is None:
        raw = embedded.get("factors")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _okta_has_mfa(user: dict[str, Any]) -> bool:
    """True when factors exist or credentials.provider is federated (not local password)."""
    if user.get("mfa") is True or user.get("mfaEnabled") is True:
        return True
    if user.get("mfa") is False or user.get("mfaEnabled") is False:
        return False
    creds = user.get("credentials") if isinstance(user.get("credentials"), dict) else {}
    if creds.get("mfa") is True or creds.get("mfaEnabled") is True:
        return True
    factors = _okta_factors(user)
    if factors:
        for factor in factors:
            status = str(factor.get("status") or "ACTIVE").strip().upper()
            ftype = str(factor.get("factorType") or factor.get("factor_type") or "").strip().lower()
            if ftype in {"question", "security_question"}:
                continue
            if status in {"ACTIVE", "ENROLLED", "PENDING_ACTIVATION"}:
                return True
        return False
    ptype = _okta_provider_type(user)
    if ptype in {"FEDERATION", "SOCIAL", "SAML", "OIDC"}:
        return True
    if ptype in {"OKTA", "LDAP", "ACTIVE_DIRECTORY", "IMPORT", "AD"}:
        return False
    return True


def _okta_is_admin(user: dict[str, Any]) -> bool:
    login = _okta_login(user).lower()
    if "admin" in login:
        return True
    role = str(user.get("role") or user.get("userType") or "").upper()
    if "ADMIN" in role:
        return True
    profile = user.get("profile") if isinstance(user.get("profile"), dict) else {}
    title = str(profile.get("title") or profile.get("userType") or "").upper()
    return "ADMIN" in title


def _is_okta_user(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    creds = item.get("credentials")
    if isinstance(creds, dict) and creds.get("provider") is not None:
        return True
    profile = item.get("profile")
    if isinstance(profile, dict) and (profile.get("login") or profile.get("email")):
        return True
    return False


def parse_okta_users(users: list[Any], *, org: str = "") -> list:
    """Okta GET /api/v1/users list. MFA gap when credentials.provider is local and no factors."""
    records: list = []
    for user in users:
        if not isinstance(user, dict) or not _is_okta_user(user):
            continue
        login = _okta_login(user)
        admin = _okta_is_admin(user)
        ptype = _okta_provider_type(user) or "UNKNOWN"
        records.append(
            asset(
                PREFIX,
                login,
                login,
                description=f"Okta user {login} provider={ptype}",
                asset_type="PR" if admin else "SP",
                source=SOURCE,
                labels=["saas", "okta", "user"] + (["admin"] if admin else []),
            )
        )
        if _okta_has_mfa(user):
            continue
        sev = "critical" if admin else "high"
        related = [login]
        if org:
            related = [org, login]
        records.append(
            finding(
                PREFIX,
                f"OKTA-MFA-{login}",
                f"Okta user without MFA: {login}",
                description=(
                    f"{login} has credentials.provider type={ptype or 'OKTA'} "
                    f"with no MFA factors ({'admin' if admin else 'user'})."
                ),
                severity=sev,
                source=SOURCE,
                related_assets=related,
                labels=["saas", "okta", "mfa-gap", ptype.lower() or "okta"],
                extra=control_extra(
                    "CTL-OKTA-MFA",
                    "Enforce MFA on all Okta admins",
                    csf_function="protect",
                    priority="1",
                ),
            )
        )
    return records


def _graph_text(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    return str(value).strip().strip("\"'")


def _graph_upn(user: dict[str, Any]) -> str:
    return _graph_text(
        user.get("userPrincipalName")
        or user.get("user_principal_name")
        or user.get("mail")
        or user.get("id")
    )


def _is_graph_registration(item: Any) -> bool:
    """Microsoft Graph userRegistrationDetails row (not Okta /api/v1/users)."""
    if not isinstance(item, dict) or _is_okta_user(item):
        return False
    upn = _graph_upn(item)
    if not upn:
        return False
    if "isMfaRegistered" in item or "is_mfa_registered" in item:
        return True
    if "isMfaCapable" in item or "is_mfa_capable" in item:
        return True
    if item.get("methodsRegistered") is not None or item.get("methods_registered") is not None:
        return True
    if "isAdmin" in item or "is_admin" in item:
        return True
    return False


def _graph_value_users(doc: dict[str, Any]) -> list[dict[str, Any]]:
    ctx = str(doc.get("@odata.context") or "")
    blobs: list[Any] = []
    for key in ("value", "userRegistrationDetails", "user_registration_details"):
        if key in doc:
            blobs.append(doc.get(key))
    users: list[dict[str, Any]] = []
    for blob in blobs:
        if isinstance(blob, list):
            users.extend(x for x in blob if isinstance(x, dict))
        elif isinstance(blob, dict):
            users.append(blob)
    if users and (
        "userRegistrationDetails" in ctx
        or all(_is_graph_registration(u) for u in users)
    ):
        return [u for u in users if _is_graph_registration(u)]
    return []


def _graph_is_admin(user: dict[str, Any]) -> bool:
    if user.get("isAdmin") is True or user.get("is_admin") is True:
        return True
    if user.get("isAdmin") is False or user.get("is_admin") is False:
        blob = f"{_graph_upn(user)} {_graph_text(user.get('userDisplayName') or user.get('displayName'))}".lower()
        return "breakglass" in blob or "global admin" in blob
    blob = f"{_graph_upn(user)} {_graph_text(user.get('userDisplayName') or user.get('displayName'))}".lower()
    return "admin" in blob or "breakglass" in blob


def _graph_mfa_registered(user: dict[str, Any]) -> bool:
    """True when isMfaRegistered or a non-empty methodsRegistered list."""
    if user.get("isMfaRegistered") is True or user.get("is_mfa_registered") is True:
        return True
    if user.get("isMfaRegistered") is False or user.get("is_mfa_registered") is False:
        return False
    methods = user.get("methodsRegistered")
    if methods is None:
        methods = user.get("methods_registered")
    if isinstance(methods, list) and any(_graph_text(m) for m in methods):
        return True
    return False


def _graph_tenant_from_users(users: list[dict[str, Any]]) -> str:
    for user in users:
        upn = _graph_upn(user)
        if "@" in upn:
            return upn.rsplit("@", 1)[-1].strip().lower()
    return ""


def parse_graph_registration(users: list[Any], *, tenant: str = "") -> list:
    """Graph GET /reports/authenticationMethods/userRegistrationDetails. MFA gap when not registered."""
    rows = [u for u in users if isinstance(u, dict) and _is_graph_registration(u)]
    records: list = []
    tenant = tenant or _graph_tenant_from_users(rows)
    if tenant:
        records.append(
            asset(
                PREFIX,
                tenant,
                tenant,
                description=f"Entra tenant {tenant} (Graph userRegistrationDetails)",
                asset_type="PR",
                source=SOURCE,
                labels=["saas", "entra", "graph", "tenant"],
            )
        )
    for user in rows:
        upn = _graph_upn(user)
        if not upn:
            continue
        utype = _graph_text(user.get("userType") or user.get("user_type")).lower() or "member"
        admin = _graph_is_admin(user)
        if utype == "guest" and not admin:
            continue
        records.append(
            asset(
                PREFIX,
                upn,
                upn,
                description=f"Entra user {upn} userType={utype}",
                asset_type="PR" if admin else "SP",
                source=SOURCE,
                labels=["saas", "entra", "graph", "user"] + (["admin"] if admin else []),
            )
        )
        if _graph_mfa_registered(user):
            continue
        sev = "critical" if admin else "high"
        related = [upn]
        if tenant:
            related = [tenant, upn]
        records.append(
            finding(
                PREFIX,
                f"GRAPH-MFA-{upn}",
                f"Entra user without MFA: {upn}",
                description=(
                    f"{upn} has isMfaRegistered=false "
                    f"({('admin' if admin else 'user')}, Graph userRegistrationDetails)."
                ),
                severity=sev,
                source=SOURCE,
                related_assets=related,
                labels=["saas", "entra", "graph", "mfa-gap"],
                extra=control_extra(
                    "CTL-ENTRA-MFA",
                    "Enforce MFA on Entra ID users",
                    csf_function="protect",
                    priority="1",
                ),
            )
        )
    return records


def parse_doc(doc: Any) -> list:
    if not isinstance(doc, dict):
        return []
    records: list = []
    m365 = doc.get("m365") or {}
    if isinstance(m365, dict) and m365:
        tenant = str(m365.get("tenant") or "m365-tenant")
        records.append(
            asset(
                PREFIX,
                "M365",
                tenant,
                description=f"Microsoft 365 tenant {tenant}",
                asset_type="PR",
                source=SOURCE,
                labels=["saas", "m365"],
            )
        )
        if m365.get("legacy_auth_enabled"):
            records.append(
                finding(
                    PREFIX,
                    "M365-LEGACY-AUTH",
                    "M365 legacy authentication enabled",
                    description="Basic/legacy auth protocols are enabled on the tenant.",
                    severity="high",
                    source=SOURCE,
                    related_assets=[tenant],
                    labels=["saas", "m365", "legacy-auth"],
                    extra=control_extra(
                        "CTL-M365-BLOCK-LEGACY",
                        "Block legacy authentication",
                        csf_function="protect",
                        priority="1",
                    ),
                )
            )
        for item in m365.get("findings") or []:
            if not isinstance(item, dict):
                continue
            fid = str(item.get("id") or item.get("name"))
            records.append(
                finding(
                    PREFIX,
                    fid,
                    str(item.get("name") or fid),
                    description=str(item.get("description") or item.get("name") or fid),
                    severity=str(item.get("severity") or "medium"),
                    source=SOURCE,
                    related_assets=[tenant],
                    labels=["saas", "m365", fid],
                    extra=control_extra(
                        "CTL-M365-GUEST",
                        "Restrict Entra guest access",
                        csf_function="protect",
                        priority="2",
                        category="process",
                    ),
                )
            )
    okta = doc.get("okta") or {}
    if isinstance(okta, dict) and okta:
        org = str(okta.get("org") or "okta")
        records.append(
            asset(
                PREFIX,
                "OKTA",
                org,
                description=f"Okta org {org}",
                asset_type="PR",
                source=SOURCE,
                labels=["saas", "okta"],
            )
        )
        for admin in okta.get("admins") or []:
            if not isinstance(admin, dict):
                continue
            login = str(admin.get("login") or "okta-admin")
            role = str(admin.get("role") or "ADMIN")
            records.append(
                asset(
                    PREFIX,
                    login,
                    login,
                    description=f"Okta {role} {login}",
                    asset_type="PR",
                    source=SOURCE,
                    labels=["saas", "okta", "admin"],
                )
            )
            if not admin.get("mfa", True) and "ADMIN" in role.upper():
                records.append(
                    finding(
                        PREFIX,
                        f"OKTA-MFA-{login}",
                        f"Okta admin without MFA: {login}",
                        description=f"{login} has role {role} with MFA disabled.",
                        severity="critical",
                        source=SOURCE,
                        related_assets=[org, login],
                        labels=["saas", "okta", "mfa-gap"],
                        extra=control_extra(
                            "CTL-OKTA-MFA",
                            "Enforce MFA on all Okta admins",
                            csf_function="protect",
                            priority="1",
                        ),
                    )
                )
        records.extend(parse_okta_users(okta.get("users") or [], org=org))
    if isinstance(doc.get("users"), list):
        records.extend(parse_okta_users(doc.get("users") or []))
    return records


def parse_files(files: list[Path]) -> list:
    records: list = []
    for path in files:
        loaded = load_structured(path)
        if loaded and all(_is_graph_registration(item) for item in loaded):
            records.extend(parse_graph_registration(loaded))
            continue
        if loaded and all(_is_okta_user(item) for item in loaded):
            records.extend(parse_okta_users(loaded))
            continue
        for doc in loaded:
            if isinstance(doc, dict):
                graph_users = _graph_value_users(doc)
                if graph_users:
                    records.extend(parse_graph_registration(graph_users))
                    continue
            records.extend(parse_doc(doc))
    return records


def main() -> None:
    files = discover_input_files("saas")
    records = parse_files(files)
    records.append(
        evidence(
            PREFIX,
            "SAAS",
            "M365/Okta demo parse",
            description="Parsed M365 legacy auth, Okta admin MFA gap, Okta /api/v1/users (credentials.provider), and Microsoft Graph userRegistrationDetails (isMfaRegistered). No IdP APIs called.",
            source=SOURCE,
        )
    )
    emit("saas", records, files)


if __name__ == "__main__":
    main()
