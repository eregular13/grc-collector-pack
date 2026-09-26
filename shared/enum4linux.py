"""Parse dropped enum4linux-ng JSON or text. No subprocess. No credentials."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from shared.io_util import read_text

IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
TARGET_RE = re.compile(r"Target\s+\.+\s+(\S+)", re.I)
GROUP_RE = re.compile(r"group:\[([^\]]+)\]", re.I)
SHARE_MAP_RE = re.compile(
    r"//\S+/(\S+)\s+Mapping:\s+(OK|DENIED|N/A|FAIL)"
    r"(?:,\s*Listing:\s+(OK|DENIED|N/A|FAIL))?"
    r"(?:,\s*Writ(?:e|ing):\s+(OK|DENIED|N/A|FAIL))?",
    re.I,
)
_WRITE_OK = frozenset({"OK", "TRUE", "YES", "WRITE", "WRITABLE", "READ/WRITE", "READWRITE"})
NULL_RE = re.compile(r"null\s+session|sessions?\s+using username\s+['\"]['\"]", re.I)
_BANNERS = (
    "enum4linux",
    "share enumeration",
    "smb domain info",
    "users on",
    "target information",
)


def _named(name: str) -> bool:
    low = name.lower().replace("_", "-")
    return "enum4linux" in low or "e4l-ng" in low or low.startswith("e4l")


def _looks_bloodhound(payload: Any, text: str) -> bool:
    if "objectidentifier" in text[:4000].lower() or '"aces"' in text[:4000].lower():
        return True
    if isinstance(payload, dict):
        if payload.get("ObjectIdentifier") or payload.get("objectid"):
            return True
        data = payload.get("data")
        if isinstance(data, dict) and (data.get("nodes") or data.get("edges")):
            return True
        meta = payload.get("meta")
        if isinstance(meta, dict) and meta.get("type") in {
            "users",
            "computers",
            "groups",
            "domains",
            "ous",
        }:
            return True
    return False


def _looks_hk(text: str, name: str) -> bool:
    if name.lower().endswith(".csv"):
        return True
    head = text[:400]
    return "Severity" in head and "," in text[:200]


def looks_like_enum4linux(text: str, name: str = "", payload: Any = None) -> bool:
    if _named(name):
        return True
    if _looks_hk(text, name) or _looks_bloodhound(payload, text):
        return False
    low = text[:12000].lower()
    if any(token in low for token in _BANNERS):
        return True
    if isinstance(payload, dict):
        if payload.get("smb_domain_info") or payload.get("null_session") is not None:
            return True
        sessions = payload.get("sessions")
        if isinstance(sessions, dict) and (
            "null" in sessions
            or "null_session" in sessions
            or "sessions_possible" in sessions
        ):
            return True
        if payload.get("target") and (
            payload.get("users") is not None
            or payload.get("groups") is not None
            or payload.get("shares") is not None
        ):
            return True
    return False


def _load_json(text: str) -> Any:
    stripped = text.lstrip("\ufeff").lstrip()
    if not stripped or stripped.startswith("<"):
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _iter_named(raw: Any) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    if isinstance(raw, dict):
        for key, val in raw.items():
            if isinstance(val, dict):
                out.append((str(key), val))
            elif isinstance(val, str):
                out.append((str(val), {}))
        return out
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                name = str(
                    item.get("username")
                    or item.get("groupname")
                    or item.get("name")
                    or item.get("share")
                    or ""
                )
                out.append((name, item))
            elif isinstance(item, str):
                out.append((item, {}))
    return out


def _explicit_write(row: dict[str, Any]) -> bool:
    """listing OK is READ only. WRITE only when the export says write."""
    if row.get("writable") is True or str(row.get("writable") or "").strip().upper() in _WRITE_OK:
        return True
    access = row.get("access") or row.get("permissions") or row.get("perm") or ""
    if isinstance(access, dict):
        for key in ("writing", "write", "writable"):
            if str(access.get(key) or "").strip().upper() in _WRITE_OK:
                return True
        return False
    if isinstance(access, list):
        blob = " ".join(str(x) for x in access).upper()
        return bool(re.search(r"\bWRITE", blob))
    return bool(re.search(r"\bWRITE", str(access).upper()))


def _share_access(row: dict[str, Any]) -> str:
    access = row.get("access") or row.get("permissions") or row.get("perm") or ""
    write = _explicit_write(row)
    if isinstance(access, dict):
        mapping = str(access.get("mapping") or "").strip().upper()
        listing = str(access.get("listing") or "").strip().upper()
        if write and (listing == "OK" or mapping == "OK"):
            return "READ, WRITE"
        if write:
            return "WRITE"
        if listing == "OK" or mapping == "OK":
            return "READ"
        parts = []
        if mapping:
            parts.append(f"mapping={mapping}")
        if listing:
            parts.append(f"listing={listing}")
        return ", ".join(parts)
    if write:
        return "READ, WRITE" if isinstance(access, list) or str(access).strip() else "WRITE"
    if isinstance(access, list):
        return ", ".join(str(x) for x in access)
    text = str(access)
    if re.search(r"\bWRITE", text.upper()):
        return text
    return text


def _writable(access: str) -> bool:
    return bool(re.search(r"\bWRITE", access.upper()))


def _target_host(payload: dict[str, Any]) -> str:
    """enum4linux-ng JSON uses target.host; never stringify the dict."""
    raw = payload.get("target")
    if isinstance(raw, dict):
        return str(raw.get("host") or raw.get("ip") or raw.get("hostname") or "").strip()
    if raw not in (None, ""):
        return str(raw).strip()
    return str(
        payload.get("hostname") or payload.get("host") or payload.get("name") or ""
    ).strip()


def _null_session(payload: dict[str, Any], sessions: dict[str, Any]) -> bool:
    """Real ng key is sessions.null (AUTH_NULL). Keep sessions.null_session for old drops."""
    if payload.get("null_session") is not None:
        return bool(payload.get("null_session"))
    if sessions.get("null") is not None:
        return bool(sessions.get("null"))
    if sessions.get("null_session") is not None:
        return bool(sessions.get("null_session"))
    return False


def _host_from_json(payload: dict[str, Any]) -> dict[str, Any] | None:
    target = _target_host(payload)
    addr = ""
    raw_target = payload.get("target")
    smb = payload.get("smb_domain_info") if isinstance(payload.get("smb_domain_info"), dict) else {}
    fqdn = str(smb.get("FQDN") or smb.get("fqdn") or "").strip()
    netbios_name = str(
        smb.get("NetBIOS computer name") or smb.get("netbios_computer") or ""
    ).strip()
    domain = str(
        smb.get("NetBIOS domain name") or smb.get("DNS domain") or smb.get("domain") or ""
    ).strip()
    if isinstance(raw_target, dict):
        addr = str(raw_target.get("ip") or "").strip()
        if not addr and IP_RE.fullmatch(str(raw_target.get("host") or "").strip()):
            addr = str(raw_target.get("host")).strip()
    if IP_RE.fullmatch(target):
        addr = target
        target = netbios_name or str(smb.get("hostname") or "") or target
    elif not addr:
        blob = target if not isinstance(raw_target, dict) else str(raw_target.get("host") or "")
        found = IP_RE.search(blob)
        if found:
            addr = found.group(0)
    sessions = payload.get("sessions") if isinstance(payload.get("sessions"), dict) else {}
    null_session = _null_session(payload, sessions)
    groups = []
    for name, _row in _iter_named(payload.get("groups")):
        label = str(_row.get("groupname") or _row.get("name") or name).strip()
        if label:
            groups.append(label)
    users = []
    for name, _row in _iter_named(payload.get("users")):
        label = str(_row.get("username") or _row.get("name") or name).strip()
        if label and not label.isdigit():
            users.append(label)
    shares = []
    for name, row in _iter_named(payload.get("shares")):
        label = str(row.get("name") or row.get("share") or name).strip()
        if not label:
            continue
        shares.append({"name": label, "access": _share_access(row)})
    if not target and not addr and not groups and not shares and not null_session:
        return None
    name = target or addr
    if not name:
        return None
    return {
        "name": name,
        "addr": addr,
        "null_session": null_session,
        "groups": groups,
        "users": users,
        "shares": shares,
        "fqdn": fqdn,
        "netbios": netbios_name,
        "domain": domain,
    }


def _from_text(text: str) -> dict[str, Any] | None:
    name = ""
    addr = ""
    tgt = TARGET_RE.search(text)
    if tgt:
        token = tgt.group(1).strip().strip("'\"")
        if IP_RE.fullmatch(token):
            addr = token
            name = token
        else:
            name = token
    groups = [m.group(1).strip() for m in GROUP_RE.finditer(text)]
    shares: list[dict[str, str]] = []
    for match in SHARE_MAP_RE.finditer(text):
        share = match.group(1).rstrip("\\")
        mapping = (match.group(2) or "").upper()
        listing = (match.group(3) or "").upper()
        writing = (match.group(4) or "").upper()
        if writing in _WRITE_OK and (listing == "OK" or mapping == "OK"):
            access = "READ, WRITE"
        elif writing in _WRITE_OK:
            access = "WRITE"
        elif listing == "OK" or mapping == "OK":
            access = "READ"
        else:
            access = "NO ACCESS"
        shares.append({"name": share, "access": access})
    null_session = bool(NULL_RE.search(text))
    if not name and not addr and not groups and not shares and not null_session:
        return None
    return {
        "name": name or addr or "enum-host",
        "addr": addr,
        "null_session": null_session,
        "groups": groups,
        "users": [],
        "shares": shares,
    }


def parse_enum4linux(path: Path, raw: str | None = None) -> list[dict[str, Any]] | None:
    """Return hosts with listed users/groups/shares, or None when not enum4linux-ng."""
    text = raw if raw is not None else read_text(path)
    stripped = text.lstrip("\ufeff").lstrip()
    if stripped.startswith("<"):
        return None
    if _looks_hk(text, path.name):
        return None
    payload = _load_json(text)
    if _looks_bloodhound(payload, text):
        return None
    named = _named(path.name)
    if not (named or looks_like_enum4linux(text, path.name, payload)):
        return None
    if payload is not None and isinstance(payload, (dict, list)):
        rows = payload if isinstance(payload, list) else [payload]
        out: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            host = _host_from_json(row)
            if host is not None:
                out.append(host)
        return out
    host = _from_text(text)
    return [host] if host is not None else []
