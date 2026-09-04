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
    r"//\S+/(\S+)\s+Mapping:\s+(OK|DENIED|N/A|FAIL)(?:,\s*Listing:\s+(OK|DENIED|N/A|FAIL))?",
    re.I,
)
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
            "null_session" in sessions or "sessions_possible" in sessions
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


def _share_access(row: dict[str, Any]) -> str:
    access = row.get("access") or row.get("permissions") or row.get("perm") or ""
    if isinstance(access, list):
        return ", ".join(str(x) for x in access)
    return str(access)


def _writable(access: str) -> bool:
    return "WRITE" in access.upper()


def _host_from_json(payload: dict[str, Any]) -> dict[str, Any] | None:
    target = str(
        payload.get("hostname")
        or payload.get("host")
        or payload.get("name")
        or payload.get("target")
        or ""
    ).strip()
    addr = ""
    if IP_RE.fullmatch(target):
        addr = target
        netbios = payload.get("smb_domain_info")
        if isinstance(netbios, dict):
            target = str(
                netbios.get("NetBIOS computer name")
                or netbios.get("hostname")
                or target
            )
        else:
            target = addr
    elif IP_RE.search(str(payload.get("target") or "")):
        addr = IP_RE.search(str(payload.get("target"))).group(0)
    sessions = payload.get("sessions") if isinstance(payload.get("sessions"), dict) else {}
    null_session = bool(
        payload.get("null_session")
        if payload.get("null_session") is not None
        else sessions.get("null_session")
    )
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
        access = "READ, WRITE" if listing == "OK" else ("READ" if mapping == "OK" else "NO ACCESS")
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
