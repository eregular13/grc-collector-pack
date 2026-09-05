"""Parse dropped smbmap share tables. No subprocess. No live SMB. No credentials."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from shared.io_util import read_text

IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
HOST_RE = re.compile(
    r"\[\+\]\s+(?:IP:\s*)?(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?\s+Name:\s+(\S+)",
    re.I,
)
HOST_ALT_RE = re.compile(
    r"\[\+\]\s+Host:\s+(\S+)(?:\s+Name:\s+(\S+))?",
    re.I,
)
SHARE_RE = re.compile(
    r"^\s+(\S+)\s+(NO ACCESS|READ ONLY|READ,\s*WRITE|WRITE(?: ONLY)?|READ)\b\s*(.*)$",
    re.I,
)
_BANNERS = (
    "[+] ip:",
    "finding open smb shares",
    "disk",
    "permissions",
    "smbmap",
)
_SKIP = frozenset({"disk", "----", "----", "share", "permissions", "comment"})
_SECRET = re.compile(r"(password|passwd|pass|hash|ntlm|secret)\s*[:=]", re.I)


def _named(name: str) -> bool:
    return "smbmap" in name.lower()


def _looks_nmap(text: str) -> bool:
    return "Host:" in text and "Ports:" in text


def _looks_arp(text: str) -> bool:
    low = text[:12000].lower()
    return "starting arp-scan" in low or "ending arp-scan" in low


def _looks_nbt(text: str) -> bool:
    low = text[:12000].lower()
    return "doing nbt name scan" in low or "nbt name scan" in low or "netbios name table" in low


def _looks_netdiscover(text: str) -> bool:
    low = text[:12000].lower()
    return "currently scanning" in low or "mac vendor / hostname" in low or "at mac address" in low


def _looks_fping(text: str) -> bool:
    low = text.lower()
    return " is alive" in low or " is unreachable" in low


def looks_like_smbmap(text: str, name: str = "") -> bool:
    if _named(name):
        return True
    if _looks_nmap(text) or _looks_arp(text) or _looks_nbt(text) or _looks_netdiscover(text) or _looks_fping(text):
        return False
    low = text[:12000].lower()
    if "smbmap" in low or "[+] ip:" in low or "finding open smb shares" in low:
        return True
    if "permissions" in low and ("read, write" in low or "read only" in low or "no access" in low):
        return True
    for line in text.splitlines():
        if HOST_RE.search(line) or SHARE_RE.match(line):
            return True
    return False


def _access_open(token: str) -> bool:
    up = token.upper().replace(" ", "")
    if up == "NOACCESS":
        return False
    return "READ" in up or "WRITE" in up


def _writable(token: str) -> bool:
    return "WRITE" in token.upper()


def _load_payload(text: str) -> Any:
    stripped = text.lstrip("\ufeff").lstrip()
    if not stripped:
        return []
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        rows: list[Any] = []
        for line in stripped.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in {"[", "]"}:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows


def _share_from_obj(row: dict[str, Any]) -> dict[str, str] | None:
    name = str(row.get("name") or row.get("share") or row.get("disk") or "").strip()
    if not name or name.lower() in {"disk", "share"}:
        return None
    access = str(row.get("permissions") or row.get("access") or row.get("perm") or "").strip()
    comment = str(row.get("comment") or row.get("remark") or "")
    if _SECRET.search(comment):
        comment = "[REDACTED]"
    return {"name": name, "access": access, "comment": comment}


def _host_slot(addr: str, hostname: str) -> dict[str, Any]:
    name = hostname or addr
    return {"name": name, "addr": addr, "hostname": hostname, "shares": []}


def _from_json(text: str) -> list[dict[str, Any]]:
    payload = _load_payload(text)
    rows: list[Any]
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        inner = payload.get("hosts") or payload.get("data") or payload.get("results") or payload.get("shares")
        if isinstance(inner, list) and inner and isinstance(inner[0], dict) and (
            inner[0].get("share") or inner[0].get("permissions") or inner[0].get("access")
        ) and not (payload.get("ip") or payload.get("host") or payload.get("name")):
            rows = [payload]
        elif isinstance(inner, list):
            rows = inner
        else:
            rows = [payload]
    else:
        return []
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("port") not in (None, "", 445, "445") and isinstance(row.get("ports"), list) and row.get("ports"):
            continue
        addr = str(row.get("ip") or row.get("addr") or row.get("address") or "").strip()
        hostname = str(row.get("hostname") or row.get("host") or row.get("name") or row.get("target") or "").strip()
        if hostname and IP_RE.fullmatch(hostname):
            if not addr:
                addr = hostname
            hostname = ""
        shares_raw = row.get("shares") or row.get("disks")
        shares: list[dict[str, str]] = []
        if isinstance(shares_raw, list):
            for item in shares_raw:
                if isinstance(item, dict):
                    parsed = _share_from_obj(item)
                    if parsed:
                        shares.append(parsed)
        else:
            parsed = _share_from_obj(row)
            if parsed and (row.get("share") or row.get("permissions") or row.get("access")):
                shares.append(parsed)
        if not addr and not hostname and not shares:
            continue
        name = hostname or addr
        if not name:
            continue
        slot = grouped.setdefault(name.lower(), _host_slot(addr, hostname))
        if addr and not slot.get("addr"):
            slot["addr"] = addr
        if hostname and not slot.get("hostname"):
            slot["hostname"] = hostname
            slot["name"] = hostname
        slot["shares"].extend(shares)
    return list(grouped.values())


def _from_text(text: str) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        if _SECRET.search(line) and "permissions" not in line.lower():
            continue
        host_m = HOST_RE.search(line)
        if host_m:
            addr, _port, hostname = host_m.group(1), host_m.group(2), host_m.group(3)
            if hostname.lower() in {"<unknown>", "unknown", "-"}:
                hostname = ""
            name = hostname or addr
            current = grouped.setdefault(name.lower(), _host_slot(addr, hostname))
            continue
        alt = HOST_ALT_RE.search(line)
        if alt:
            token, hostname = alt.group(1), alt.group(2) or ""
            addr = token if IP_RE.fullmatch(token) else ""
            if not hostname and not addr:
                hostname = token
            name = hostname or addr
            current = grouped.setdefault(name.lower(), _host_slot(addr, hostname))
            continue
        share_m = SHARE_RE.match(line)
        if not share_m:
            continue
        share_name = share_m.group(1)
        if share_name.lower() in _SKIP or set(share_name) <= set("-"):
            continue
        access = re.sub(r"\s+", " ", share_m.group(2).strip())
        comment = share_m.group(3).strip()
        if _SECRET.search(comment):
            comment = "[REDACTED]"
        if current is None:
            continue
        current["shares"].append({"name": share_name, "access": access, "comment": comment})
    return list(grouped.values())


def parse_smbmap(path: Path, raw: str | None = None) -> list[dict[str, Any]] | None:
    """Return hosts with share rows, or None when the file is not smbmap."""
    text = raw if raw is not None else read_text(path)
    stripped = text.lstrip("\ufeff").lstrip()
    if stripped.startswith("<"):
        return None
    named = _named(path.name)
    if not named:
        if _looks_nmap(text) or _looks_arp(text) or _looks_nbt(text) or _looks_netdiscover(text) or _looks_fping(text):
            return None
        if not looks_like_smbmap(text, path.name):
            return None
    is_jsonish = (
        stripped.startswith("{")
        or (stripped.startswith("[") and not stripped.startswith("[+]"))
        or path.suffix.lower() in {".json", ".jsonl"}
    )
    if is_jsonish:
        return _from_json(text)
    return _from_text(text)
