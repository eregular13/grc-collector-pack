"""Parse dropped nbtscan name/IP tables. No subprocess. No live NetBIOS."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from shared.io_util import read_text
from shared.netdiscover import looks_like_netdiscover

MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
LINE_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)(?:\s+(.*))?$"
)
HOST_RE = re.compile(r"NetBIOS Name Table for Host\s+(\d{1,3}(?:\.\d{1,3}){3})", re.I)
NBT_MARK = re.compile(r"<(?:server|unknown|00|20|1[bcde])>", re.I)
_BANNERS = (
    "doing nbt name scan",
    "nbt name scan",
    "netbios name",
    "nbtscan",
)
_SKIP_HEAD = (
    "ip address",
    "netbios name",
    "doing nbt",
    "incomplete packet",
    "name             service",
)


def _named(name: str) -> bool:
    return "nbtscan" in name.lower()


def _is_mac(token: str) -> bool:
    return bool(MAC_RE.fullmatch(token.strip()))


def _maybe_hostname(token: str) -> str:
    raw = token.strip().strip(",")
    if not raw or _is_mac(raw) or IP_RE.match(raw):
        return ""
    if raw.startswith("<") and raw.endswith(">"):
        return ""
    if not any(c.isalpha() for c in raw):
        return ""
    if "." in raw:
        return raw
    return ""


def _banner(text: str) -> bool:
    low = text[:12000].lower()
    return any(token in low for token in _BANNERS)


def _looks_fping(text: str) -> bool:
    low = text.lower()
    return " is alive" in low or " is unreachable" in low


def _looks_arp_banner(text: str) -> bool:
    low = text[:12000].lower()
    return "starting arp-scan" in low or "ending arp-scan" in low


def looks_like_nbtscan(text: str, name: str = "") -> bool:
    if _named(name):
        return True
    if looks_like_netdiscover(text, name) or _looks_arp_banner(text) or _looks_fping(text):
        return False
    if _banner(text):
        return True
    for line in text.splitlines():
        if _row_from_line(line) is not None:
            return True
    return False


def _row_from_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    low = stripped.lower()
    if any(low.startswith(h) for h in _SKIP_HEAD):
        return None
    if set(stripped) <= set("-_="):
        return None
    if " is alive" in low or " is unreachable" in low:
        return None
    match = LINE_RE.match(stripped)
    if not match:
        return None
    addr, second, rest = match.group(1), match.group(2), (match.group(3) or "").strip()
    if _is_mac(second):
        return None
    tokens = rest.split() if rest else []
    blob = f"{second} {rest}"
    if not (NBT_MARK.search(blob) or MAC_RE.search(rest) or _maybe_hostname(tokens[-1] if tokens else "")):
        return None
    netbios = second
    mac = ""
    hostname = ""
    user = ""
    leftover: list[str] = []
    for tok in tokens:
        if _is_mac(tok):
            mac = tok
            continue
        hostish = _maybe_hostname(tok)
        if hostish:
            hostname = hostish
            continue
        if tok.startswith("<") and tok.endswith(">"):
            continue
        leftover.append(tok)
    if leftover and leftover[0].upper() not in {netbios.upper(), "<SERVER>", "<UNKNOWN>"}:
        user = leftover[0]
    name = hostname or netbios or addr
    if not name:
        return None
    return {
        "name": name,
        "addr": addr,
        "hostname": hostname,
        "netbios": netbios,
        "mac": mac,
        "user": user,
        "ports": [],
    }


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


def _looks_json_row(row: dict[str, Any]) -> bool:
    if row.get("port") not in (None, ""):
        return False
    ports = row.get("ports")
    if isinstance(ports, list) and ports:
        return False
    if not (row.get("ip") or row.get("addr") or row.get("address")):
        return False
    if row.get("netbios") or row.get("nbt") or row.get("name") or row.get("hostname"):
        return True
    return row.get("scanner") == "nbtscan" or row.get("tool") == "nbtscan"


def _host_from_row(row: dict[str, Any]) -> dict[str, Any] | None:
    if not _looks_json_row(row):
        return None
    addr = str(row.get("ip") or row.get("addr") or row.get("address") or "").strip()
    hostname = str(row.get("hostname") or row.get("host") or row.get("fqdn") or "").strip()
    netbios = str(row.get("netbios") or row.get("nbt") or row.get("name") or "").strip()
    if hostname and IP_RE.match(hostname):
        if not addr:
            addr = hostname
        hostname = ""
    if netbios and IP_RE.match(netbios):
        if not addr:
            addr = netbios
        netbios = ""
    mac = ""
    mac_m = MAC_RE.search(str(row.get("mac") or row.get("mac_address") or ""))
    if mac_m:
        mac = mac_m.group(0)
    name = hostname or netbios or addr
    if not name:
        return None
    return {
        "name": name,
        "addr": addr,
        "hostname": hostname,
        "netbios": netbios,
        "mac": mac,
        "user": str(row.get("user") or ""),
        "ports": [],
    }


def _from_text(text: str) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    current_ip = ""
    for line in text.splitlines():
        host_m = HOST_RE.search(line)
        if host_m:
            current_ip = host_m.group(1)
            continue
        row = _row_from_line(line)
        if row is None and current_ip:
            parts = line.split()
            if parts and not IP_RE.match(parts[0]) and NBT_MARK.search(line) and "UNIQUE" in line.upper():
                netbios = parts[0]
                name = netbios
                row = {
                    "name": name,
                    "addr": current_ip,
                    "hostname": "",
                    "netbios": netbios,
                    "mac": "",
                    "user": "",
                    "ports": [],
                }
        if row is None:
            continue
        key = str(row["name"]).lower()
        grouped.setdefault(key, row)
    return list(grouped.values())


def parse_nbtscan(path: Path, raw: str | None = None) -> list[dict[str, Any]] | None:
    """Return hosts (asset-only), or None when the file is not nbtscan."""
    text = raw if raw is not None else read_text(path)
    stripped = text.lstrip("\ufeff").lstrip()
    if stripped.startswith("<"):
        return None
    named = _named(path.name)
    if not named:
        if looks_like_netdiscover(text, path.name) or _looks_arp_banner(text) or _looks_fping(text):
            return None
        if not looks_like_nbtscan(text, path.name):
            return None
    is_jsonish = (
        stripped.startswith("{")
        or stripped.startswith("[")
        or path.suffix.lower() in {".json", ".jsonl"}
    )
    if is_jsonish:
        payload = _load_payload(text)
        rows = payload if isinstance(payload, list) else []
        if isinstance(payload, dict):
            inner = payload.get("hosts") or payload.get("data") or payload.get("results")
            if isinstance(inner, list):
                rows = inner
            else:
                rows = [payload]
        out: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            host = _host_from_row(row)
            if host is not None:
                out.append(host)
        return out
    return _from_text(text)
