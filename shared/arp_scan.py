"""Parse dropped arp-scan text or JSON. No subprocess. No live ARP."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from shared.io_util import read_text
from shared.netdiscover import looks_like_netdiscover

MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
LINE_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\s*(.*)$"
)
_VENDOR_TAIL = frozenset(
    {"inc.", "inc", "ltd.", "ltd", "llc", "llc.", "corp.", "corp", "co.", "gmbh", "sa", "ag", "plc"}
)


def _named(name: str) -> bool:
    low = name.lower().replace("_", "-")
    return "arp-scan" in low or "arpscan" in low


def _has_banner(text: str) -> bool:
    low = text[:12000].lower()
    return "starting arp-scan" in low or "ending arp-scan" in low


def _maybe_hostname(token: str) -> str:
    raw = token.strip().strip(",")
    if not raw or raw.lower() in _VENDOR_TAIL:
        return ""
    if not any(c.isalpha() for c in raw):
        return ""
    if "." in raw or "-" in raw:
        return raw
    return ""


def _looks_arp_json_row(row: dict[str, Any]) -> bool:
    mac = str(row.get("mac") or row.get("mac_address") or row.get("hwaddr") or row.get("hardware") or "")
    if not mac or not MAC_RE.search(mac):
        return False
    if not (row.get("ip") or row.get("addr") or row.get("address") or row.get("ipv4")):
        return False
    if row.get("port") not in (None, ""):
        return False
    ports = row.get("ports")
    if isinstance(ports, list) and ports:
        return False
    return True


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


def _rows_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    if payload.get("scanner") == "arp-scan" or payload.get("tool") == "arp-scan":
        raw = payload.get("hosts") or payload.get("data") or payload.get("results")
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
        if _looks_arp_json_row(payload):
            return [payload]
        return []
    for key in ("hosts", "data", "results"):
        raw = payload.get(key)
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
        if isinstance(raw, dict) and _looks_arp_json_row(raw):
            return [raw]
    if _looks_arp_json_row(payload):
        return [payload]
    return []


def _host_from_row(row: dict[str, Any]) -> dict[str, Any] | None:
    if not _looks_arp_json_row(row):
        return None
    addr = str(row.get("ip") or row.get("addr") or row.get("address") or row.get("ipv4") or "").strip()
    mac_m = MAC_RE.search(str(row.get("mac") or row.get("mac_address") or row.get("hwaddr") or row.get("hardware") or ""))
    mac = mac_m.group(0) if mac_m else ""
    hostname = str(row.get("hostname") or row.get("name") or row.get("host") or row.get("dns") or "").strip()
    if hostname and hostname.replace(".", "").isdigit():
        if not addr:
            addr = hostname
        hostname = ""
    vendor = str(row.get("vendor") or row.get("oui") or row.get("company") or "").strip()
    name = hostname or addr
    if not name:
        return None
    return {"name": name, "addr": addr, "hostname": hostname, "mac": mac, "vendor": vendor, "ports": []}


def _host_from_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    low = stripped.lower()
    if low.startswith("starting arp-scan") or low.startswith("ending arp-scan"):
        return None
    if low.startswith("interface:") or low.startswith("host:"):
        return None
    match = LINE_RE.match(stripped)
    if not match:
        return None
    addr, mac, rest = match.group(1), match.group(2), match.group(3).strip()
    hostname = ""
    vendor = rest
    if rest:
        tokens = rest.split()
        maybe = _maybe_hostname(tokens[-1]) if tokens else ""
        if maybe:
            hostname = maybe
            vendor = " ".join(tokens[:-1]).strip()
    name = hostname or addr
    if not name:
        return None
    return {"name": name, "addr": addr, "hostname": hostname, "mac": mac, "vendor": vendor, "ports": []}


def _from_text(text: str) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        host = _host_from_line(line)
        if host is None:
            continue
        key = str(host["name"]).lower()
        slot = grouped.setdefault(key, host)
        if host.get("mac") and not slot.get("mac"):
            slot["mac"] = host["mac"]
        if host.get("vendor") and not slot.get("vendor"):
            slot["vendor"] = host["vendor"]
        if host.get("hostname") and not slot.get("hostname"):
            slot["hostname"] = host["hostname"]
            slot["name"] = host["hostname"]
    return list(grouped.values())


def _from_json(text: str) -> list[dict[str, Any]]:
    payload = _load_payload(text)
    grouped: dict[str, dict[str, Any]] = {}
    for row in _rows_from_payload(payload):
        host = _host_from_row(row)
        if host is None:
            continue
        key = str(host["name"]).lower()
        grouped.setdefault(key, host)
    return list(grouped.values())


def _looks_arp_text(text: str, name: str = "") -> bool:
    if looks_like_netdiscover(text, name) and not _named(name):
        return False
    if _has_banner(text):
        return True
    if "Host:" in text and "Ports:" in text:
        return False
    hits = 0
    for line in text.splitlines():
        if _host_from_line(line) is not None:
            hits += 1
            if hits >= 1:
                return True
    return False


def parse_arp_scan(path: Path, raw: str | None = None) -> list[dict[str, Any]] | None:
    """Return hosts (asset-only), or None when the file is not arp-scan."""
    text = raw if raw is not None else read_text(path)
    stripped = text.lstrip("\ufeff").lstrip()
    if stripped.startswith("<"):
        return None
    named = _named(path.name)
    if looks_like_netdiscover(text, path.name) and not named:
        return None
    is_jsonish = (
        stripped.startswith("{")
        or stripped.startswith("[")
        or path.suffix.lower() in {".json", ".jsonl"}
    )
    if is_jsonish:
        payload = _load_payload(text)
        rows = _rows_from_payload(payload)
        arp_rows = [r for r in rows if _looks_arp_json_row(r)]
        if named:
            out: list[dict[str, Any]] = []
            for row in arp_rows:
                host = _host_from_row(row)
                if host is not None:
                    out.append(host)
            return out
        if not arp_rows:
            return None
        if any(
            r.get("port") not in (None, "")
            or (isinstance(r.get("ports"), list) and r.get("ports"))
            for r in rows[:5]
            if isinstance(r, dict)
        ):
            return None
        return _from_json(text)
    if named or _looks_arp_text(text, path.name):
        return _from_text(text)
    return None
