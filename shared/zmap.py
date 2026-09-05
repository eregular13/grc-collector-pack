"""Parse dropped zmap JSON, CSV, or text. No subprocess. No live scan."""

from __future__ import annotations

import csv
import json
import re
from io import StringIO
from pathlib import Path
from typing import Any

from shared.io_util import read_text

IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
HOST_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:[,\t ]+(?P<rest>\S.*))?$",
)


def _named(name: str) -> bool:
    return "zmap" in name.lower()


def _looks_foreign(text: str, name: str) -> bool:
    low = text[:12000].lower()
    if name.lower().endswith((".xml", ".gnmap")) or text.lstrip().startswith("<"):
        return True
    if "host:" in text and "ports:" in low:
        return True
    if "[+] ip:" in low or "smbmap" in low:
        return True
    if "starting arp-scan" in low or "doing nbt name scan" in low:
        return True
    if "currently scanning" in low or "tcp open" in low and " from " in low:
        return True
    if "naabu" in low or "rustscan" in low:
        return True
    return False


def looks_like_zmap(text: str, name: str = "", payload: Any = None) -> bool:
    if _named(name):
        return True
    if _looks_foreign(text, name):
        return False
    head = text[:4000].lower()
    if "# zmap" in head or "zmap output" in head or "zmap v" in head:
        return True
    if isinstance(payload, dict) and (payload.get("saddr") or payload.get("classification")):
        return True
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        if payload[0].get("saddr") or payload[0].get("classification") == "synack":
            return True
    first = next((ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")), "")
    if first.lower().replace(" ", "") in {"saddr,dport", "saddr,ip,dport", "ip,dport"} or (
        "saddr" in first.lower() and "," in first
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
        rows: list[Any] = []
        for line in stripped.splitlines():
            line = line.strip().rstrip(",")
            if not line or line.startswith("#") or line in {"[", "]"}:
                continue
            if not line.startswith("{") and not line.startswith("["):
                return None
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                return None
        return rows or None


def _port(raw: Any) -> str:
    token = str(raw or "").strip()
    if token.isdigit() and 1 <= int(token) <= 65535:
        return token
    return ""


def _push(grouped: dict[str, dict[str, Any]], addr: str, hostname: str, portid: str) -> None:
    if not addr and not hostname:
        return
    name = hostname or addr
    key = name.lower()
    slot = grouped.setdefault(key, {"name": name, "addr": addr, "hostname": hostname, "ports": []})
    if addr and not slot.get("addr"):
        slot["addr"] = addr
    if hostname and not slot.get("hostname"):
        slot["hostname"] = hostname
        slot["name"] = hostname
    if portid and not any(p == portid for p, _ in slot["ports"]):
        slot["ports"].append((portid, ""))


def _from_row(grouped: dict[str, dict[str, Any]], row: dict[str, Any]) -> None:
    status = str(row.get("classification") or row.get("status") or row.get("success") or "open").lower()
    if status in {"closed", "fail", "failed", "0", "false", "rst"}:
        return
    addr = str(row.get("saddr") or row.get("ip") or row.get("addr") or "").strip()
    hostname = str(row.get("hostname") or row.get("host") or row.get("name") or "").strip()
    if IP_RE.fullmatch(hostname):
        if not addr:
            addr = hostname
        hostname = ""
    _push(grouped, addr, hostname, _port(row.get("dport") or row.get("port") or row.get("portid")))


def _from_csv(text: str, grouped: dict[str, dict[str, Any]]) -> None:
    sample = "\n".join(
        ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")
    )
    if not sample:
        return
    try:
        reader = csv.DictReader(StringIO(sample))
        if not reader.fieldnames:
            return
        fields = {str(f).strip().lower(): f for f in reader.fieldnames if f}
        if not ({"saddr", "ip", "addr"} & set(fields)):
            return
        for row in reader:
            if not row:
                continue
            lower = {str(k).strip().lower(): (v or "").strip() for k, v in row.items() if k}
            _from_row(grouped, lower)
    except csv.Error:
        return


def _from_text(text: str, grouped: dict[str, dict[str, Any]]) -> None:
    default_port = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if " -p " in stripped.lower() or " --target-port" in stripped.lower():
                hit = re.search(r"(?:-p|--target-port)\s+(\d+)", stripped, re.I)
                if hit:
                    default_port = _port(hit.group(1))
            continue
        if "," in stripped and not IP_RE.match(stripped.split(",", 1)[0].strip()):
            continue
        match = HOST_RE.match(stripped)
        if not match:
            continue
        addr = match.group("ip")
        rest = (match.group("rest") or "").strip()
        hostname = ""
        portid = default_port
        for token in rest.replace(",", " ").split():
            if _port(token):
                portid = _port(token)
            elif IP_RE.fullmatch(token):
                continue
            elif token.lower() not in {"tcp", "udp", "open", "synack"}:
                hostname = token
        _push(grouped, addr, hostname, portid)


def parse_zmap(path: Path, raw: str | None = None) -> list[dict[str, Any]] | None:
    """Return hosts with open ports, or None when the file is not zmap."""
    text = raw if raw is not None else read_text(path)
    if _looks_foreign(text, path.name) and not _named(path.name):
        return None
    payload = _load_json(text)
    if not ( _named(path.name) or looks_like_zmap(text, path.name, payload)):
        return None
    grouped: dict[str, dict[str, Any]] = {}
    if isinstance(payload, (dict, list)):
        rows = payload if isinstance(payload, list) else [payload]
        for row in rows:
            if isinstance(row, dict):
                _from_row(grouped, row)
        return [slot for slot in grouped.values() if slot.get("ports")]
    first = next((ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")), "")
    if first and "," in first and "saddr" in first.lower() or (first and "," in first and first.lower().split(",")[0].strip() in {"ip", "saddr", "addr"}):
        _from_csv(text, grouped)
        return [slot for slot in grouped.values() if slot.get("ports")]
    _from_text(text, grouped)
    return [slot for slot in grouped.values() if slot.get("ports")]
