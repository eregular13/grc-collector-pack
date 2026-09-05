"""Parse dropped unicornscan text. No subprocess. No live scan."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from shared.io_util import read_text

IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
# TCP open ftp[21] from 10.0.0.50 ttl 64 [hostname]
ROW_RE = re.compile(
    r"(?P<proto>TCP|UDP)\s+open(?:\s+\S*?)?(?:\[(?P<port>\d+)\])?"
    r"(?::(?P<port2>\d+))?\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:\s+ttl\s+\d+)?(?:\s+(?P<host>\S+))?",
    re.I,
)
# TCP open 10.0.0.50:21 ttl 64
ALT_RE = re.compile(
    r"(?P<proto>TCP|UDP)\s+open\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)"
    r"(?:\s+ttl\s+\d+)?(?:\s+(?P<host>\S+))?",
    re.I,
)


def _named(name: str) -> bool:
    low = name.lower()
    return "unicornscan" in low or low.startswith("uniscan")


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
    if "currently scanning" in low or "# zmap" in low:
        return True
    return False


def looks_like_unicornscan(text: str, name: str = "") -> bool:
    if _named(name):
        return True
    if _looks_foreign(text, name):
        return False
    low = text[:8000].lower()
    if "unicornscan" in low:
        return True
    if ROW_RE.search(text) or ALT_RE.search(text):
        return True
    return False


def _port(raw: str) -> str:
    token = str(raw or "").strip()
    if token.isdigit() and 1 <= int(token) <= 65535:
        return token
    return ""


def _push(grouped: dict[str, dict[str, Any]], addr: str, hostname: str, portid: str, proto: str) -> None:
    if not portid or (not addr and not hostname):
        return
    name = hostname or addr
    key = name.lower()
    slot = grouped.setdefault(key, {"name": name, "addr": addr, "hostname": hostname, "ports": []})
    if addr and not slot.get("addr"):
        slot["addr"] = addr
    if hostname and not slot.get("hostname"):
        slot["hostname"] = hostname
        slot["name"] = hostname
    if not any(p == portid for p, _ in slot["ports"]):
        slot["ports"].append((portid, proto.lower()))


def parse_unicornscan(path: Path, raw: str | None = None) -> list[dict[str, Any]] | None:
    """Return hosts with open ports, or None when the file is not unicornscan."""
    text = raw if raw is not None else read_text(path)
    if _looks_foreign(text, path.name) and not _named(path.name):
        return None
    if not looks_like_unicornscan(text, path.name):
        return None
    grouped: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ROW_RE.search(stripped) or ALT_RE.search(stripped)
        if not match:
            continue
        addr = match.group("ip")
        portid = _port(match.groupdict().get("port") or match.groupdict().get("port2") or "")
        host = (match.groupdict().get("host") or "").strip()
        if host.lower() in {"ttl", "open", "tcp", "udp"} or IP_RE.fullmatch(host):
            host = ""
        _push(grouped, addr, host, portid, match.group("proto") or "tcp")
    return [slot for slot in grouped.values() if slot.get("ports")]
