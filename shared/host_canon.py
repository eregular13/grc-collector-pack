"""Canonical host keys for pack assets (prior-unit).

Rules:
- casefold hostname labels
- loopback aliases fold to 127.0.0.1 (localhost, ::1, ip6-localhost, ...)
- strip trailing .local/.localdomain/.lan/.home/.internal
- strip single-label distro suffix host.debian / host.ubuntu -> host
- never merge distinct non-loopback IPs
Callers/ledger should keep original names as aliases.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

_LOOPBACK_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }
)
_TAIL_DROP = frozenset({"local", "localdomain", "lan", "home", "internal"})
_DISTRO_ONE = frozenset(
    {"debian", "ubuntu", "fedora", "centos", "rhel", "redhat", "suse", "opensuse", "arch", "alpine"}
)


def is_loopback_host(text: str) -> bool:
    t = (text or "").strip().lower().rstrip(".")
    if not t:
        return False
    if t in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(t).is_loopback
    except ValueError:
        return False


def canonical_host_key(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    # drop bare :port on hostname (not IPv6)
    if text.count(":") == 1 and not text.replace(":", "").replace(".", "").isdigit():
        left, right = text.rsplit(":", 1)
        if right.isdigit():
            text = left
    try:
        ip = ipaddress.ip_address(text.strip())
        if ip.is_loopback:
            return "127.0.0.1"
        return str(ip)
    except ValueError:
        pass
    host = text.strip().lower().rstrip(".")
    if host in _LOOPBACK_NAMES or is_loopback_host(host):
        return "127.0.0.1"
    parts = [p for p in host.split(".") if p]
    while len(parts) >= 2 and parts[-1] in _TAIL_DROP:
        parts = parts[:-1]
    if len(parts) == 2 and parts[-1] in _DISTRO_ONE:
        parts = parts[:1]
    return ".".join(parts) if parts else host


def host_aliases(raw: Any, canon: str | None = None) -> list[str]:
    orig = str(raw or "").strip()
    key = canon or canonical_host_key(orig)
    out: list[str] = []
    for v in (orig, orig.lower(), key):
        if v and v not in out:
            out.append(v)
    if key == "127.0.0.1":
        for v in ("localhost", "127.0.0.1", "::1"):
            if v not in out:
                out.append(v)
    return out
