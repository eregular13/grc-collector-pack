"""Parse dropped sslscan XML or text. No sockets. No live TLS probes."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from shared.io_util import read_text

_WEAK_PROTO = (
    ("ssl", "2", "SSLv2"),
    ("ssl", "3", "SSLv3"),
    ("tls", "1.0", "TLS 1.0"),
    ("tls", "1.00", "TLS 1.0"),
)
_TEXT_WEAK = re.compile(
    r"^\s*(SSLv2|SSLv3|TLSv1\.0|TLS 1\.0)\s+enabled\b",
    re.I | re.M,
)
_TEXT_HOST = re.compile(
    r"Testing SSL server\s+(\S+)|Connected to\s+(\S+)|sslscan\s+(\S+)",
    re.I,
)
_TEXT_HEART = re.compile(r"vulnerable to heartbleed|heartbleed.*vulnerable", re.I)
_WEAK_CIPHER = ("rc4", "des", "export", "null", "md5", "anon")


def _tag(el: ET.Element) -> str:
    return el.tag.split("}")[-1].lower()


def is_sslscan_text(text: str, name: str = "") -> bool:
    if "sslscan" in name.lower():
        return True
    low = text[:16000].lower()
    if "<ssltest" in low or "sslscan results" in low:
        return True
    if "testing ssl server" in low or "ssl/tls protocols:" in low:
        return True
    return False


def _weak_cipher(cipher: str, bits: str) -> bool:
    blob = cipher.lower()
    if any(tok in blob for tok in _WEAK_CIPHER):
        return True
    try:
        return int(bits) < 128
    except (TypeError, ValueError):
        return False


def _from_xml(text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out: list[dict[str, Any]] = []
    tests = [el for el in root.iter() if _tag(el) == "ssltest"]
    if _tag(root) == "ssltest":
        tests = [root]
    for test in tests:
        host = str(test.attrib.get("sniname") or test.attrib.get("host") or "").strip()
        if not host:
            continue
        for child in list(test):
            tag = _tag(child)
            if tag == "protocol":
                ptype = str(child.attrib.get("type") or "").lower()
                ver = str(child.attrib.get("version") or "").lower()
                enabled = str(child.attrib.get("enabled") or "").strip() in {"1", "true", "yes"}
                if not enabled:
                    continue
                label = ""
                for want_type, want_ver, name in _WEAK_PROTO:
                    if ptype == want_type and ver == want_ver:
                        label = name
                        break
                if not label:
                    continue
                out.append(
                    {
                        "host": host,
                        "id": label.replace(" ", "").replace(".", "") or "sslscan",
                        "name": f"{label} offered",
                        "finding": f"{label} enabled on {host}",
                        "severity": "high",
                    }
                )
            elif tag == "heartbleed":
                vuln = str(child.attrib.get("vulnerable") or "").strip() in {"1", "true", "yes"}
                if not vuln:
                    continue
                out.append(
                    {
                        "host": host,
                        "id": "heartbleed",
                        "name": "heartbleed",
                        "finding": "Heartbleed still offered on TLS",
                        "severity": "high",
                        "cve": "CVE-2014-0160",
                    }
                )
            elif tag == "cipher":
                cipher = str(child.attrib.get("cipher") or child.attrib.get("name") or "")
                bits = str(child.attrib.get("bits") or "")
                status = str(child.attrib.get("status") or "accepted").lower()
                if status in {"rejected", "failed"}:
                    continue
                if not _weak_cipher(cipher, bits):
                    continue
                out.append(
                    {
                        "host": host,
                        "id": f"weak-cipher-{cipher or bits}",
                        "name": f"TLS weak cipher: {host}",
                        "finding": f"{host} presents a weak TLS cipher ({cipher or bits})",
                        "severity": "medium",
                    }
                )
    return out


def _from_text(text: str) -> list[dict[str, Any]]:
    host = "unknown"
    match = _TEXT_HOST.search(text)
    if match:
        host = next(g for g in match.groups() if g)
        host = host.split("://")[-1].split("/")[0].split(":")[0]
    out: list[dict[str, Any]] = []
    for hit in _TEXT_WEAK.finditer(text):
        token = hit.group(1).lower()
        if "sslv2" in token:
            label = "SSLv2"
        elif "sslv3" in token:
            label = "SSLv3"
        else:
            label = "TLS 1.0"
        out.append(
            {
                "host": host,
                "id": label.replace(" ", "").replace(".", ""),
                "name": f"{label} offered",
                "finding": f"{label} enabled on {host}",
                "severity": "high",
            }
        )
    if _TEXT_HEART.search(text):
        out.append(
            {
                "host": host,
                "id": "heartbleed",
                "name": "heartbleed",
                "finding": "Heartbleed still offered on TLS",
                "severity": "high",
                "cve": "CVE-2014-0160",
            }
        )
    return out


def parse_sslscan(path: Path) -> list[dict[str, Any]] | None:
    """Return weak/failed rows, or None when the file is not sslscan."""
    text = read_text(path)
    if not is_sslscan_text(text, path.name):
        return None
    stripped = text.lstrip("\ufeff")
    if stripped.startswith("<") or path.suffix.lower() == ".xml":
        return _from_xml(stripped)
    return _from_text(text)
