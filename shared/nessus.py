"""Parse operator-landed NessusClientData / .nessus XML. No API. No subprocess."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from shared.io_util import read_text

_KEY_MEDIUM_PORTS = frozenset({"445", "3389", "23", "21"})
_KEY_MEDIUM_TEXT = (
    "smb",
    "microsoft-ds",
    "rdp",
    "remote desktop",
    "telnet",
    "admin share",
    "administrative share",
    "tls 1.0",
    "ssl version",
    "weak cipher",
)


def _tag(el: ET.Element) -> str:
    return el.tag.split("}")[-1]


def is_demo_lab_stub(text: str) -> bool:
    """Farm tool-bin DEMO .txt is not an operator Nessus export."""
    low = text.lower()
    if "farm/tool-bin/lab" in low:
        return True
    if "demo fixture-shaped, not a scan" in low:
        return True
    return (
        "not a real scanner" in low
        and "nessusclientdata" in low
        and "<reporthost" not in low
    )


def is_nessus_text(text: str, name: str = "") -> bool:
    if is_demo_lab_stub(text):
        return False
    if name.lower().endswith(".nessus"):
        return True
    low = text[:12000].lower()
    return "nessusclientdata" in low or "<reporthost" in low


def _risk_severity(item: ET.Element) -> str:
    raw = str(item.attrib.get("severity") or "").strip()
    risk = ""
    for child in list(item):
        if _tag(child) == "risk_factor":
            risk = (child.text or "").strip().lower()
            break
    if raw == "4" or risk == "critical":
        return "critical"
    if raw == "3" or risk == "high":
        return "high"
    if raw == "2" or risk == "medium":
        return "medium"
    if raw == "1" or risk == "low":
        return "low"
    if risk in {"critical", "high", "medium", "low"}:
        return risk
    return "info"


def _plugin_text(item: ET.Element) -> str:
    bits = [str(item.attrib.get("pluginName") or "")]
    for child in list(item):
        tag = _tag(child).lower()
        if tag in {"description", "synopsis", "plugin_output", "solution"}:
            bits.append(child.text or "")
    return " ".join(bits).lower()


def _keep_item(item: ET.Element, sev: str) -> bool:
    if sev in {"high", "critical"}:
        return True
    if sev != "medium":
        return False
    port = str(item.attrib.get("port") or "")
    if port in _KEY_MEDIUM_PORTS:
        return True
    blob = _plugin_text(item)
    return any(tok in blob for tok in _KEY_MEDIUM_TEXT)


def iter_nessus_items(text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    rows: list[dict[str, Any]] = []
    for host_el in root.iter():
        if _tag(host_el) != "ReportHost":
            continue
        host = str(host_el.attrib.get("name") or "").strip()
        if not host:
            for child in list(host_el):
                if _tag(child) != "HostProperties":
                    continue
                for tag_el in list(child):
                    if _tag(tag_el) == "tag" and tag_el.attrib.get("name") in {
                        "host-fqdn",
                        "host-ip",
                    }:
                        host = (tag_el.text or "").strip() or host
        host = host or "unknown"
        for item in list(host_el):
            if _tag(item) != "ReportItem":
                continue
            sev = _risk_severity(item)
            if not _keep_item(item, sev):
                continue
            title = str(item.attrib.get("pluginName") or item.attrib.get("pluginID") or "Nessus finding")
            plugin = str(item.attrib.get("pluginID") or "")
            port = str(item.attrib.get("port") or "")
            svc = str(item.attrib.get("svc_name") or "")
            desc = title
            for child in list(item):
                if _tag(child) == "description" and (child.text or "").strip():
                    desc = (child.text or "").strip()
                    break
            rows.append(
                {
                    "host": host,
                    "name": title,
                    "description": desc,
                    "severity": sev,
                    "port": port,
                    "service": svc,
                    "plugin_id": plugin,
                }
            )
    return rows


def parse_nessus(path: Path) -> list[dict[str, Any]] | None:
    """Return Nessus rows, or None when the file is not an operator export."""
    text = read_text(path)
    if is_demo_lab_stub(text):
        return None
    if not is_nessus_text(text, path.name):
        return None
    return iter_nessus_items(text)
