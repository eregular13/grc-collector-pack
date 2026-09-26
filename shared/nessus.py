"""Parse operator-landed NessusClientData / .nessus XML. No API. No subprocess."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any  # noqa: F401 — used by _ids_from_props / iter rows

from shared.asset_ids import stamp_ids
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
        props = _host_properties(host_el)
        if not host:
            host = str(props.get("host-fqdn") or props.get("host-ip") or "").strip()
        host = host or "unknown"
        ids = _ids_from_props(props)
        for item in list(host_el):
            if _tag(item) != "ReportItem":
                continue
            sev = _risk_severity(item)
            if not _keep_item(item, sev):
                continue
            title = str(item.attrib.get("pluginName") or item.attrib.get("pluginID") or "Nessus finding")
            plugin = str(item.attrib.get("pluginID") or "")
            port = str(item.attrib.get("port") or "")
            proto = str(item.attrib.get("protocol") or "")
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
                    "protocol": proto,
                    "service": svc,
                    "plugin_id": plugin,
                    "ids": ids,
                    "host_start": props.get("HOST_START") or "",
                    "id_quality": ids.get("id_quality") or "",
                }
            )
    return rows


def _host_properties(host_el: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    for child in list(host_el):
        if _tag(child) != "HostProperties":
            continue
        for tag_el in list(child):
            if _tag(tag_el) != "tag":
                continue
            name = str(tag_el.attrib.get("name") or "").strip()
            if not name:
                continue
            props[name] = (tag_el.text or "").strip()
    return props


def _ids_from_props(props: dict[str, str]) -> dict[str, Any]:
    macs = []
    for key in ("mac-address", "mac-macAddress", "mac"):
        if props.get(key):
            macs.extend(props[key].replace("\r", "\n").split("\n"))
    quality = ""
    if props.get("local-checks-proto") or props.get("LastAuthenticatedResults") or props.get(
        "Credentialed_Scan", ""
    ).lower() in {"yes", "true", "1"}:
        quality = "credentialed"
    elif props:
        quality = "uncredentialed"
    extra = stamp_ids(
        {},
        uuid=props.get("host-uuid") or props.get("tenable-uuid") or "",
        bios_uuid=props.get("bios-uuid") or "",
        mac=macs,
        netbios=props.get("netbios-name") or "",
        fqdn=props.get("host-fqdn") or "",
        ip=props.get("host-ip") or "",
        hostname=props.get("hostname") or "",
        id_quality=quality,
    )
    return extra.get("ids") or {}


def parse_nessus(path: Path) -> list[dict[str, Any]] | None:
    """Return Nessus rows, or None when the file is not an operator export."""
    text = read_text(path)
    if is_demo_lab_stub(text):
        return None
    if not is_nessus_text(text, path.name):
        return None
    return iter_nessus_items(text)
