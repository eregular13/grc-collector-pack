"""Parse operator-landed NessusClientData / .nessus XML. No API. No subprocess."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any  # noqa: F401 — used by _ids_from_props / iter rows

from shared.asset_ids import stamp_ids
from shared.io_util import read_text
from shared.scan_time import format_detection_date, parse_scan_datetime

# Same ^CVE-\d{4}-\d{4,7}$ semantics as shared/kev.py. Do not import kev here.
# Lookarounds: reject XCVE- prefix and do not truncate overlong IDs.
_CVE_RE = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,7}(?![0-9])", re.I)
_CVE_STRICT = re.compile(r"^CVE-\d{4}-\d{4,7}$")


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


def _keep_item(item: ET.Element, sev: str) -> bool:
    """Keep every non-info ReportItem. POA&M gating is include_poam, not the parser."""
    del item
    return sev in {"low", "medium", "high", "critical"}


def _add_cves(blob: str, found: list[str], seen: set[str]) -> None:
    for match in _CVE_RE.findall(blob or ""):
        token = match.strip().upper()
        if not _CVE_STRICT.fullmatch(token):
            continue
        if token not in seen:
            seen.add(token)
            found.append(token)


def _cves_from_item(item: ET.Element) -> list[str]:
    """CVE IDs from <cve> children only (spec §7.1). No attributes, no *-cve tags."""
    found: list[str] = []
    seen: set[str] = set()
    for child in list(item):
        if _tag(child).lower() == "cve":
            _add_cves(child.text or "", found, seen)
    return found


def _cwes_from_item(item: ET.Element) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for child in list(item):
        if _tag(child).lower() != "cwe":
            continue
        token = (child.text or "").strip()
        if token and token not in seen:
            seen.add(token)
            found.append(token)
    return found


def _host_scan_time(host_el: ET.Element) -> str:
    """HOST_START, else HOST_END, from ReportHost HostProperties tags."""
    start = ""
    end = ""
    for child in list(host_el):
        if _tag(child) != "HostProperties":
            continue
        for tag_el in list(child):
            if _tag(tag_el) != "tag":
                continue
            name = str(tag_el.attrib.get("name") or "")
            val = (tag_el.text or "").strip()
            if not val:
                continue
            if name in {"HOST_START", "host_start"}:
                start = val
            elif name in {"HOST_END", "host_end"}:
                end = val
    raw = start or end
    if not raw:
        return ""
    parsed = parse_scan_datetime(raw)
    if not parsed:
        return raw
    return parsed[0].isoformat()


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
        scan_time = _host_scan_time(host_el)
        for item in list(host_el):
            if _tag(item) != "ReportItem":
                continue
            sev = _risk_severity(item)
            if not _keep_item(item, sev):
                continue
            title = str(item.attrib.get("pluginName") or item.attrib.get("pluginID") or "Nessus finding")
            plugin = str(item.attrib.get("pluginID") or "")
            port = str(item.attrib.get("port") or "")
            proto = str(item.attrib.get("protocol") or "").strip()
            svc = str(item.attrib.get("svc_name") or "")
            family = str(item.attrib.get("pluginFamily") or "")
            desc = title
            cves = _cves_from_item(item)
            cwes = _cwes_from_item(item)
            for child in list(item):
                tag = _tag(child)
                if tag == "description" and (child.text or "").strip():
                    desc = (child.text or "").strip()
            row: dict[str, Any] = {
                "host": host,
                "name": title,
                "description": desc,
                "severity": sev,
                "port": port,
                "protocol": proto,
                "service": svc,
                "plugin_id": plugin,
                "plugin_family": family,
                "ids": ids,
                "cves": cves,
                "cwes": cwes,
                "host_start": props.get("HOST_START") or "",
                "id_quality": ids.get("id_quality") or "",
            }
            if scan_time:
                row["scan_time"] = scan_time
            rows.append(row)
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


def nessus_detection_date(row: dict[str, Any]) -> str:
    """YYYY-MM-DD from HOST_START/HOST_END, else not recorded."""
    return format_detection_date(row.get("scan_time"))
