"""Parse operator-landed NessusClientData / .nessus XML. No API. No subprocess."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from shared.io_util import read_text
from shared.scan_time import format_detection_date, parse_scan_datetime


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
            svc = str(item.attrib.get("svc_name") or "")
            proto = str(item.attrib.get("protocol") or "").strip()
            desc = title
            cves: list[str] = []
            for child in list(item):
                tag = _tag(child)
                if tag == "description" and (child.text or "").strip():
                    desc = (child.text or "").strip()
                elif tag == "cve":
                    raw = (child.text or "").strip()
                    if raw and raw not in cves:
                        cves.append(raw)
            row: dict[str, Any] = {
                "host": host,
                "name": title,
                "description": desc,
                "severity": sev,
                "port": port,
                "service": svc,
                "protocol": proto,
                "plugin_id": plugin,
                "cves": cves,
            }
            if scan_time:
                row["scan_time"] = scan_time
            rows.append(row)
    return rows


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
