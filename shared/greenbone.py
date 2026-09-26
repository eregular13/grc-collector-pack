"""Parse Greenbone / OpenVAS GMP report XML and CSV. No scanner spawn."""

from __future__ import annotations

import csv
import xml.etree.ElementTree as ET
from io import StringIO
from pathlib import Path
from typing import Any, Iterator

from shared.io_util import read_text

_THREAT_SEV = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "log": "info",
    "debug": "info",
    "false positive": "info",
    "alarm": "high",
}


def _local(tag: str) -> str:
    return (tag or "").split("}")[-1].lower()


def _child(el: ET.Element, name: str) -> ET.Element | None:
    want = name.lower()
    for child in list(el):
        if _local(child.tag) == want:
            return child
    return None


def _child_text(el: ET.Element, name: str) -> str:
    hit = _child(el, name)
    if hit is None:
        return ""
    return (hit.text or "").strip()


def cvss_band(raw: Any) -> str:
    try:
        score = float(str(raw).strip())
    except (TypeError, ValueError):
        return ""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _severity(threat: str, cvss: str) -> str:
    band = cvss_band(cvss)
    if band:
        return band
    return _THREAT_SEV.get(str(threat or "").strip().lower(), "medium")


def is_greenbone_xml(text: str, name: str = "") -> bool:
    if not text or not text.strip():
        return False
    low = text[:12000].lower()
    if "nessusclientdata" in low or "<reporthost" in low:
        return False
    if "<niktoscan" in low or "<scandetails" in low:
        return False
    if "greenbone" in name.lower() or "openvas" in name.lower() or "gmp" in name.lower():
        return "<result" in low and "<nvt" in low
    return ("<nvt" in low and "<result" in low) and (
        "gmp" in low or "openvas" in low or "greenbone" in low or 'oid="1.3.6.1.4.1.25623' in low
    )


def is_greenbone_csv(text: str, name: str = "") -> bool:
    head = (text or "").lstrip("\ufeff").splitlines()[:1]
    if not head:
        return False
    header = head[0].lower()
    if "nvt oid" in header or "nvt name" in header:
        return True
    if ("ip" in header and "cvss" in header and "severity" in header) and (
        "openvas" in name.lower() or "greenbone" in name.lower()
    ):
        return True
    return False


def _cves_from_nvt(nvt: ET.Element) -> str:
    refs = _child(nvt, "refs") or _child(nvt, "references")
    if refs is None:
        return ""
    found: list[str] = []
    for ref in list(refs):
        if _local(ref.tag) != "ref":
            continue
        rtype = (ref.attrib.get("type") or "").lower()
        rid = ref.attrib.get("id") or (ref.text or "").strip()
        if rtype == "cve" and rid:
            found.append(rid)
    return found[0] if found else ""


def iter_greenbone_xml(text: str) -> Iterator[dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return
    for el in root.iter():
        if _local(el.tag) != "result":
            continue
        nvt = _child(el, "nvt")
        if nvt is None:
            continue
        host_el = _child(el, "host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        if host_el is not None and not host:
            host = _child_text(host_el, "ip") or _child_text(host_el, "hostname")
        port = _child_text(el, "port")
        name = _child_text(el, "name") or _child_text(nvt, "name") or "openvas"
        oid = nvt.attrib.get("oid") or _child_text(nvt, "oid") or name
        threat = _child_text(el, "threat") or _child_text(el, "original_threat")
        cvss = _child_text(el, "severity") or _child_text(nvt, "cvss_base")
        desc = _child_text(el, "description") or name
        yield {
            "host": host or "unknown",
            "port": port,
            "name": name,
            "oid": oid,
            "severity": _severity(threat, cvss),
            "threat": threat,
            "cvss": cvss,
            "cve": _cves_from_nvt(nvt),
            "description": desc,
        }


def iter_greenbone_csv(text: str) -> Iterator[dict[str, Any]]:
    raw = text.lstrip("\ufeff")
    reader = csv.DictReader(StringIO(raw))
    for row in reader:
        if not row:
            continue
        lower = {str(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        host = lower.get("ip") or lower.get("hostname") or lower.get("host") or "unknown"
        if not host:
            continue
        name = lower.get("nvt name") or lower.get("name") or "openvas"
        oid = lower.get("nvt oid") or lower.get("oid") or name
        cves = (lower.get("cves") or "").split(",")
        cve = next((c.strip() for c in cves if c.strip().upper().startswith("CVE")), "")
        yield {
            "host": host,
            "port": lower.get("port") or "",
            "name": name,
            "oid": oid,
            "severity": _severity(lower.get("severity") or "", lower.get("cvss") or ""),
            "threat": lower.get("severity") or "",
            "cvss": lower.get("cvss") or "",
            "cve": cve,
            "description": lower.get("summary") or lower.get("specific result") or name,
        }


def parse_greenbone(path: Path) -> list[dict[str, Any]] | None:
    """Return Greenbone/OpenVAS rows, or None when the file is another format."""
    text = read_text(path)
    name = path.name
    suffix = path.suffix.lower()
    if suffix == ".csv" or ("," in text[:200] and is_greenbone_csv(text, name)):
        if is_greenbone_csv(text, name):
            return list(iter_greenbone_csv(text))
        return None
    if suffix in {".xml", ".omp"} or text.lstrip().startswith("<"):
        if is_greenbone_xml(text, name):
            return list(iter_greenbone_xml(text))
        return None
    return None
