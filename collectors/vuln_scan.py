from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shared.io_util import discover_input_files, emit, load_structured
from shared.schema import asset, control_extra, evidence, finding, normalize_severity

SOURCE = "vuln_scan"
PREFIX = "VULN-"


def _info(item: dict[str, Any]) -> dict[str, Any]:
    info = item.get("info") or item.get("Info") or {}
    return info if isinstance(info, dict) else {}


def _host_from_uri(uri: str) -> str:
    text = (uri or "").strip()
    if not text:
        return "unknown-host"
    if "://" not in text:
        host = text.split("/")[0].strip("[]")
        if host.count(":") == 1:
            name, port = host.rsplit(":", 1)
            if port.isdigit():
                host = name
        return host or "unknown-host"
    parsed = urlparse(text)
    if parsed.hostname:
        return parsed.hostname
    rest = text.split("://", 1)[-1]
    host = rest.split("/")[0]
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    host = host.strip("[]")
    if host.count(":") == 1:
        name, port = host.rsplit(":", 1)
        if port.isdigit():
            host = name
    return host or "unknown-host"


def _nuclei_scalar(raw: Any) -> str:
    if isinstance(raw, (list, tuple)) and raw:
        raw = raw[0]
    if raw is None:
        return ""
    return str(raw).strip()


_CVE_TOKEN = re.compile(r"(CVE-\d{4}-\d{4,})", re.I)


def _nuclei_cves(item: dict[str, Any], info: dict[str, Any]) -> list[str]:
    """CVE-IDs from Nuclei info.classification.cve-id (string or list)."""
    blobs: list[Any] = []
    cls = info.get("classification") or item.get("classification") or {}
    if isinstance(cls, dict):
        for key in ("cve-id", "cve_id", "cveId", "CVE-ID", "cve", "CVE"):
            if cls.get(key) is not None:
                blobs.append(cls.get(key))
    elif isinstance(cls, (list, str)):
        blobs.append(cls)
    for src in (info, item):
        for key in ("cve-id", "cve_id", "cveId", "CVE-ID"):
            if src.get(key) is not None:
                blobs.append(src.get(key))
    found: list[str] = []
    seen: set[str] = set()

    def _add(raw: Any) -> None:
        if isinstance(raw, (list, tuple)):
            for part in raw:
                _add(part)
            return
        text = str(raw or "").strip()
        if not text:
            return
        for match in _CVE_TOKEN.findall(text):
            up = match.upper()
            if up not in seen:
                seen.add(up)
                found.append(up)

    for blob in blobs:
        _add(blob)
    return found


def _nuclei_finding_key(template: str, cves: list[str]) -> str:
    """Prefer CVE from classification when template-id is not itself a CVE."""
    if template.upper().startswith("CVE-"):
        return template
    if cves:
        return cves[0]
    return template


def _nuclei_template_from_path(item: dict[str, Any]) -> str:
    """CVE or basename from Nuclei `template` / `template-path` / `template-url`."""
    for key in (
        "template",
        "template-path",
        "template_path",
        "templatePath",
        "template-url",
        "template_url",
        "templateURL",
    ):
        raw = _nuclei_scalar(item.get(key))
        if not raw:
            continue
        text = raw.replace("\\", "/").split("?", 1)[0].split("#", 1)[0].rstrip("/")
        match = _CVE_TOKEN.search(text)
        if match:
            return match.group(1).upper()
        base = text.rsplit("/", 1)[-1]
        if base.lower().endswith((".yaml", ".yml", ".json")):
            base = base.rsplit(".", 1)[0]
        if base and base.lower() not in {"http", "https", "cves", "templates", "nuclei-templates"}:
            return base
    return ""


def _nuclei_template_id(item: dict[str, Any]) -> str:
    """template-id, else CVE/basename from template path when template-id is empty."""
    for key in ("template-id", "template_id", "templateID", "templateId"):
        val = _nuclei_scalar(item.get(key))
        if val:
            return val
    return _nuclei_template_from_path(item)


def _nuclei_host(item: dict[str, Any]) -> str:
    """Prefer host; else ip (no host/matched-at); else matched-at URL hostname."""
    for key in (
        "host",
        "hostname",
        "ip",
        "IP",
        "ipv4",
        "ipv6",
        "ip-address",
        "matched-at",
        "matched_at",
        "url",
    ):
        text = _nuclei_scalar(item.get(key))
        if not text:
            continue
        host = _host_from_uri(text)
        host = (host or "").strip().strip("[]").rstrip(".")
        if host and host.lower() not in {"http", "https", "unknown-host"}:
            if "://" in host or "/" in host:
                continue
            return host
    return "unknown-host"


def parse_nuclei_item(item: Any) -> list:
    if not isinstance(item, dict):
        return []
    info = _info(item)
    explicit_id = any(
        _nuclei_scalar(item.get(key))
        for key in ("template-id", "template_id", "templateID", "templateId")
    )
    template = _nuclei_template_id(item)
    name = str(info.get("name") or template or "nuclei-finding")
    if not template and not name:
        return []
    host = _nuclei_host(item)
    sev = str(info.get("severity") or item.get("severity") or "medium")
    desc = str(info.get("description") or name)
    if str(desc).lower().startswith(("http://", "https://")):
        desc = name
    cves = _nuclei_cves(item, info)
    key = _nuclei_finding_key(template, cves) or name
    extra = control_extra(
        "CTL-PATCH-MGMT",
        "Vulnerability patching SLA",
        csf_function="protect",
        priority="1" if sev.lower() in {"high", "critical"} else "2",
        category="process",
    )
    extra["cve"] = cves[0] if cves else (template if template.upper().startswith("CVE-") else None)
    extra["template_id"] = template
    from_cve_id = bool(cves) and not template.upper().startswith("CVE-")
    from_path = (not explicit_id) and bool(template)
    matched = item.get("matched-at") or item.get("matched_at")
    extra["matched_at"] = _host_from_uri(str(matched)) if matched else None
    ip_only = not _nuclei_scalar(item.get("host") or item.get("hostname")) and bool(
        _nuclei_scalar(item.get("ip") or item.get("IP") or item.get("ipv4") or item.get("ipv6"))
    )
    extra["ip"] = _nuclei_scalar(item.get("ip") or item.get("IP") or item.get("ipv4") or item.get("ipv6")) or None
    labels = ["vuln", "nuclei"]
    if ip_only:
        labels.append("ip-only")
    if from_cve_id:
        labels.append("cve-id")
    if from_path:
        labels.append("template-path")
    return [
        asset(
            PREFIX,
            host,
            host,
            description=f"Vulnerability scan target {host}",
            asset_type="SP",
            source=SOURCE,
            labels=labels,
        ),
        finding(
            PREFIX,
            key,
            name,
            description=desc,
            severity=sev,
            source=SOURCE,
            related_assets=[host],
            labels=labels + ([template] if template else []),
            extra=extra,
        ),
    ]


def _is_sarif(doc: Any) -> bool:
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        return False
    schema = str(doc.get("$schema") or "").lower()
    if "sarif" in schema:
        return True
    if doc.get("version") and any(isinstance(run, dict) and "results" in run for run in doc["runs"]):
        return True
    return False


def _cvss_or_level(raw: Any) -> str:
    key = str(raw).strip().lower()
    if not key:
        return ""
    try:
        score = float(key)
    except ValueError:
        return normalize_severity(key)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _sarif_severity(result: dict[str, Any], rule: dict[str, Any]) -> str:
    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    rule_props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    default_cfg = rule.get("defaultConfiguration") if isinstance(rule.get("defaultConfiguration"), dict) else {}
    for raw in (
        props.get("issue_severity"),
        props.get("severity"),
        rule_props.get("issue_severity"),
        rule_props.get("severity"),
        rule_props.get("security-severity"),
        result.get("level"),
        default_cfg.get("level"),
    ):
        if raw is None or str(raw).strip() == "":
            continue
        mapped = _cvss_or_level(raw)
        if mapped:
            return mapped
    return "medium"


def _sarif_message(result: dict[str, Any], rule: dict[str, Any]) -> str:
    msg = result.get("message")
    if isinstance(msg, dict) and msg.get("text"):
        return str(msg["text"])
    if isinstance(msg, str) and msg.strip():
        return msg
    for key in ("fullDescription", "shortDescription", "help"):
        blob = rule.get(key)
        if isinstance(blob, dict) and blob.get("text"):
            return str(blob["text"])
        if isinstance(blob, str) and blob.strip():
            return blob
    return str(rule.get("name") or result.get("ruleId") or "nuclei-sarif")


def parse_nuclei_sarif(doc: dict[str, Any]) -> list:
    records: list = []
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver") or {})
        rules: dict[str, dict[str, Any]] = {}
        for rule in driver.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules[str(rule["id"])] = rule
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "")
            rule = rules.get(rule_id) or {}
            short = rule.get("shortDescription")
            if isinstance(short, dict):
                short_text = str(short.get("text") or "")
            else:
                short_text = str(short or "")
            name = short_text or str(rule.get("name") or rule_id or "nuclei-sarif")
            uri = ""
            for loc in result.get("locations") or []:
                if not isinstance(loc, dict):
                    continue
                art = (loc.get("physicalLocation") or {}).get("artifactLocation") or {}
                uri = str(art.get("uri") or "")
                if uri:
                    break
            props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
            host = str(props.get("host") or props.get("url") or _host_from_uri(uri) or "unknown-host")
            sev = _sarif_severity(result, rule)
            extra = control_extra(
                "CTL-PATCH-MGMT",
                "Vulnerability patching SLA",
                csf_function="protect",
                priority="1" if sev in {"high", "critical"} else "2",
                category="process",
            )
            extra["cve"] = rule_id if rule_id.upper().startswith("CVE-") else None
            extra["template_id"] = rule_id
            extra["matched_at"] = uri
            extra["format"] = "nuclei-sarif"
            records.append(
                asset(
                    PREFIX,
                    host,
                    host,
                    description=f"Vulnerability scan target {host}",
                    asset_type="SP",
                    source=SOURCE,
                    labels=["vuln", "nuclei", "sarif"],
                )
            )
            records.append(
                finding(
                    PREFIX,
                    rule_id or name,
                    name,
                    description=_sarif_message(result, rule),
                    severity=sev,
                    source=SOURCE,
                    related_assets=[host],
                    labels=["vuln", "nuclei", "sarif"] + ([rule_id] if rule_id else []),
                    extra=extra,
                )
            )
    return records


def _openvas_host(result: ET.Element) -> str:
    """Prefer <host> text; empty/whitespace falls back to ip= (or <ip> child)."""
    host_el = result.find("host")
    if host_el is None:
        for key, val in (result.attrib or {}).items():
            if str(key).lower() in {"host", "ip", "ipv4", "ipv6"}:
                text = (val or "").strip()
                if text:
                    return text
        return "unknown-host"
    text = (host_el.text or "").strip()
    if text:
        return text
    for key, val in (host_el.attrib or {}).items():
        if str(key).lower() in {"ip", "ipv4", "ipv6"}:
            ip = (val or "").strip()
            if ip:
                return ip
    for child in list(host_el):
        tag = str(child.tag or "").lower()
        if tag not in {"ip", "ipv4", "ipv6"}:
            continue
        ip = (child.text or "").strip()
        if ip:
            return ip
        for key, val in (child.attrib or {}).items():
            if str(key).lower() in {"ip", "ipv4", "ipv6", "address"}:
                ip = (val or "").strip()
                if ip:
                    return ip
    return "unknown-host"


def _openvas_severity(result: ET.Element, nvt: ET.Element | None) -> str:
    """Numeric CVSS (e.g. 9.8) maps via score bands; named threat is fallback."""
    nvt = nvt if nvt is not None else ET.Element("nvt")
    candidates: list[Any] = [
        result.findtext("severity"),
        nvt.findtext("cvss_base"),
        result.findtext("cvss_base"),
        result.findtext("cvss"),
    ]
    sevs = nvt.find("severities")
    if sevs is not None:
        candidates.append(sevs.get("score"))
        for score_el in sevs.findall(".//score"):
            candidates.append(score_el.text)
    candidates.append(result.findtext("threat"))
    numeric: list[str] = []
    named: list[str] = []
    for raw in candidates:
        if raw is None or str(raw).strip() == "":
            continue
        text = str(raw).strip()
        try:
            float(text)
        except ValueError:
            named.append(text)
        else:
            numeric.append(text)
    for raw in numeric + named:
        mapped = _cvss_or_level(raw)
        if mapped:
            return mapped
    return "medium"


_OPENVAS_CVE_JUNK = frozenset({"", "nocve", "none", "n/a", "na", "null", "-", "unknown", "not applicable"})


def _openvas_cve(nvt: ET.Element | None) -> str:
    """First real CVE-*; skip NOCVE/empty <cve> text and use refs / <cves> children."""
    if nvt is None:
        return ""
    blobs: list[str] = []
    for tag in ("cve", "CVE"):
        text = (nvt.findtext(tag) or "").strip()
        if text:
            blobs.append(text)
    for child in nvt.findall(".//cve"):
        text = (child.text or "").strip()
        if text:
            blobs.append(text)
    for ref in nvt.findall(".//ref"):
        rtype = (ref.get("type") or ref.get("Type") or "").lower()
        rid = (ref.get("id") or ref.get("ID") or ref.text or "").strip()
        if rtype in {"cve", "cve-id", "cveid"} and rid:
            blobs.append(rid)
        elif _CVE_TOKEN.search(rid):
            blobs.append(rid)
    seen: set[str] = set()
    found: list[str] = []
    for blob in blobs:
        for part in re.split(r"[,;\s]+", blob):
            part = part.strip().strip("[]\"'")
            if not part or part.lower() in _OPENVAS_CVE_JUNK:
                continue
            match = _CVE_TOKEN.search(part)
            if not match:
                continue
            up = match.group(1).upper()
            if up not in seen:
                seen.add(up)
                found.append(up)
    return found[0] if found else ""


def parse_openvas_xml(path: Path) -> list:
    records: list = []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return records
    for result in tree.getroot().iter("result"):
        host = _openvas_host(result)
        nvt = result.find("nvt")
        name = "openvas-result"
        cve = ""
        if nvt is not None:
            name = (nvt.findtext("name") or nvt.get("oid") or name).strip()
            cve = _openvas_cve(nvt)
        sev = _openvas_severity(result, nvt)
        desc = (result.findtext("description") or name).strip()
        extra = control_extra(
            "CTL-PATCH-MGMT",
            "Vulnerability patching SLA",
            csf_function="protect",
            priority="1" if sev in {"high", "critical"} else "2",
            category="process",
        )
        extra["cve"] = cve or None
        extra["cvss"] = (result.findtext("severity") or (nvt.findtext("cvss_base") if nvt is not None else "") or "").strip() or None
        key = cve or name
        records.append(
            asset(
                PREFIX,
                host,
                host,
                description=f"OpenVAS/Greenbone target {host}",
                asset_type="SP",
                source=SOURCE,
                labels=["vuln", "openvas"],
            )
        )
        records.append(
            finding(
                PREFIX,
                key,
                name if not cve else f"{cve} {name}",
                description=desc,
                severity=sev,
                source=SOURCE,
                related_assets=[host],
                labels=["vuln", "openvas"] + ([cve] if cve else []),
                extra=extra,
            )
        )
    return records


def _xml_local(tag: Any) -> str:
    return str(tag or "").split("}")[-1]


def _looks_like_nessus(path: Path, text: str) -> bool:
    """Tenable Nessus .nessus / NessusClientData_v2 ReportHost XML."""
    if path.suffix.lower() == ".nessus":
        return True
    if "NessusClientData" in text:
        return True
    return "<ReportHost" in text and "<ReportItem" in text


_NESSUS_PLUGIN_SEV = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}
_NESSUS_CVE_JUNK = _OPENVAS_CVE_JUNK


def _nessus_host(report_host: ET.Element) -> str:
    """Prefer host-fqdn; empty/whitespace falls back to ReportHost name, then host-ip."""
    tags: dict[str, str] = {}
    for child in list(report_host):
        if _xml_local(child.tag) != "HostProperties":
            continue
        for tag in list(child):
            if _xml_local(tag.tag) != "tag":
                continue
            name = (tag.get("name") or tag.get("Name") or "").strip().lower()
            val = (tag.text or "").strip()
            if name and val:
                tags[name] = val
    for key in ("host-fqdn", "host_fqdn", "hostname", "netbios-name", "netbios_name"):
        if tags.get(key):
            return tags[key]
    name = (report_host.get("name") or report_host.get("Name") or "").strip()
    if name:
        return name
    for key in ("host-ip", "host_ip", "host-ipv4", "host-ipv6", "local-ip"):
        if tags.get(key):
            return tags[key]
    return "unknown-host"


def _nessus_cve(item: ET.Element) -> str:
    """First real CVE-* from <cve>, see_also, or xref; skip NOCVE/empty."""
    blobs: list[str] = []
    for child in item.iter():
        local = _xml_local(child.tag).lower()
        if local in {"cve", "cve-id", "cveid"}:
            text = (child.text or "").strip()
            if text:
                blobs.append(text)
            cid = (child.get("id") or child.get("ID") or "").strip()
            if cid:
                blobs.append(cid)
        elif local in {"see_also", "see-also", "xref"}:
            text = (child.text or "").strip()
            if text:
                blobs.append(text)
    seen: set[str] = set()
    found: list[str] = []
    for blob in blobs:
        for part in re.split(r"[,;\s]+", blob):
            part = part.strip().strip("[]\"'")
            if not part or part.lower() in _NESSUS_CVE_JUNK:
                continue
            match = _CVE_TOKEN.search(part)
            if not match:
                continue
            up = match.group(1).upper()
            if up not in seen:
                seen.add(up)
                found.append(up)
    return found[0] if found else ""


def _nessus_severity(item: ET.Element) -> str:
    """CVSS3/CVSS numeric first; risk_factor named; plugin severity attr is 0–4 not CVSS."""
    for tag in (
        "cvss3_base_score",
        "cvss3_temporal_score",
        "cvssv3",
        "cvss3",
        "cvss_base_score",
        "cvssv2",
        "cvss",
    ):
        text = (item.findtext(tag) or "").strip()
        if not text:
            continue
        try:
            float(text)
        except ValueError:
            continue
        mapped = _cvss_or_level(text)
        if mapped:
            return mapped
    rf = (item.findtext("risk_factor") or item.findtext("RiskFactor") or "").strip()
    if rf:
        mapped = _cvss_or_level(rf)
        if mapped:
            return mapped
    attr = (item.get("severity") or item.get("Severity") or "").strip()
    if attr in _NESSUS_PLUGIN_SEV:
        return _NESSUS_PLUGIN_SEV[attr]
    if attr:
        return _cvss_or_level(attr)
    named = (item.findtext("severity") or "").strip()
    if named:
        return _cvss_or_level(named)
    return "medium"


def _nessus_skip(item: ET.Element, sev: str) -> bool:
    """Drop info plugins (severity 0 / risk_factor None) so they never become findings."""
    if sev in {"info", "none"}:
        return True
    attr = (item.get("severity") or item.get("Severity") or "").strip()
    if attr == "0":
        return True
    rf = (item.findtext("risk_factor") or item.findtext("RiskFactor") or "").strip().lower()
    if rf in {"none", "info", "informational", "information"}:
        return True
    return False


def parse_nessus_xml(path: Path) -> list:
    records: list = []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return records
    for host_el in tree.getroot().iter():
        if _xml_local(host_el.tag) != "ReportHost":
            continue
        host = _nessus_host(host_el)
        host_emitted = False
        for item in list(host_el):
            if _xml_local(item.tag) != "ReportItem":
                continue
            sev = _nessus_severity(item)
            if _nessus_skip(item, sev):
                continue
            plugin = (
                item.get("pluginID")
                or item.get("pluginId")
                or item.get("plugin_id")
                or ""
            ).strip()
            name = (
                item.get("pluginName")
                or item.get("plugin_name")
                or item.findtext("plugin_name")
                or plugin
                or "nessus-result"
            ).strip()
            cve = _nessus_cve(item)
            desc = (item.findtext("description") or item.findtext("synopsis") or name).strip()
            extra = control_extra(
                "CTL-PATCH-MGMT",
                "Vulnerability patching SLA",
                csf_function="protect",
                priority="1" if sev in {"high", "critical"} else "2",
                category="process",
            )
            extra["cve"] = cve or None
            extra["plugin_id"] = plugin or None
            extra["port"] = (item.get("port") or "").strip() or None
            extra["format"] = "nessus"
            extra["cvss"] = (
                (item.findtext("cvss3_base_score") or item.findtext("cvss_base_score") or "").strip()
                or None
            )
            key = cve or plugin or name
            if not host_emitted:
                records.append(
                    asset(
                        PREFIX,
                        host,
                        host,
                        description=f"Nessus target {host}",
                        asset_type="SP",
                        source=SOURCE,
                        labels=["vuln", "nessus"],
                    )
                )
                host_emitted = True
            records.append(
                finding(
                    PREFIX,
                    key,
                    name if not cve else f"{cve} {name}",
                    description=desc,
                    severity=sev,
                    source=SOURCE,
                    related_assets=[host],
                    labels=["vuln", "nessus"] + ([cve] if cve else []),
                    extra=extra,
                )
            )
    return records


def parse_files(files: list[Path]) -> list:
    records: list = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "<nmaprun" in text:
            continue
        if _looks_like_nessus(path, text):
            records.extend(parse_nessus_xml(path))
            continue
        if path.suffix.lower() == ".xml" or "<result" in text:
            ov = parse_openvas_xml(path)
            if ov:
                records.extend(ov)
                continue
        for item in load_structured(path):
            if _is_sarif(item):
                records.extend(parse_nuclei_sarif(item))
            else:
                records.extend(parse_nuclei_item(item))
    return records


def main() -> None:
    files = discover_input_files("vuln")
    records = parse_files(files)
    records.append(
        evidence(
            PREFIX,
            "NUCLEI",
            "Nuclei/OpenVAS/Nessus demo parse",
            description="Parsed Nuclei JSONL (empty template-id uses template/template-path CVE basename) and SARIF, OpenVAS XML, and Nessus .nessus ReportItem. Blank lines and truncated objects were skipped. No live scan.",
            source=SOURCE,
        )
    )
    emit("vuln", records, files)


if __name__ == "__main__":
    main()
