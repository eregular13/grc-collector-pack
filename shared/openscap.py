"""Parse OpenSCAP XCCDF results / ARF. Fail/error only. Not CIS-CAT.

Keep rule id, severity, title, and SCAP Security Guide references.
pass / notapplicable / notselected stay silent.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from shared.hardening_map import extra_control_fields, oscap_control, oscap_short_id

_OSCAP_NAME = (
    "openscap",
    "oscap",
    "ssg-",
    "xccdf-results",
    "arf-results",
    "scap-results",
)
_OSCAP_MARKERS = (
    "ssgproject",
    "open-scap",
    "openscap",
    "scap-security-guide",
    "org.ssgproject",
    "anssi",
    "disa-stig",
    "xccdf_org.ssgproject",
)
_CIS_BRAND = ("cis-cat", "ciscat", "cisecurity", "cis benchmark", "cis ubuntu")
_FAIL = frozenset({"fail", "failed", "error"})
_SILENT = frozenset(
    {"pass", "passed", "notapplicable", "notselected", "notchecked", "informational"}
)


_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_OVAL_VULN_CLASSES = frozenset({"vulnerability", "patch"})


def is_openscap(payload: Any = None, *, name: str = "", text: str = "") -> bool:
    """True for OpenSCAP / SSG XCCDF or ARF. Never claims CIS-CAT JSON."""
    n = (name or "").lower()
    raw = (text or "").lstrip("\ufeff")  # UTF-8 BOM decoded as U+FEFF is not whitespace
    low = raw.lower()
    if any(tok in n for tok in _CIS_BRAND) and not any(tok in n for tok in _OSCAP_NAME):
        return False
    if any(tok in n for tok in _OSCAP_NAME):
        return True
    if raw.lstrip().startswith("<") and any(tok in low for tok in _OSCAP_MARKERS):
        return True
    if raw.lstrip().startswith("<") and "<oval_results" in low[:4096]:
        return True
    if isinstance(payload, dict):
        blob = " ".join(str(payload.get(k) or "") for k in ("benchmark", "Benchmark", "id", "href"))
        if any(tok in blob.lower() for tok in _OSCAP_MARKERS):
            return True
    return False


def _local(tag: str) -> str:
    return tag.split("}")[-1].lower().replace("_", "-")


def _text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return (el.text or "").strip()


def _rule_catalog(root: ET.Element) -> dict[str, dict[str, Any]]:
    """idref → title / severity / SSG references from Benchmark Rule elements."""
    catalog: dict[str, dict[str, Any]] = {}
    for el in root.iter():
        if _local(el.tag) != "rule":
            continue
        rid = str(el.attrib.get("id") or "").strip()
        if not rid:
            continue
        title = ""
        refs: list[str] = []
        for child in list(el):
            loc = _local(child.tag)
            if loc == "title" and not title:
                title = _text(child)
            elif loc in {"ident", "reference"}:
                href = (child.attrib.get("href") or child.attrib.get("system") or "").strip()
                body = _text(child)
                if href and body:
                    refs.append(f"{href} {body}".strip())
                elif body:
                    refs.append(body)
                elif href:
                    refs.append(href)
        catalog[rid] = {
            "title": title,
            "severity": str(el.attrib.get("severity") or "").strip().lower(),
            "references": refs,
        }
    return catalog


def _iter_rule_results(root: ET.Element) -> list[ET.Element]:
    out: list[ET.Element] = []
    for el in root.iter():
        if _local(el.tag) in {"rule-result", "ruleresult"}:
            out.append(el)
    return out


def _result_value(el: ET.Element) -> str:
    for child in list(el):
        if _local(child.tag) == "result":
            return _text(child).lower().replace(" ", "")
    return str(el.attrib.get("result") or "").lower().replace(" ", "")


def _target_host(root: ET.Element) -> str:
    fqdn = ""
    host = ""
    target = ""
    oval_host = ""
    for el in root.iter():
        loc = _local(el.tag)
        val = (_text(el) or el.attrib.get("name") or "").strip()
        if not val:
            continue
        if loc == "fqdn":
            fqdn = fqdn or val
        elif loc == "target":
            target = target or val
        elif loc == "hostname":
            host = host or val
        elif loc == "primary-host-name":  # OVAL results system_info
            oval_host = oval_host or val
    return fqdn or target or host or oval_host or "openscap-host"


def target_ids(root: ET.Element) -> dict[str, Any]:
    """Collect ARF ai:fqdn / connections for extra.ids."""
    ids: dict[str, Any] = {"fqdn": "", "hostname": "", "ip": [], "mac": []}
    for el in root.iter():
        loc = _local(el.tag)
        val = (_text(el) or el.attrib.get("name") or "").strip()
        if loc == "fqdn" and val and not ids["fqdn"]:
            ids["fqdn"] = val
        elif loc == "hostname" and val and not ids["hostname"]:
            ids["hostname"] = val
        elif loc in {"ip-v4", "ip-v6", "ip-address"} and val:
            ids["ip"].append(val)
        elif loc == "mac-address" and val:
            ids["mac"].append(val)
        elif loc == "fact" and "mac" in str(el.attrib.get("name") or "").lower() and val:
            ids["mac"].append(val)
    return ids


def _result_refs(el: ET.Element) -> list[str]:
    refs: list[str] = []
    for child in list(el):
        loc = _local(child.tag)
        if loc in {"ident", "reference"}:
            href = (child.attrib.get("href") or child.attrib.get("system") or "").strip()
            body = _text(child)
            if href and body:
                refs.append(f"{href} {body}".strip())
            elif body:
                refs.append(body)
            elif href:
                refs.append(href)
    return refs


def _report_scan_time(root: ET.Element) -> str:
    """XCCDF TestResult start-time, else end-time. Real oscap attribute names."""
    for el in root.iter():
        if _local(el.tag) != "testresult":
            continue
        raw = (
            str(el.attrib.get("start-time") or el.attrib.get("start_time") or "").strip()
            or str(el.attrib.get("end-time") or el.attrib.get("end_time") or "").strip()
        )
        if raw:
            return raw
    return ""


def _ident_cves(el: ET.Element) -> list[str]:
    """CVE ids from direct <ident> children (structured; never URLs/prose)."""
    out: list[str] = []
    for child in list(el):
        if _local(child.tag) != "ident":
            continue
        val = _text(child).upper()
        if _CVE_ID.match(val) and val not in out:
            out.append(val)
    return out


def _check_refs(el: ET.Element) -> list[str]:
    """OVAL definition ids a rule-result's <check> points at."""
    out: list[str] = []
    for child in el.iter():
        if _local(child.tag) == "check-content-ref":
            name = str(child.attrib.get("name") or "").strip()
            if name:
                out.append(name)
    return out


def oval_definitions(root: ET.Element) -> dict[str, dict[str, Any]]:
    """OVAL definition id -> class/title/severity/CVE refs (reference source=CVE)."""
    defs: dict[str, dict[str, Any]] = {}
    for el in root.iter():
        if _local(el.tag) != "definition" or not el.attrib.get("class"):
            continue
        did = str(el.attrib.get("id") or "").strip()
        if not did:
            continue
        title, sev, cves = "", "", []
        for child in el.iter():
            loc = _local(child.tag)
            if loc == "title" and not title:
                title = _text(child)
            elif loc == "severity" and not sev:
                sev = _text(child).lower()
            elif loc == "reference" and str(child.attrib.get("source") or "").strip().upper() == "CVE":
                cid = str(child.attrib.get("ref_id") or "").strip().upper()
                if _CVE_ID.match(cid) and cid not in cves:
                    cves.append(cid)
            elif loc == "cve":  # Red Hat advisory <cve>CVE-…</cve>
                cid = _text(child).upper()
                if _CVE_ID.match(cid) and cid not in cves:
                    cves.append(cid)
        defs[did] = {
            "class": str(el.attrib.get("class") or "").strip().lower(),
            "title": title,
            "severity": sev,
            "cves": cves,
        }
    return defs


def oval_true_definitions(root: ET.Element) -> list[str]:
    """Definition ids that an OVAL results <system> evaluated result="true"."""
    out: list[str] = []
    for el in root.iter():
        if _local(el.tag) != "definition" or el.attrib.get("class"):
            continue
        did = str(el.attrib.get("definition_id") or "").strip()
        if did and str(el.attrib.get("result") or "").strip().lower() == "true" and did not in out:
            out.append(did)
    return out


_OVAL_SEV = {"critical": "critical", "important": "high", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


def openscap_cve_findings(root: ET.Element) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    """(rule idref -> CVEs, standalone OVAL vulnerability rows).

    A failing rule-result carries the CVEs of its own <ident>s, of its Benchmark
    Rule <ident>s and of every OVAL definition its <check> references. An OVAL
    vulnerability/patch definition evaluated true that no rule-result
    references (``oscap oval eval --results`` or ARF) becomes its own row.
    """
    defs = oval_definitions(root)
    catalog_cves: dict[str, list[str]] = {}
    for el in root.iter():
        if _local(el.tag) == "rule" and el.attrib.get("id"):
            catalog_cves[str(el.attrib["id"]).strip()] = _ident_cves(el)
    by_rule: dict[str, list[str]] = {}
    referenced: set[str] = set()
    for el in _iter_rule_results(root):
        rid = str(el.attrib.get("idref") or el.attrib.get("id") or "").strip()
        refs = _check_refs(el)
        referenced.update(refs)
        if _result_value(el) not in _FAIL or not rid:
            continue
        cves = list(_ident_cves(el))
        for cid in catalog_cves.get(rid, []):
            if cid not in cves:
                cves.append(cid)
        for ref in refs:
            for cid in (defs.get(ref) or {}).get("cves", []):
                if cid not in cves:
                    cves.append(cid)
        if cves:
            by_rule[rid] = by_rule.get(rid, []) + [c for c in cves if c not in by_rule.get(rid, [])]
    standalone: list[dict[str, Any]] = []
    for did in oval_true_definitions(root):
        info = defs.get(did) or {}
        if did in referenced or info.get("class") not in _OVAL_VULN_CLASSES:
            continue
        standalone.append(
            {
                "def_id": did,
                "title": str(info.get("title") or did),
                "severity": _OVAL_SEV.get(str(info.get("severity") or ""), "medium"),
                "cves": list(info.get("cves") or []),
                "class": info.get("class"),
            }
        )
    return by_rule, standalone


def iter_openscap_failures(text: str) -> list[dict[str, Any]]:
    """Return fail/error rule-results. pass/notapplicable/notselected invent nothing."""
    raw = (text or "").lstrip("\ufeff")  # tolerate UTF-8 BOM before '<'
    if not raw.lstrip().startswith("<"):
        return []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        # Malformed OpenSCAP XML is a per-file parse error, not 0 rows.
        raise ValueError(f"OpenSCAP XML parse error: {exc}") from exc
    catalog = _rule_catalog(root)
    host = _target_host(root)
    ids = target_ids(root)
    scan_time = _report_scan_time(root)
    rule_cves, oval_rows = openscap_cve_findings(root)
    out: list[dict[str, Any]] = []
    for el in _iter_rule_results(root):
        result = _result_value(el)
        if result in _SILENT:
            continue
        if result not in _FAIL:
            continue
        rid = str(el.attrib.get("idref") or el.attrib.get("id") or "").strip()
        if not rid:
            continue
        info = catalog.get(rid) or {}
        title = (
            str(el.attrib.get("title") or "").strip()
            or str(info.get("title") or "").strip()
            or oscap_short_id(rid)
        )
        severity = (
            str(el.attrib.get("severity") or "").strip().lower()
            or str(info.get("severity") or "").strip().lower()
            or "medium"
        )
        refs = list(info.get("references") or [])
        refs.extend(_result_refs(el))
        # de-dupe refs, keep order
        seen: set[str] = set()
        clean_refs: list[str] = []
        for ref in refs:
            if ref and ref not in seen:
                seen.add(ref)
                clean_refs.append(ref)
        control = oscap_control(rid, title)
        extra = extra_control_fields(control)
        extra.update(
            {
                "rule_id": rid,
                "id": rid,
                "check_id": oscap_short_id(rid),
                "result": result,
                "ssg_references": clean_refs,
                "tool": "openscap",
            }
        )
        if scan_time:
            extra["scan_time"] = scan_time
        if rule_cves.get(rid):
            extra["cves"] = list(rule_cves[rid])
            extra["cve"] = " ".join(rule_cves[rid])
        out.append(
            {
                "id": rid,
                "short_id": oscap_short_id(rid),
                "title": title,
                "host": host,
                "result": result,
                "severity": severity if severity in {"low", "medium", "high", "critical"} else "medium",
                "references": clean_refs,
                "control_key": control,
                "extra": extra,
                "ids": ids,
            }
        )
    for row in oval_rows:
        did = row["def_id"]
        extra = {
            "rule_id": did,
            "id": did,
            "check_id": did,
            "result": "true",
            "ssg_references": [],
            "tool": "openscap",
            "oval_class": row["class"],
            "cves": row["cves"],
            "cve": " ".join(row["cves"]),
        }
        if scan_time:
            extra["scan_time"] = scan_time
        out.append(
            {
                "id": did,
                "short_id": did,
                "title": row["title"],
                "host": host,
                "result": "true",
                "severity": row["severity"],
                "references": [],
                "control_key": "",
                "extra": extra,
                "ids": ids,
            }
        )
    return out

def openscap_applicability(text: str) -> dict[str, Any]:
    """Explain empty fail/error sets: NOT_APPLICABLE vs all-pass vs empty.

    OpenSCAP datastream/profile mismatch often yields only
    notapplicable/notselected rule-results. That is not "zero findings"
    in the sense of a clean host — surface NOT_APPLICABLE explicitly.
    """
    raw = text or ""
    if not raw.lstrip().startswith("<"):
        return {
            "status": "EMPTY",
            "message": "OpenSCAP input empty or not XML",
            "counts": {},
        }
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {
            "status": "UNPARSEABLE",
            "message": "OpenSCAP XML parse error",
            "counts": {},
        }
    counts: dict[str, int] = {}
    for el in _iter_rule_results(root):
        result = (_result_value(el) or "unknown").lower().replace("-", "")
        counts[result] = counts.get(result, 0) + 1
    fails = iter_openscap_failures(raw)
    if fails:
        return {
            "status": "OK",
            "message": f"OpenSCAP findings={len(fails)}",
            "counts": counts,
        }
    total = sum(counts.values())
    na = counts.get("notapplicable", 0)
    ns = counts.get("notselected", 0)
    npass = counts.get("pass", 0) + counts.get("passed", 0)
    if total == 0:
        return {
            "status": "NOT_APPLICABLE",
            "message": (
                "OpenSCAP NOT_APPLICABLE: no rule-results in TestResult "
                "(datastream/profile may not match host); not zero findings"
            ),
            "counts": counts,
        }
    if na + ns == total or (na > 0 and npass == 0 and counts.get("fail", 0) == 0):
        return {
            "status": "NOT_APPLICABLE",
            "message": (
                "OpenSCAP NOT_APPLICABLE: datastream/profile does not match host "
                f"(notapplicable={na}, notselected={ns}, total_rules={total}); "
                "not zero findings"
            ),
            "counts": counts,
        }
    if npass and not fails:
        return {
            "status": "OK",
            "message": f"OpenSCAP all pass (pass={npass}); no fail/error rows",
            "counts": counts,
        }
    return {
        "status": "NOT_APPLICABLE",
        "message": f"OpenSCAP NOT_APPLICABLE: no fail/error rows (counts={counts})",
        "counts": counts,
    }
