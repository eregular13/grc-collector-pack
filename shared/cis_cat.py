"""Parse CIS-CAT / XCCDF assessment exports. Failed/failing only. No CIS-CAT binary."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any


def is_cis_cat(payload: Any = None, *, name: str = "", text: str = "") -> bool:
    n = (name or "").lower()
    if "cis-cat" in n or "ciscat" in n or "xccdf" in n:
        return True
    raw = text or ""
    if raw.lstrip().startswith("<"):
        low = raw.lower()
        return "rule-result" in low or "ruleresult" in low or "cisecurity" in low
    if not isinstance(payload, dict):
        return False
    if payload.get("benchmark") or payload.get("Benchmark"):
        return True
    if payload.get("RuleResults") or payload.get("ruleResults") or payload.get("rule-results"):
        return True
    report = payload.get("Report") or payload.get("report")
    if isinstance(report, dict) and (
        report.get("RuleResults") or report.get("benchmark") or report.get("Benchmark")
    ):
        return True
    tr = payload.get("TestResult") or payload.get("testResult")
    if isinstance(tr, dict) and (tr.get("rule-result") or tr.get("rule_result") or tr.get("results")):
        return True
    return False


def _fail_status(value: Any) -> bool:
    result = str(value or "").lower().replace(" ", "")
    return result in {"fail", "failed", "error", "notpass", "notpassed"}


def _row_host(row: dict[str, Any], default: str) -> str:
    return str(
        row.get("target")
        or row.get("hostname")
        or row.get("host")
        or row.get("computer")
        or default
        or "cis-host"
    )


def _iter_json_rows(payload: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    host = str(
        payload.get("target")
        or payload.get("hostname")
        or payload.get("host")
        or payload.get("Target")
        or ""
    )
    report = payload.get("Report") or payload.get("report")
    if isinstance(report, dict):
        host = str(report.get("Target") or report.get("target") or host)
        raw = (
            report.get("RuleResults")
            or report.get("results")
            or report.get("Rules")
            or []
        )
        return host, [r for r in raw if isinstance(r, dict)]
    tr = payload.get("TestResult") or payload.get("testResult")
    if isinstance(tr, dict):
        host = str(tr.get("target") or tr.get("hostname") or host)
        raw = tr.get("rule-result") or tr.get("rule_result") or tr.get("results") or []
        if isinstance(raw, dict):
            raw = [raw]
        return host, [r for r in raw if isinstance(r, dict)]
    raw = (
        payload.get("results")
        or payload.get("RuleResults")
        or payload.get("ruleResults")
        or payload.get("rules")
        or []
    )
    if isinstance(raw, dict):
        raw = [raw]
    return host, [r for r in raw if isinstance(r, dict)]


def iter_cis_failures(payload: Any = None, *, text: str = "") -> list[dict[str, str]]:
    """Return failed CIS-CAT/XCCDF rows. Pass/empty invent nothing."""
    if text.lstrip().startswith("<"):
        return _iter_xml_failures(text)
    if not isinstance(payload, dict):
        return []
    host, rows = _iter_json_rows(payload)
    out: list[dict[str, str]] = []
    for row in rows:
        result = row.get("result") or row.get("Result") or row.get("status") or row.get("Status")
        if not _fail_status(result):
            continue
        hid = str(
            row.get("id")
            or row.get("Id")
            or row.get("RuleID")
            or row.get("rule_id")
            or row.get("idref")
            or row.get("number")
            or "cis"
        )
        title = str(
            row.get("title")
            or row.get("Title")
            or row.get("description")
            or row.get("Description")
            or row.get("name")
            or hid
        )
        out.append({"id": hid, "title": title, "host": _row_host(row, host), "result": "fail"})
    return out


def _local(tag: str) -> str:
    return tag.split("}")[-1].lower().replace("_", "-")


def _iter_xml_failures(text: str) -> list[dict[str, str]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    host = "cis-host"
    for el in root.iter():
        if _local(el.tag) in {"target", "target-facts", "hostname"}:
            val = (el.text or el.attrib.get("name") or "").strip()
            if val:
                host = val
                break
    out: list[dict[str, str]] = []
    for el in root.iter():
        if _local(el.tag) not in {"rule-result", "ruleresult"}:
            continue
        result_el = None
        for child in list(el):
            if _local(child.tag) == "result":
                result_el = child
                break
        result = (result_el.text if result_el is not None else "") or el.attrib.get("result") or ""
        if not _fail_status(result):
            continue
        hid = str(
            el.attrib.get("idref")
            or el.attrib.get("id")
            or el.findtext("id")
            or "cis"
        )
        title = str(
            el.attrib.get("title")
            or el.findtext("title")
            or el.findtext("description")
            or hid
        )
        out.append({"id": hid, "title": title, "host": host, "result": "fail"})
    return out
