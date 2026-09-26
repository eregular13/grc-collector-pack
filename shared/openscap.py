"""Parse OpenSCAP XCCDF results / ARF. Fail/error only. Not CIS-CAT.

Keep rule id, severity, title, and SCAP Security Guide references.
pass / notapplicable / notselected stay silent.
"""

from __future__ import annotations

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


def is_openscap(payload: Any = None, *, name: str = "", text: str = "") -> bool:
    """True for OpenSCAP / SSG XCCDF or ARF. Never claims CIS-CAT JSON."""
    n = (name or "").lower()
    raw = text or ""
    low = raw.lower()
    if any(tok in n for tok in _CIS_BRAND) and not any(tok in n for tok in _OSCAP_NAME):
        return False
    if any(tok in n for tok in _OSCAP_NAME):
        return True
    if raw.lstrip().startswith("<") and any(tok in low for tok in _OSCAP_MARKERS):
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
    return fqdn or target or host or "openscap-host"


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


def iter_openscap_failures(text: str) -> list[dict[str, Any]]:
    """Return fail/error rule-results. pass/notapplicable/notselected invent nothing."""
    raw = text or ""
    if not raw.lstrip().startswith("<"):
        return []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []
    catalog = _rule_catalog(root)
    host = _target_host(root)
    ids = target_ids(root)
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
    return out
