"""Parse SARIF 2.1 JSON already on disk. No network. Not a scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.io_util import read_json

LEVEL_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def is_sarif(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if not isinstance(payload.get("runs"), list):
        return False
    ver = str(payload.get("version") or "")
    return ver.startswith("2.") or "$schema" in payload or bool(payload.get("runs"))


def load_sarif(path: Path) -> dict[str, Any] | None:
    try:
        payload = read_json(path)
    except Exception:
        return None
    return payload if is_sarif(payload) else None


def _score_severity(raw: str) -> str | None:
    token = str(raw or "").strip().lower()
    if not token:
        return None
    if token in LEVEL_SEV:
        return LEVEL_SEV[token]
    if token in {"critical", "high", "medium", "low", "info"}:
        return token
    try:
        score = float(token)
    except ValueError:
        return None
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _rule_index(driver: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """ruleId / ruleIndex → driver.rules[] for security-severity lookup."""
    out: dict[str, dict[str, Any]] = {}
    rules = driver.get("rules") if isinstance(driver.get("rules"), list) else []
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        out[str(idx)] = rule
        rid = str(rule.get("id") or "").strip()
        if rid:
            out[rid] = rule
    return out


def _rule_for_hit(hit: dict[str, Any], catalog: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if "ruleIndex" in hit and hit.get("ruleIndex") is not None:
        rule = catalog.get(str(hit.get("ruleIndex")))
        if isinstance(rule, dict):
            return rule
    rid = str(hit.get("ruleId") or "").strip()
    if rid:
        rule = catalog.get(rid)
        if isinstance(rule, dict):
            return rule
    return {}


def _severity(hit: dict[str, Any], rule: dict[str, Any] | None = None) -> str:
    """Prefer rule.properties.security-severity (Trivy CRITICAL) over result.level.

    Trivy maps both CRITICAL and HIGH to SARIF level=error, so falling back to
    level alone demotes critical to high.
    """
    props = hit.get("properties") if isinstance(hit.get("properties"), dict) else {}
    rule = rule if isinstance(rule, dict) else {}
    rule_props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    for raw in (
        props.get("severity"),
        props.get("security-severity"),
        rule_props.get("security-severity"),
        rule_props.get("severity"),
    ):
        mapped = _score_severity(str(raw or ""))
        if mapped:
            return mapped
    tags = rule_props.get("tags") if isinstance(rule_props.get("tags"), list) else []
    for tag in tags:
        mapped = _score_severity(str(tag or ""))
        if mapped and mapped in {"critical", "high", "medium", "low"}:
            return mapped
    level = str(hit.get("level") or "warning").lower()
    return LEVEL_SEV.get(level, "medium")


def iter_sarif_results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten runs[].results[] into rule/message/uri/severity/tool rows."""
    rows: list[dict[str, Any]] = []
    for run in payload.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run.get("tool"), dict) else {}
        tool = str(driver.get("name") or "sarif")
        catalog = _rule_index(driver if isinstance(driver, dict) else {})
        run_ids: dict[str, Any] = {}
        scan_time = ""
        props = run.get("properties") if isinstance(run.get("properties"), dict) else {}
        if props.get("imageID") or props.get("imageId") or props.get("repoDigests") or props.get("repoTags"):
            run_ids = {
                "image_id": str(props.get("imageID") or props.get("imageId") or "").strip(),
                "image_digest": props.get("repoDigests") or [],
                "image_ref": "",
            }
            tags = props.get("repoTags") if isinstance(props.get("repoTags"), list) else []
            if tags:
                run_ids["image_ref"] = str(tags[0])
        for inv in run.get("invocations") or []:
            if not isinstance(inv, dict):
                continue
            if inv.get("machine"):
                run_ids["hostname"] = str(inv.get("machine"))
            raw = inv.get("startTimeUtc") or inv.get("endTimeUtc")
            if raw:
                scan_time = str(raw)
        for hit in run.get("results") or []:
            if not isinstance(hit, dict):
                continue
            locs = hit.get("locations") or []
            uri = "target"
            if locs and isinstance(locs[0], dict):
                phys = locs[0].get("physicalLocation") or {}
                art = phys.get("artifactLocation") or {}
                uri = str(art.get("uri") or uri)
            msg = hit.get("message") if isinstance(hit.get("message"), dict) else {}
            rule = _rule_for_hit(hit, catalog)
            row = {
                "rule_id": str(hit.get("ruleId") or "sarif"),
                "message": str(msg.get("text") or hit.get("ruleId") or "SARIF finding"),
                "uri": uri,
                "severity": _severity(hit, rule),
                "tool": tool,
                "level": str(hit.get("level") or ""),
                "ids": dict(run_ids),
            }
            if scan_time:
                row["scan_time"] = scan_time
            rows.append(row)
    return rows
