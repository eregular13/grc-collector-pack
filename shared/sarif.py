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


def _severity(hit: dict[str, Any]) -> str:
    props = hit.get("properties") if isinstance(hit.get("properties"), dict) else {}
    raw = str(props.get("severity") or props.get("security-severity") or "").lower()
    if raw in LEVEL_SEV:
        return LEVEL_SEV[raw]
    if raw in {"critical", "high", "medium", "low", "info"}:
        return raw
    try:
        score = float(raw)
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"
    except ValueError:
        pass
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
            rows.append(
                {
                    "rule_id": str(hit.get("ruleId") or "sarif"),
                    "message": str(msg.get("text") or hit.get("ruleId") or "SARIF finding"),
                    "uri": uri,
                    "severity": _severity(hit),
                    "tool": tool,
                    "level": str(hit.get("level") or ""),
                }
            )
    return rows
