"""Origin Eval / CISO JSON handoff. File-drop only. No HTTP. No RiskReady wrap."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared.io_util import read_jsonl, write_json

MAX_FINDINGS = 5
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _sev_rank(value: Any) -> int:
    return _SEV_RANK.get(str(value or "").strip().lower(), 0)


def _canonical(out: Path) -> list[dict[str, Any]]:
    folder = out / "canonical"
    records: list[dict[str, Any]] = []
    if not folder.is_dir():
        return records
    for path in sorted(folder.glob("*.jsonl")):
        for row in read_jsonl(path):
            if isinstance(row, dict):
                records.append(row)
    return records


def _finding_row(rec: dict[str, Any]) -> dict[str, Any]:
    return {
        "ref_id": rec.get("ref_id"),
        "name": rec.get("name"),
        "description": rec.get("description"),
        "severity": rec.get("severity"),
        "assets": list(rec.get("assets") or []),
        "source": rec.get("source"),
        "category": rec.get("category"),
    }


def _asset_row(rec: dict[str, Any]) -> dict[str, Any]:
    return {
        "ref_id": rec.get("ref_id"),
        "name": rec.get("name"),
        "description": rec.get("description"),
        "source": rec.get("source"),
    }


def select_max_findings(records: list[dict[str, Any]], limit: int = MAX_FINDINGS) -> list[dict[str, Any]]:
    findings = [r for r in records if r.get("kind") == "finding"]
    findings.sort(key=lambda r: (-_sev_rank(r.get("severity")), str(r.get("name") or "")))
    return [_finding_row(r) for r in findings[: max(0, int(limit))]]


def related_assets(records: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = {str(n).strip().lower() for row in findings for n in (row.get("assets") or []) if str(n).strip()}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rec in records:
        if rec.get("kind") != "asset":
            continue
        name = str(rec.get("name") or "").strip().lower()
        if not name or name in seen:
            continue
        if names and name not in names:
            continue
        seen.add(name)
        out.append(_asset_row(rec))
    return out


def build_eval_handoff(
    out: Path,
    *,
    sample: bool,
    client_keep: bool,
    sources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    records = _canonical(out)
    findings = select_max_findings(records)
    assets = related_assets(records, findings)
    ciso = out / "ciso-assistant"
    poam = out / "poam" / "poam.csv"
    ciso_files = sorted(p.name for p in ciso.glob("*.csv")) if ciso.is_dir() else []
    label = (
        "SAMPLE — redacted KEEP-chain fixtures. Not a client KEEP drop."
        if sample or not client_keep
        else "Client KEEP file-drop. Human reviews before Eval import."
    )
    return {
        "product": "grc-collector-pack",
        "consumer": "origin-eval",
        "posted": False,
        "http": False,
        "wrap": "review-only",
        "demo": bool(sample or not client_keep),
        "sample": bool(sample or not client_keep),
        "client_keep": bool(client_keep) and not sample,
        "label": label,
        "max_findings": MAX_FINDINGS,
        "findings": findings,
        "assets": assets,
        "counts": {
            "findings_selected": len(findings),
            "assets_selected": len(assets),
            "canonical": len(records),
        },
        "ciso": {
            "shape": "ciso-assistant",
            "dir": str(ciso),
            "files": ciso_files,
        },
        "poam": str(poam) if poam.is_file() else "",
        "sources": [
            {
                "family": row.get("family"),
                "group": row.get("group"),
                "sensor": row.get("sensor"),
                "name": row.get("name"),
                "sample": row.get("sample"),
                "adapter": row.get("adapter"),
            }
            for row in (sources or [])
        ],
        "note": (
            "File-drop only. Origin Eval reads this JSON (max-5 findings + assets). "
            "Pack does not call Eval HTTP and does not POST /api/risks."
        ),
    }


def write_eval_handoff(out: Path, payload: dict[str, Any] | None = None, **kwargs: Any) -> Path:
    dest = out / "eval" / "handoff.json"
    data = payload if payload is not None else build_eval_handoff(out, **kwargs)
    write_json(dest, data)
    manifest = {
        "handoff": str(dest),
        "posted": False,
        "http": False,
        "posts_api_risks": False,
        "consumer": "origin-eval",
        "max_findings": MAX_FINDINGS,
        "sample": data.get("sample"),
        "client_keep": data.get("client_keep"),
    }
    write_json(out / "eval" / "MANIFEST.json", manifest)
    return dest


def load_handoff(out: Path) -> dict[str, Any]:
    path = out / "eval" / "handoff.json"
    return json.loads(path.read_text(encoding="utf-8"))
