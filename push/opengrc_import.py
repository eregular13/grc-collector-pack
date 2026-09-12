"""OpenGRC Data Manager CSV writers. Live POST skipped (schema not confirmed)."""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any

from push.common import PACK, refuse_live_without_gate, split_canonical

DEST = PACK / "out" / "opengrc"
ASSET_HEADER = ["name", "description", "asset_tag"]
RISK_HEADER = ["title", "description", "mitigation"]
MAPPING = [
    {"csv": "assets.csv", "column": "name", "source": "canonical asset.name"},
    {"csv": "assets.csv", "column": "description", "source": "canonical asset.description"},
    {"csv": "assets.csv", "column": "asset_tag", "source": "canonical asset.ref_id (OpenGRC searchable asset_tag)"},
    {"csv": "risks.csv", "column": "title", "source": "canonical finding.name"},
    {"csv": "risks.csv", "column": "description", "source": "canonical finding.description"},
    {"csv": "risks.csv", "column": "mitigation", "source": "finding.extra.control.name or recommended_action or blank"},
]


def write_files(rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    assets, findings = split_canonical(rows)
    DEST.mkdir(parents=True, exist_ok=True)
    asset_path = DEST / "assets.csv"
    risk_path = DEST / "risks.csv"
    with asset_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ASSET_HEADER)
        writer.writeheader()
        seen: set[str] = set()
        for rec in assets:
            name = str(rec.get("name") or rec.get("ref_id") or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            writer.writerow(
                {
                    "name": name[:200],
                    "description": str(rec.get("description") or "")[:500],
                    "asset_tag": str(rec.get("ref_id") or "")[:80],
                }
            )
    with risk_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RISK_HEADER)
        writer.writeheader()
        for rec in findings:
            extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
            control = extra.get("control") if isinstance(extra.get("control"), dict) else {}
            mit = str(control.get("name") or rec.get("recommended_action") or "")
            writer.writerow(
                {
                    "title": str(rec.get("name") or rec.get("ref_id") or "")[:200],
                    "description": str(rec.get("description") or "")[:500],
                    "mitigation": mit[:500],
                }
            )
    map_path = DEST / "MAPPING.md"
    lines = [
        "# OpenGRC CSV mapping",
        "",
        "Data Manager import: download template in OpenGRC UI and align columns.",
        "Public Sanctum create-body fields are not confirmed here — **no live POST**.",
        "",
        "| File | Column | Source |",
        "| --- | --- | --- |",
    ]
    for row in MAPPING:
        lines.append(f"| `{row['csv']}` | `{row['column']}` | {row['source']} |")
    map_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (DEST / "mapping.json").write_text(json.dumps(MAPPING, indent=2), encoding="utf-8")
    return {
        "assets_csv": str(asset_path),
        "risks_csv": str(risk_path),
        "mapping": str(map_path),
        "asset_rows": len(seen),
        "risk_rows": len(findings),
    }


def plan() -> dict[str, Any]:
    written = write_files()
    url = (os.environ.get("OPENGRC_URL") or "").rstrip("/")
    return {
        "target": "opengrc",
        "dry_run": True,
        "endpoint": "OpenGRC Data Manager CSV (no HTTP; schema unconfirmed — no_post)",
        "opengrc_url_set": bool(url),
        "method": "none (CSV Data Manager; live POST skipped — schema unconfirmed)",
        "http": False,
        "files": written,
        "note": "Import assets.csv then risks.csv in OpenGRC Data Manager. Bearer Sanctum if Reid later confirms fields.",
    }


def live() -> dict[str, Any]:
    refuse_live_without_gate("opengrc")
    url = (os.environ.get("OPENGRC_URL") or "").strip()
    token = (os.environ.get("OPENGRC_TOKEN") or "").strip()
    if not url or not token:
        raise SystemExit(2)
    rec = plan()
    rec["dry_run"] = False
    rec["http"] = False
    rec["live_skipped"] = "opengrc_schema_unconfirmed_no_post"
    return rec
