#!/usr/bin/env python3
"""Dry PENDING-shaped RiskReady preview. Never POST /api/risks. No sockets."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _out() -> Path:
    raw = os.environ.get("OUT_DIR")
    return Path(raw) if raw else ROOT / "out"


def _rr_dir(out: Path) -> Path:
    for name in ("riskready", "riskready_drop"):
        path = out / name
        if path.is_dir():
            return path
    return out / "riskready"


def build_rr_preview(out: Path | None = None) -> dict:
    out = out or _out()
    proposed_path = _rr_dir(out) / "risks_proposed.json"
    proposed = []
    if proposed_path.exists():
        proposed = json.loads(proposed_path.read_text(encoding="utf-8"))
    pending = []
    for row in proposed:
        pending.append(
            {
                "shape": "PENDING",
                "hitl": "approve",
                "auto_approve": False,
                "posted": False,
                "ref_id": row.get("ref_id"),
                "name": row.get("name"),
                "severity": row.get("severity"),
                "likelihood": row.get("likelihood"),
                "impact": row.get("impact"),
                "treatment": row.get("treatment"),
            }
        )
    return {
        "product": "grc-collector-pack",
        "sink": "riskready",
        "status": "PENDING",
        "posts_api_risks": False,
        "pending": pending,
        "count": len(pending),
    }


def write_preview(out: Path | None = None) -> tuple[Path, Path]:
    out = out or _out()
    dest_dir = out / "import_preview"
    dest_dir.mkdir(parents=True, exist_ok=True)
    pending_path = dest_dir / "riskready_pending.json"
    pending_path.write_text(json.dumps(build_rr_preview(out), indent=2) + "\n", encoding="utf-8")
    manifest = {
        "written_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": ["probo.json", "riskready_pending.json"],
        "posts_api_risks": False,
        "sockets": False,
        "note": "HITL approve on RiskReady. Never auto-PENDING-approve. Never POST /api/risks.",
    }
    manifest_path = dest_dir / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return pending_path, manifest_path


def main() -> None:
    pending, manifest = write_preview()
    print(pending)
    print(manifest)


if __name__ == "__main__":
    main()
