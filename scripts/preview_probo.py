#!/usr/bin/env python3
"""Dry createRisk-shaped preview from CISO CSVs. No sockets. Documentation only."""

from __future__ import annotations

import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _out() -> Path:
    raw = os.environ.get("OUT_DIR")
    return Path(raw) if raw else ROOT / "out"


def _ciso_dir(out: Path) -> Path:
    for name in ("ciso-assistant", "ciso_drop"):
        path = out / name
        if path.is_dir():
            return path
    return out / "ciso-assistant"


def build_probo_preview(out: Path | None = None) -> dict:
    out = out or _out()
    findings_path = _ciso_dir(out) / "findings.csv"
    rows = []
    if findings_path.exists():
        with findings_path.open(encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
    create_risk = []
    for row in rows:
        if str(row.get("severity") or "").lower() not in {"high", "critical"}:
            continue
        create_risk.append(
            {
                "shape": "createRisk",
                "documentation_only": True,
                "ref_id": row.get("ref_id"),
                "name": row.get("name"),
                "description": row.get("description"),
                "severity": row.get("severity"),
                "status": "draft",
            }
        )
    return {
        "product": "grc-collector-pack",
        "sink": "probo-documentation",
        "posted": False,
        "createRisk": create_risk,
        "count": len(create_risk),
    }


def write_preview(out: Path | None = None) -> Path:
    out = out or _out()
    dest_dir = out / "import_preview"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "probo.json"
    dest.write_text(json.dumps(build_probo_preview(out), indent=2) + "\n", encoding="utf-8")
    return dest


def main() -> None:
    path = write_preview()
    print(path)


if __name__ == "__main__":
    main()
