"""Load fixture+estate findings into memory and count mapped vs UNMAPPED. Not a LAN scan."""
from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dropbox.orchestrator.poam import map_finding

PT = timezone(timedelta(hours=-7))
PACK = Path(__file__).resolve().parents[1]
OUT = PACK.parent / "product-lab" / "24h" / "eval"


def _names_from_csv(path: Path) -> list[str]:
    if not path.is_file():
        return []
    rows: list[str] = []
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            name = (row.get("weakness") or row.get("name") or row.get("title") or "").strip()
            if name:
                rows.append(name)
    return rows


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    names.extend(_names_from_csv(PACK / "out-estate" / "poam" / "poam.csv"))
    names.extend(_names_from_csv(PACK / "dropbox" / "out" / "poam.csv"))
    canon = PACK / "out" / "canonical"
    if canon.is_dir():
        for path in canon.glob("*.json"):
            try:
                blob = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            rows = blob if isinstance(blob, list) else blob.get("rows") if isinstance(blob, dict) else []
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("name") or row.get("weakness") or row.get("title") or "").strip()
                if name:
                    names.append(name)
    mapped = Counter()
    unmapped = Counter()
    for name in names:
        rec = map_finding(name, "eval", "medium")
        if rec.get("mapped"):
            mapped[rec.get("weakness") or name] += 1
        else:
            unmapped[name] += 1
    payload = {
        "clock": datetime.now(PT).strftime("%Y-%m-%dT%H:%M:%S-07:00"),
        "note": "in-memory map audit; not a client LAN; not paying-day",
        "input_names": len(names),
        "mapped_classes": mapped.most_common(),
        "unmapped_top": unmapped.most_common(40),
        "unmapped_count": sum(unmapped.values()),
        "mapped_count": sum(mapped.values()),
    }
    path = OUT / "map_audit.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "path": str(path), "mapped": payload["mapped_count"], "unmapped": payload["unmapped_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
