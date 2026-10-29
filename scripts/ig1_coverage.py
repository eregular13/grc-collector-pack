#!/usr/bin/env python3
"""Render CIS v8 IG1 coverage from one or more pack out/ dirs (read-only).

Usage: python scripts/ig1_coverage.py REPORT_DIR OUT_DIR [OUT_DIR ...]
Reads OUT_DIR/poam/poam.csv; writes REPORT_DIR/ig1-coverage.{csv,md}.
No network. Never writes outside REPORT_DIR.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.cis_ig1 import coverage, summary, write_report  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    report = Path(args[0])
    paths = []
    for raw in args[1:]:
        p = Path(raw) / "poam" / "poam.csv"
        if not p.is_file():
            print(f"missing {p}", file=sys.stderr)
            return 2
        paths.append(p)
    rows = coverage(paths)
    write_report(rows, report, [p.parent.parent.name for p in paths])
    print(json.dumps(summary(rows)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
