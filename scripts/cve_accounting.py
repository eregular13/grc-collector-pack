#!/usr/bin/env python3
"""CVE-completeness accounting for a lab/pack work dir. Exit 2 on any loss."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.cve_accounting import summary_line, write_report  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: cve_accounting.py WORK", file=sys.stderr)
        return 2
    report = write_report(Path(argv[1]))
    print(summary_line(report))
    if not report["ok"]:
        print("CVE_ACCOUNTING_FAIL " + json.dumps(
            {"input_not_parsed": report["input_not_parsed"],
             "canonical_unaccounted": report["canonical_unaccounted"]}, sort_keys=True)[:4000],
            file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
