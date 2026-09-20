#!/usr/bin/env python3
"""CI/lab only. Decide FARM_SHIP=yes|skip for the farm wipe/clone gate.

Not a public operator entrypoint. SAMPLE/DEMO != client. paying_day FAIL.
Identical re-PASS of the same assertion surface is not a ship event.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.farm_ship import (  # noqa: E402
    FARM_SHIP_OK_LINE,
    decide_ship,
    write_github_output,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CI/lab farm ship-surface gate (not an operator entrypoint)"
    )
    parser.add_argument(
        "--root",
        default=str(ROOT),
        help="pack checkout (default: repo root)",
    )
    parser.add_argument(
        "--compare-ref",
        default="",
        help="base SHA (PR base or github.event.before). Empty/zero => ship",
    )
    parser.add_argument(
        "--write-env",
        default="",
        help="append GitHub Actions output (ship=yes|skip ...)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print decision JSON on stdout",
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    decision = decide_ship(root, args.compare_ref)
    dest = Path(args.write_env) if args.write_env else None
    write_github_output(decision, dest)
    if args.json:
        print(json.dumps(decision, indent=2, sort_keys=True))
    else:
        print(f"FARM_SHIP={decision['ship']}")
        print(f"FARM_SHIP_REASON={decision['reason']}")
        print(f"FARM_SHIP_HEAD={decision.get('head') or ''}")
        print(f"FARM_SHIP_SURFACE={decision.get('surface') or ''}")
        changed = decision.get("changed") or []
        if changed:
            print("FARM_SHIP_CHANGED=" + ",".join(changed))
        print("LAB=farm_ship_surface SAMPLE=true DEMO=true paying_day=FAIL")
        print("identical re-PASS of this surface is not a ship event")
        print("SAMPLE/DEMO != client. Not client KEEP.")
        if decision["ship"] == "yes":
            print(FARM_SHIP_OK_LINE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
