"""Operator GRC import. Dry-run default. Dual-gate live. WRAP_DEAD for RiskReady."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from push import ciso_import, opengrc_import, probo_import

TARGETS = ("ciso", "opengrc", "probo", "all", "riskready")


def _wrap_dead() -> dict[str, Any]:
    return {
        "target": "riskready",
        "WRAP_DEAD": True,
        "http": False,
        "note": "RiskReady stay-out. File drop only. No HTTP. No /api/risks.",
    }


def run(target: str, live: bool) -> dict[str, Any]:
    target = (target or "all").lower()
    if target == "riskready":
        rec = _wrap_dead()
        rec["ok"] = False
        rec["exit"] = 2
        print(json.dumps(rec, indent=2))
        raise SystemExit(2)
    if live:
        if target == "ciso":
            rec = ciso_import.live()
        elif target == "opengrc":
            rec = opengrc_import.live()
        elif target == "probo":
            rec = probo_import.live()
        elif target == "all":
            rec = {
                "target": "all",
                "dry_run": False,
                "ciso": ciso_import.live(),
                "opengrc": opengrc_import.live(),
                "probo": probo_import.live(),
                "riskready": _wrap_dead(),
            }
        else:
            raise SystemExit(2)
    else:
        if target == "ciso":
            rec = ciso_import.plan()
        elif target == "opengrc":
            rec = opengrc_import.plan()
        elif target == "probo":
            rec = probo_import.plan()
        elif target == "all":
            rec = {
                "target": "all",
                "dry_run": True,
                "http": False,
                "ciso": ciso_import.plan(),
                "opengrc": opengrc_import.plan(),
                "probo": probo_import.plan(),
                "riskready": _wrap_dead(),
            }
        else:
            raise SystemExit(2)
    rec["ok"] = True
    rec["client_facing_ready"] = False
    print(json.dumps(rec, indent=2, default=str))
    return rec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dropbox.import_grc",
        description="Import pack CSVs/canonical into CISO, OpenGRC, or Probo. --dry-run is default. --help does no HTTP.",
    )
    parser.add_argument("--target", choices=TARGETS, default="all")
    parser.add_argument("--dry-run", action="store_true", help="Plan only (default). No network.")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Requires env URL/token AND push/GATE_<TARGET>. Missing gate → exit 2.",
    )
    args = parser.parse_args(argv)
    if args.live and args.dry_run:
        print("choose --dry-run or --live, not both", file=sys.stderr)
        return 2
    try:
        run(args.target, live=bool(args.live))
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 2
        if args.target == "riskready":
            return 2
        if code == 2:
            print(json.dumps({"ok": False, "error": "live_without_gate", "exit": 2}), file=sys.stderr)
        return code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
