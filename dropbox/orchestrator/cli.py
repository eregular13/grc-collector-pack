from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dropbox.orchestrator.plan import build_plan
from dropbox.orchestrator.run import run_stages
from dropbox.orchestrator.scope import load_scope


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="orchestrator", description="Evergreen drop-box brakes")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_plan = sub.add_parser("plan", help="Print shards and stages; no live scan")
    p_plan.add_argument("--scope", required=True)
    p_run = sub.add_parser("run", help="Stage machine")
    p_run.add_argument("--scope", required=True)
    p_run.add_argument("--stage", default="all", choices=["discover", "deepen", "ingest", "all"])
    p_run.add_argument("--fixture", action="store_true", default=True)
    p_run.add_argument("--live", action="store_true", help="Request live stages (still refuses unsigned/empty)")
    p_run.add_argument("--run-pack", action="store_true")
    args = parser.parse_args(argv)
    scope = load_scope(Path(args.scope))
    if args.cmd == "plan":
        print(json.dumps(build_plan(scope), indent=2))
        return 0
    fixture = not bool(getattr(args, "live", False))
    result = run_stages(scope, stage=args.stage, fixture=fixture, run_pack=args.run_pack)
    print(json.dumps({"ok": result.get("ok"), "refused": result.get("refused"), "reason": result.get("reason")}, indent=2))
    if result.get("refused"):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
