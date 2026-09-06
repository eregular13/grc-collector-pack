"""CLI: python -m dropbox.orchestrator plan|run --scope PATH [--stage plan|discover|deepen|ingest|all]"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dropbox.orchestrator.plan import build_plan
from dropbox.orchestrator.run import BrakeError, run
from dropbox.orchestrator.scope import ScopeError, load_scope


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evergreen orchestrator brakes (quiet→loud).")
    parser.add_argument("command", choices=["plan", "run", "console", "mcp"])
    parser.add_argument(
        "--action",
        default="plan",
        help="mcp hook action: plan|status|run|ingest|grc_export",
    )
    parser.add_argument("--scope", required=False, default=str(Path("dropbox/SCOPE.example.yaml")))
    parser.add_argument(
        "--stage",
        default="plan",
        help="plan|discover|deepen|ingest|grc_export|all",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Optional orchestrator out dir (default dropbox/out or DROPBOX_OUT).",
    )
    args = parser.parse_args(argv)
    scope_path = Path(args.scope)
    try:
        if args.command == "console":
            from dropbox.orchestrator.console import serve

            return serve()
        if args.command == "mcp":
            from dropbox.orchestrator.mcp_hook import dispatch

            result = dispatch(args.action, scope_path, args.stage)
            print(json.dumps(result, indent=2))
            return int(result.get("exit") or (0 if result.get("ok") else 2))
        if args.command == "plan":
            scope = load_scope(scope_path)
            print(json.dumps(build_plan(scope), indent=2))
            return 0
        out = Path(args.out) if args.out else None
        payload = run(scope_path, args.stage, dest=out)
        print(json.dumps(payload, indent=2))
        if payload.get("refused"):
            return 2
        return 0
    except ScopeError as exc:
        print(f"SCOPE_FAIL: {exc}", file=sys.stderr)
        return 2
    except BrakeError as exc:
        print(f"BRAKE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
