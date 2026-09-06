"""Operator MCP hook: wrap the orchestrator CLI. Not a public attack API.

No socket bind. No scanner install. Live stages still hit SCOPE brakes.
Future MCP servers should call dispatch() — they must not expose raw nmap/nessus argv.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from dropbox.orchestrator.plan import build_plan
from dropbox.orchestrator.run import BrakeError, run
from dropbox.orchestrator.scope import ScopeError, load_scope

ALLOWED = frozenset({"plan", "status", "run", "ingest", "grc_export", "console_status"})
DENIED = frozenset(
    {
        "exploit",
        "c2",
        "spray",
        "scan_internet",
        "nuclei",
        "msf",
        "metasploit",
        "attack",
        "pentest_auto",
    }
)
LIVE_STAGES = frozenset({"discover", "deepen", "all"})


def _looks_like_attack(token: str) -> bool:
    t = (token or "").strip().lower()
    if t in DENIED or t.startswith("attack") or "exploit" in t:
        return True
    return any(bad in t for bad in ("spray", "nuclei", "msf", "c2", "scan_internet"))


def dispatch(action: str, scope_path: Path | str | None = None, stage: str = "plan") -> dict[str, Any]:
    action = (action or "").strip().lower()
    stage = (stage or "plan").strip().lower()
    if _looks_like_attack(action) or _looks_like_attack(stage):
        return {
            "ok": False,
            "error": "not_an_attack_api",
            "exit": 2,
            "note": "Operator MCP wraps plan/run/status only. No payload library.",
        }
    if action not in ALLOWED:
        return {"ok": False, "error": "unknown_action", "exit": 2, "allowed": sorted(ALLOWED)}
    path = Path(scope_path or "dropbox/SCOPE.example.yaml")
    try:
        if action in {"status", "console_status"}:
            from dropbox.orchestrator.console import status_payload

            return {"ok": True, "action": action, "payload": status_payload(), "bind": "none"}
        if action == "plan":
            plan = build_plan(load_scope(path))
            return {"ok": True, "action": "plan", "payload": plan, "exit": 0}
        if action in {"ingest", "grc_export"}:
            stage = action
        payload = run(path, stage)
        refused = payload.get("refused")
        return {
            "ok": refused is None,
            "action": action,
            "stage": stage,
            "payload": payload,
            "exit": 2 if refused else 0,
            "note": "live stages use the same SCOPE brakes as the CLI",
        }
    except ScopeError as exc:
        return {"ok": False, "error": f"SCOPE_FAIL: {exc}", "exit": 2}
    except BrakeError as exc:
        return {"ok": False, "error": f"BRAKE: {exc}", "exit": 2}
