"""Operator MCP stub hooks. SCOPE-gated. No exploit / attack API.

Wraps existing dropbox CLI and orchestrator functions. Does not start a
Hexstrike server, does not submodule hexstrike-ai, and does not expose
Metasploit / AIExploitGenerator / exploit-chain tools.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from dropbox.orchestrator import byo
from dropbox.orchestrator.farm import Farm
from dropbox.orchestrator.pipeline import (
    STAGE_GRAPH,
    _orch_dir,
    deepen_stage,
    discover_stage,
    ingest_stage,
    integrity_stops,
    orchestrate,
)
from dropbox.scope import ALLOWED_RUNNERS, GateError, LICENSE_LOCK_SPAWN, ORCH_BYO, load_scope

# Goose-style live_ready allowlist (Metis). File-drop / LICENSE-LOCK never join.
LIVE_READY_ALLOW = frozenset(ORCH_BYO) | frozenset(ALLOWED_RUNNERS)

OPERATOR_TOOLS = (
    "scope_status",
    "orchestrator_plan",
    "orchestrator_status",
    "stage_discover",
    "stage_deepen",
    "stage_ingest",
    "farm_slots",
    "farm_slot_status",
    "farm_toolbin_status",
    "export_ciso_poam",
)

TOOL_DESC = {
    "scope_status": "SCOPE gate: client, window, stages, allow_tools ∩ PATH.",
    "orchestrator_plan": "Plan-only orchestrate. Never implies --live.",
    "orchestrator_status": "Stage graph, last integrity stop, shard/batch counters.",
    "stage_discover": "Quiet discover. Live BYO only if allowlisted + on PATH.",
    "stage_deepen": "Gated deepen. Refuses unless stages.deepen is true.",
    "stage_ingest": "Copy artifacts into in/. Does not scan.",
    "farm_slots": "Private SLOTS catalog counts under written SCOPE. No binaries.",
    "farm_slot_status": "Full slot matrix. Optional category filter.",
    "farm_toolbin_status": (
        "FARM_TOOL_BIN resolve: per-slot live_ready plus live_ready_count/slots[]. "
        "Never live_ready for demo_stub or file_drop-only names."
    ),
    "export_ciso_poam": (
        "Reads out/ciso-assistant/ + out/poam/ + out/simplerisk/. "
        "posted false unless CISO_PUSH=1. Conductor http is always false."
    ),
}

# Substrings that must never become callable tools.
REFUSED_ATTACK = (
    "hexstrike",
    "aiexploitgenerator",
    "metasploit",
    "msfconsole",
    "exploit-chain",
    "exploitchain",
    "unauth-autonomous",
    "autonomous spray",
)


def _slot_matrix(allow_tools: list[str]) -> list[dict[str, Any]]:
    from farm.adapters.catalog import slot_matrix

    return slot_matrix(allow_tools)


def farm_slots(scope_path: Path | None = None) -> dict[str, Any]:
    from farm.adapters.catalog import (
        brakes_defaults,
        catalog_summary,
        ingest_map,
        invoke_slots,
        load_catalog,
        wired_slots,
    )

    scope = load_scope(scope_path)
    data = load_catalog()
    wired = wired_slots()
    invoke = invoke_slots()
    counts = catalog_summary()
    return {
        "tool": "farm_slots",
        "private": bool(data.get("private")),
        "hub_publish": bool(data.get("hub_publish")),
        "vendored_binaries": bool(data.get("vendored_binaries")),
        "count": counts["total"],
        "wired": sorted(wired),
        "wired_count": counts["wired"],
        "invoke": sorted(invoke),
        "invoke_count": counts["invoke"],
        "file_drop_count": counts["file_drop"],
        "by_category": counts["by_category"],
        "by_sensor": ingest_map(),
        "brakes": brakes_defaults(),
        "counts": counts,
        "scope_gated": True,
        "client": scope.client_name,
        "demo": "DEMO" in scope.client_name.upper(),
    }


def farm_slot_status_tool(scope_path: Path | None = None, category: str | None = None) -> dict[str, Any]:
    from farm.adapters.catalog import farm_slot_status, invoke_slots, wired_slots

    scope = load_scope(scope_path)
    matrix = farm_slot_status(scope.allow_tools, category=category)
    return {
        "tool": "farm_slot_status",
        "ok": True,
        "live": False,
        "plan_only": True,
        "scope_gated": True,
        "client": scope.client_name,
        "category": category or "",
        "count": len(matrix),
        "wired_count": len(wired_slots()),
        "invoke_count": len(invoke_slots()),
        "matrix": matrix,
        "demo": "DEMO" in scope.client_name.upper(),
    }


def _slot_live_ready(
    *,
    name: str,
    binary: str,
    state: str,
    allowlisted: bool,
    demo_scope: bool,
) -> bool:
    """live_ready is never true for demo_stub, file_drop-only, or LICENSE-LOCK."""
    from farm.adapters.catalog import FILE_DROP_ONLY

    if demo_scope or not allowlisted or state != "present":
        return False
    if name in FILE_DROP_ONLY or binary in FILE_DROP_ONLY:
        return False
    if name in LICENSE_LOCK_SPAWN or binary in LICENSE_LOCK_SPAWN:
        return False
    return name in LIVE_READY_ALLOW or binary in LIVE_READY_ALLOW


def farm_toolbin_status_tool(scope_path: Path | None = None) -> dict[str, Any]:
    """Resolve wired invoke slots via FARM_TOOL_BIN then PATH. Does not invoke.

    Honesty for quiet→loud: DEMO stubs may will_run in farm-toolbin-e2e.
    live_ready stays 0 on DEMO SCOPE, lab stubs, or file_drop-only names
    even if a binary sits under FARM_TOOL_BIN. Real --live needs a signed
    non-DEMO SCOPE plus an allowlisted real binary on the Goose list.
    """
    from dropbox.scanner_free import is_demo_lab_stub
    from farm.adapters.catalog import FILE_DROP_ONLY, invoke_slots, load_slots

    scope = load_scope(scope_path)
    raw = (os.environ.get("FARM_TOOL_BIN") or "").strip()
    allow = {str(t).strip().lower() for t in scope.allow_tools if str(t).strip()}
    demo_scope = "DEMO" in scope.client_name.upper()
    rows: list[dict[str, Any]] = []
    present = missing = demo_stub = file_drop = will_run = live_ready = 0
    seen: set[str] = set()
    for name, slot in sorted(invoke_slots().items()):
        binary = str(slot.get("binary") or name).lower()
        seen.add(name)
        seen.add(binary)
        exe = byo.farm_which(binary)
        if not exe:
            state = "missing"
            missing += 1
        elif is_demo_lab_stub(Path(exe)):
            state = "demo_stub"
            demo_stub += 1
        else:
            state = "present"
            present += 1
        allowlisted = name in allow or binary in allow
        drop_only = name in FILE_DROP_ONLY or binary in FILE_DROP_ONLY
        can_run = allowlisted and bool(exe) and not drop_only
        ready = _slot_live_ready(
            name=name,
            binary=binary,
            state=state,
            allowlisted=allowlisted,
            demo_scope=demo_scope,
        )
        if can_run:
            will_run += 1
        if ready:
            live_ready += 1
        rows.append(
            {
                "slot": name,
                "binary": binary,
                "path": exe or "",
                "state": state,
                "stage": str(slot.get("category") or slot.get("stage") or ""),
                "allowlisted": allowlisted,
                "will_run": can_run,
                "live_ready": ready,
            }
        )
    catalog = load_slots()
    for name in sorted(FILE_DROP_ONLY):
        if name in seen:
            continue
        slot = catalog.get(name) or {}
        binary = str(slot.get("binary") or name).lower()
        exe = byo.farm_which(binary)
        file_drop += 1
        rows.append(
            {
                "slot": name,
                "binary": binary,
                "path": exe or "",
                "state": "file_drop",
                "stage": str(slot.get("category") or slot.get("stage") or "file_drop"),
                "allowlisted": name in allow or binary in allow,
                "will_run": False,
                "live_ready": False,
            }
        )
    refused = [name for name in sorted(LICENSE_LOCK_SPAWN) if byo.farm_which(name) is None]
    return {
        "tool": "farm_toolbin_status",
        "ok": True,
        "live": False,
        "plan_only": True,
        "scope_gated": True,
        "client": scope.client_name,
        "farm_tool_bin": raw,
        "count": len(rows),
        "present": present,
        "missing": missing,
        "demo_stub": demo_stub,
        "file_drop": file_drop,
        "will_run_count": will_run,
        "live_ready_count": live_ready,
        "demo_scope": demo_scope,
        "license_lock_refused": refused,
        "slots": rows,
        "demo": demo_scope,
        "note": (
            "Resolve only. Does not invoke. LICENSE-LOCK names stay refused. "
            "DEMO stubs may will_run in farm-toolbin-e2e; live_ready stays 0 on "
            "DEMO SCOPE, lab stubs, or file_drop-only names even if a binary "
            "is under FARM_TOOL_BIN. Real --live needs signed non-DEMO SCOPE "
            "plus an allowlisted real binary. DEMO ≠ client estate."
        ),
    }


def _will_run_map(summary: dict[str, Any]) -> dict[str, dict[str, bool]]:
    """Per-stage slot → will_run from orchestrate plan JSON. External stays false."""
    out: dict[str, dict[str, bool]] = {}
    top = summary.get("slots") or {}
    for stage in ("discover", "deepen", "external"):
        stage_map: dict[str, bool] = {}
        for source in (top.get(stage), (summary.get(stage) or {}).get("slots")):
            if not isinstance(source, dict):
                continue
            for row in list(source.get("selected") or []) + list(source.get("skipped") or []):
                name = str(row.get("slot") or "").strip()
                if name:
                    stage_map[name] = bool(row.get("will_run"))
        out[stage] = stage_map
    return out


def tools_list_entries() -> list[dict[str, Any]]:
    """Stable tools/list payload. Order is OPERATOR_TOOLS, never sorted."""
    tools: list[dict[str, Any]] = []
    for name in OPERATOR_TOOLS:
        props: dict[str, Any] = {}
        if name == "farm_slot_status":
            props["category"] = {
                "type": "string",
                "description": "Optional slot category filter (discover, inventory, identity, …).",
            }
        tools.append(
            {
                "name": name,
                "description": TOOL_DESC[name],
                "inputSchema": {"type": "object", "properties": props},
            }
        )
    return tools


def refuse_attack_name(name: str) -> None:
    low = (name or "").strip().lower().replace("_", "-")
    for bad in REFUSED_ATTACK:
        if bad in low:
            raise GateError(f"operator MCP refuses {name!r} (no exploit/attack API)")


def dispatch(
    name: str,
    *,
    live: bool = False,
    scope_path: Path | str | None = None,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one operator tool. Deepen stays fail-closed. Live still BYO-only."""
    refuse_attack_name(name)
    tool = (name or "").strip().lower()
    if tool not in OPERATOR_TOOLS:
        raise GateError(f"unknown operator tool {name!r}")
    path = Path(scope_path) if scope_path else None
    extra = arguments if isinstance(arguments, dict) else {}
    if tool == "scope_status":
        return scope_status(scope_path=path)
    if tool == "orchestrator_plan":
        return orchestrator_plan(scope_path=path)
    if tool == "orchestrator_status":
        return orchestrator_status(scope_path=path)
    if tool == "stage_discover":
        return stage_discover(scope_path=path, live=live)
    if tool == "stage_deepen":
        return stage_deepen_tool(scope_path=path, live=live)
    if tool == "stage_ingest":
        return stage_ingest(scope_path=path)
    if tool == "farm_slots":
        return farm_slots(scope_path=path)
    if tool == "farm_slot_status":
        cat = extra.get("category")
        return farm_slot_status_tool(scope_path=path, category=str(cat) if cat else None)
    if tool == "farm_toolbin_status":
        return farm_toolbin_status_tool(scope_path=path)
    return export_ciso_poam(scope_path=path)


def scope_status(scope_path: Path | None = None) -> dict[str, Any]:
    scope = load_scope(scope_path)
    return {
        "tool": "scope_status",
        "client": scope.client_name,
        "window": f"{scope.window_start} .. {scope.window_end}",
        "stage_discover": scope.stage_discover,
        "stage_deepen": scope.stage_deepen,
        "max_workers": scope.max_workers,
        "deepen_batch": scope.deepen_batch,
        "allow_tools": list(scope.allow_tools),
        "path_matrix": byo.tool_matrix(scope.allow_tools),
        "slot_matrix": _slot_matrix(scope.allow_tools),
        "integrity_stops": integrity_stops(scope),
        "demo": "DEMO" in scope.client_name.upper(),
    }


def orchestrator_plan(scope_path: Path | None = None) -> dict[str, Any]:
    """Always plan-only. Never implies --live."""
    scope = load_scope(scope_path)
    summary = orchestrate(scope, live=False)
    summary["tool"] = "orchestrator_plan"
    summary["live"] = False
    summary["will_run"] = _will_run_map(summary)
    return summary


def orchestrator_status(scope_path: Path | None = None) -> dict[str, Any]:
    import json

    scope = load_scope(scope_path)
    summary_path = _orch_dir() / "summary.json"
    last: dict[str, Any] = {}
    if summary_path.is_file():
        last = json.loads(summary_path.read_text(encoding="utf-8"))
    disc = last.get("discover") or {}
    deep = last.get("deepen") or {}
    return {
        "tool": "orchestrator_status",
        "stage_graph": STAGE_GRAPH,
        "stage_discover": scope.stage_discover,
        "stage_deepen": scope.stage_deepen,
        "max_workers": scope.max_workers,
        "deepen_batch": scope.deepen_batch,
        "path_matrix": byo.tool_matrix(scope.allow_tools),
        "slot_matrix": _slot_matrix(scope.allow_tools),
        "last_integrity_stop": last.get("last_integrity_stop")
        or disc.get("skip_reason")
        or deep.get("skip_reason")
        or "",
        "shard_count": disc.get("shard_count"),
        "batch_count": deep.get("batch_count"),
        "discover_destroyed": disc.get("destroyed"),
        "deepen_destroyed": deep.get("destroyed"),
        "demo": "DEMO" in scope.client_name.upper(),
    }


def _annotate_stage(plan: dict[str, Any], tool: str, live: bool) -> dict[str, Any]:
    plan["tool"] = tool
    plan["ok"] = True
    plan["live"] = bool(live)
    plan["plan_only"] = not live
    plan["scope_gated"] = True
    return plan


def stage_discover(scope_path: Path | None = None, live: bool = False) -> dict[str, Any]:
    scope = load_scope(scope_path)
    farm = Farm(max_workers=scope.max_workers)
    plan = discover_stage(scope, farm, live=live)
    return _annotate_stage(plan, "stage_discover", live)


def stage_deepen_tool(scope_path: Path | None = None, live: bool = False) -> dict[str, Any]:
    scope = load_scope(scope_path)
    if not scope.stage_deepen:
        raise GateError("orchestrator.stages.deepen is not true")
    farm = Farm(max_workers=scope.max_workers)
    plan = deepen_stage(scope, farm, live=live)
    return _annotate_stage(plan, "stage_deepen", live)


def stage_ingest(scope_path: Path | None = None) -> dict[str, Any]:
    scope = load_scope(scope_path)
    marker = ingest_stage(scope)
    marker["note"] = (
        marker.get("note")
        or "Layer B feeds Layer C via in/. Collectors stay parse-only."
    )
    return _annotate_stage(marker, "stage_ingest", live=False)


def export_ciso_poam(scope_path: Path | None = None) -> dict[str, Any]:
    """Point at existing CISO/POA&M/SimpleRisk files. Does not invent owner or due.

    posted is false unless CISO_PUSH=1 and DRY_RUN!=1. Conductor http is
    always false — RISKREADY_PUSH never enables HTTP.
    """
    scope = load_scope(scope_path)
    raw = os.environ.get("OUT_DIR")
    root = Path(raw) if raw else Path(__file__).resolve().parents[1] / "out"
    ciso = root / "ciso-assistant"
    poam = root / "poam"
    simplerisk = root / "simplerisk"
    files = []
    for folder in (ciso, poam, simplerisk):
        if not folder.is_dir():
            continue
        for path in sorted(folder.iterdir()):
            if path.is_file():
                files.append(str(path))
    ciso_push = os.environ.get("CISO_PUSH", "0") == "1"
    dry_run = os.environ.get("DRY_RUN", "1") == "1"
    posted = bool(ciso_push and not dry_run)
    return {
        "tool": "export_ciso_poam",
        "ciso_dir": str(ciso),
        "poam_dir": str(poam),
        "simplerisk_dir": str(simplerisk),
        "files": files,
        "owner_due": "blank — human fills",
        "posted": posted,
        "http": False,
        "ciso_push": "1" if ciso_push else "0",
        "clica": "prefer clica or CISO UI import — do not invent FindingsAssessment UUIDs",
        "push_ciso": "push_ciso.sh dry unless CISO_PUSH=1 and DRY_RUN!=1; assets/evidences only",
        "scope_gated": True,
        "client": scope.client_name,
        "demo": "DEMO" in scope.client_name.upper(),
        "wrap": "review-only",
        "note": (
            "Conductor never HTTP. RISKREADY_PUSH is ignored. SimpleRisk is "
            "leave-behind under out/ only."
        ),
    }


def tool_catalog() -> dict[str, Any]:
    """stdio catalog. Not FastMCP. Not Hexstrike. No network bind."""
    return {
        "server": "dropbox-operator-mcp",
        "protocol": "stdio-jsonrpc",
        "hexstrike": False,
        "exploit_api": False,
        "scope_gated": True,
        "tools": [{"name": name, "scope_gated": True} for name in OPERATOR_TOOLS],
    }


def handle_jsonrpc(req: dict[str, Any], *, scope_path: Path | str | None = None) -> dict[str, Any]:
    """One JSON-RPC 2.0 request. tools/call still SCOPE-gated via dispatch."""
    rid = req.get("id")
    method = str(req.get("method") or "")
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "dropbox-operator-mcp", "version": "stub"},
                "capabilities": {"tools": {}},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools_list_entries()}}
    if method == "tools/call":
        params = req.get("params") if isinstance(req.get("params"), dict) else {}
        name = str(params.get("name") or "")
        raw_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        # tools/call is plan-only. Never honor arguments.live / params.live.
        arguments = {k: v for k, v in raw_args.items() if str(k).lower() != "live"}
        try:
            refuse_attack_name(name)
            result = dispatch(name, live=False, scope_path=scope_path, arguments=arguments)
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        except GateError as exc:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": 2, "message": str(exc)}}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}}


def _stdio_loop(*, scope_path: Path | str | None = None) -> int:
    """JSON-RPC stdio loop. tools/call is plan-only. No network bind."""
    for raw in sys.stdin:
        if not raw.strip():
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(
                json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}),
                flush=True,
            )
            continue
        print(json.dumps(handle_jsonrpc(req, scope_path=scope_path), default=str), flush=True)
    return 0


def _scope_from_argv(args: list[str]) -> Path | None:
    if "--scope" not in args:
        return None
    idx = args.index("--scope")
    if idx + 1 >= len(args) or args[idx + 1].startswith("-"):
        return None
    return Path(args[idx + 1])


def serve(argv: list[str] | None = None) -> int:
    """List operator tools, or speak JSON-RPC on stdin (--once / --stdio)."""
    args = list(argv or [])
    scope_path = _scope_from_argv(args)
    if "--stdio" in args:
        return _stdio_loop(scope_path=scope_path)
    if "--once" in args:
        raw = sys.stdin.readline()
        if raw.strip():
            try:
                req = json.loads(raw)
            except json.JSONDecodeError as exc:
                print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}))
                return 1
            print(json.dumps(handle_jsonrpc(req, scope_path=scope_path), default=str))
            return 0
    print(json.dumps(tool_catalog(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"serve", "--list"}:
        rest = args[1:] if args and args[0] in {"serve", "--list"} else args
        return serve(rest)
    print("usage: python3 -m dropbox.mcp_stub serve", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
