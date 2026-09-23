"""Operator MCP stub hooks. SCOPE-gated. No exploit / attack API.

Wraps existing dropbox CLI and orchestrator functions. Does not start a
Hexstrike server, does not submodule hexstrike-ai, and does not expose
Metasploit / AIExploitGenerator / exploit-chain tools.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

from dropbox.keep_preflight import (
    KeepFixtureError,
    KeepPackageIncomplete,
    require_keep_package,
    require_keep_samples,
)
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
    "keep_status",
    "keep_ciso",
    "lab_drop",
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
    "keep_status": (
        "SCOPE-gated KEEP four-set inventory. Empty pack in/ is keep_real 0/4. "
        "Lab uses fixtures/keep-samples. Operator twins (hints only): "
        "./scripts/sample_to_sor.sh (SAMPLE keep), ./scripts/farm_drop_to_sor.sh "
        "(farm pack_drop), and ./scripts/lab_drop_to_sor.sh / MCP lab_drop "
        "(LAB dest_in, prove --use-existing-in, no DEMO reseed). "
        "LAB≠SAMPLE≠client. DEMO≠client. No densify."
    ),
    "keep_ciso": (
        "SAMPLE keep-lab only: fixtures/keep-samples → keep/work/out/ciso-assistant/*.csv "
        "+ IMPORT.json + OpenGRC CSVs + Probo preview. Same rails as python -m keep lab "
        "and ./scripts/sample_to_sor.sh (or make sample-to-sor). Farm pack_drop twin: "
        "./scripts/farm_drop_to_sor.sh / make farm-drop-to-sor / "
        ".\\scripts\\farm_drop_to_sor.ps1. LAB dest_in twin: "
        "./scripts/lab_drop_to_sor.sh / MCP lab_drop (prove --use-existing-in; "
        "never reseeds fixtures/pack_drop). Never densify pack in/. "
        "Never POST. paying_day FAIL. Sinks always from keep-lab. "
        "LAB≠SAMPLE≠client."
    ),
    "lab_drop": (
        "LAB dest_in prove twin: python3 scripts/prove_ciso.py --use-existing-in "
        "(same rails as ./scripts/lab_drop_to_sor.sh). Requires populated "
        "arguments.work/in or arguments.dest_in. Never reseeds fixtures/pack_drop. "
        "Empty in/ is EXISTING_IN_FAIL. LAB.txt + DEMO seed trees is LAB_SHAPE_FAIL. "
        "Returns honesty stamps + CISO/POA&M paths plus console_cli_twin / "
        "console_hint (OUT_DIR=<work>/out python -m product; Windows "
        "set OUT_DIR=... / python -m product; bind 127.0.0.1; never POSTs "
        "/api/risks). LAB≠SAMPLE≠client. paying_day FAIL. Not SAMPLE keep. "
        "Not client KEEP."
    ),
}

# Pack-truth tools live on the USB assessment MCP only. Conductor refuses them.
PACK_TRUTH_TOOLS = frozenset(
    {
        "check_scope",
        "license_guard",
        "assessment_ready",
        "assessment-ready",
    }
)

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
        if name == "keep_ciso":
            props["exporters"] = {
                "type": "boolean",
                "description": (
                    "Optional. Same meaning as scripts/sample_to_sor.sh --exporters: "
                    "a re-write of keep-lab OpenGRC/Probo sinks. keep_ciso always "
                    "returns CISO+OpenGRC+Probo from keep.lab; it does not invent "
                    "a second export path."
                ),
            }
            props["isolate_work"] = {
                "type": "boolean",
                "description": (
                    "Optional. Unique work subdirectory under keep/work (or the "
                    "supplied work) so overlapping keep_ciso calls do not share "
                    "out/. Default on when work is the shared keep/work. Not a "
                    "new operator entrypoint."
                ),
            }
        if name == "lab_drop":
            props["work"] = {
                "type": "string",
                "description": (
                    "Isolation dir whose in/ is already populated (LAB compose "
                    "pack_drop or operator copy). Same as scripts/lab_drop_to_sor.sh "
                    "--work. Required unless dest_in is set. Never reseeds."
                ),
            }
            props["dest_in"] = {
                "type": "string",
                "description": (
                    "Explicit dest_in (must be work/in). Must already hold "
                    "pack_drop. Empty or banners-only is EXISTING_IN_FAIL. "
                    "LAB.txt + DEMO adapter trees is LAB_SHAPE_FAIL."
                ),
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


def refuse_cross_wire(name: str) -> None:
    """Pack-truth tools are not conductor tools. Fail closed."""
    tool = (name or "").strip().lower().replace("_", "-")
    packed = (name or "").strip().lower()
    if packed in PACK_TRUTH_TOOLS or tool in PACK_TRUTH_TOOLS:
        raise GateError(
            f"conductor refuses pack-truth tool {name!r} (cross-wire; USB assessment MCP only)"
        )


def dispatch(
    name: str,
    *,
    live: bool = False,
    scope_path: Path | str | None = None,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one operator tool. Deepen stays fail-closed. Live still BYO-only."""
    refuse_attack_name(name)
    refuse_cross_wire(name)
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
    if tool == "keep_status":
        return keep_status(scope_path=path, arguments=extra)
    if tool == "keep_ciso":
        return keep_ciso(scope_path=path, arguments=extra)
    if tool == "lab_drop":
        return lab_drop(scope_path=path, arguments=extra)
    if tool == "export_ciso_poam":
        return export_ciso_poam(scope_path=path)
    raise GateError(f"unknown operator tool {name!r}")


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


KEEP_SENSOR_DIRS = ("identity", "saas", "vuln", "cloud")
KEEP_HONESTY_BANNERS = ("SAMPLE≠client", "DEMO≠client")
OPENGRC_KEY_CSVS = ("risks.csv", "assets.csv", "implementations.csv")
SAMPLE_TO_SOR_SCRIPT = "scripts/sample_to_sor.sh"
SAMPLE_TO_SOR_MAKE = "make sample-to-sor"
SAMPLE_TO_SOR_PS1 = ".\\scripts\\sample_to_sor.ps1"
FARM_DROP_TO_SOR_SCRIPT = "scripts/farm_drop_to_sor.sh"
FARM_DROP_TO_SOR_MAKE = "make farm-drop-to-sor"
FARM_DROP_TO_SOR_PS1 = ".\\scripts\\farm_drop_to_sor.ps1"
LAB_DROP_TO_SOR_SCRIPT = "scripts/lab_drop_to_sor.sh"
LAB_DROP_TO_SOR_MAKE = ""
LAB_DROP_TO_SOR_PS1 = ".\\scripts\\lab_drop_to_sor.ps1"
LAB_HONESTY_BANNERS = ("LAB≠SAMPLE", "LAB≠client", "SAMPLE≠client", "DEMO≠client")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _require_keep_package(root: Path | None = None) -> Path:
    """Fail closed before importing keep. GateError, not ModuleNotFoundError."""
    root = Path(root or _repo_root())
    try:
        return require_keep_package(root)
    except KeepPackageIncomplete as exc:
        raise GateError(str(exc)) from exc


def _path_arg(extra: dict[str, Any], *keys: str) -> Path | None:
    for key in keys:
        raw = extra.get(key)
        if raw:
            return Path(str(raw))
    return None


def _resolve_keep_path(path: Path | str) -> Path:
    """Resolve relative keep paths against the clone root, not process cwd."""
    target = Path(path)
    if target.is_absolute():
        return target
    return _repo_root() / target


def _keep_scope_path(scope_path: Path | str | None = None) -> Path | None:
    """Prefer an explicit SCOPE, else DROPBOX_SCOPE, resolved to the clone root."""
    if scope_path:
        return _resolve_keep_path(scope_path)
    raw = (os.environ.get("DROPBOX_SCOPE") or "").strip()
    if raw:
        return _resolve_keep_path(raw)
    return None


def _keep_pack_in(extra: dict[str, Any] | None = None) -> Path:
    extra = extra if isinstance(extra, dict) else {}
    explicit = _path_arg(extra, "pack_in", "in_dir")
    if explicit:
        return _resolve_keep_path(explicit)
    raw = (os.environ.get("IN_DIR") or "").strip()
    if raw:
        return _resolve_keep_path(raw)
    return _repo_root() / "in"


def _keep_work_dir(extra: dict[str, Any] | None = None) -> Path:
    extra = extra if isinstance(extra, dict) else {}
    return _keep_work_choice(extra)[0]


def _tri_bool(raw: Any) -> bool | None:
    if raw is True or raw == 1:
        return True
    if raw is False or raw == 0:
        return False
    if isinstance(raw, str):
        low = raw.strip().lower()
        if low in {"1", "true", "yes", "on"}:
            return True
        if low in {"0", "false", "no", "off"}:
            return False
    return None


def _want_isolate_work(
    extra: dict[str, Any] | None = None,
    *,
    work_explicit: bool,
) -> bool:
    """Unique work dir: argument / KEEP_CISO_ISOLATE, else default-on for shared keep/work."""
    extra = extra if isinstance(extra, dict) else {}
    arg = _tri_bool(extra.get("isolate_work"))
    if arg is not None:
        return arg
    env = _tri_bool(os.environ.get("KEEP_CISO_ISOLATE"))
    if env is not None:
        return env
    return not work_explicit


def _keep_work_choice(extra: dict[str, Any] | None = None) -> tuple[Path, bool]:
    """Return (base work dir, whether the operator/env picked it)."""
    extra = extra if isinstance(extra, dict) else {}
    explicit = _path_arg(extra, "work")
    if explicit:
        return _resolve_keep_path(explicit), True
    raw = (os.environ.get("KEEP_WORK") or "").strip()
    if raw:
        return _resolve_keep_path(raw), True
    return _repo_root() / "keep" / "work", False


def atomic_keep_work(parent: Path | str | None = None) -> Path:
    """Unique keep_ciso work subdirectory. Not an operator entrypoint."""
    base = Path(parent) if parent else (_repo_root() / "keep" / "work")
    dest = base / f"run-{os.getpid()}-{uuid.uuid4().hex[:10]}"
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def keep_error_text(exc: BaseException, *, stderr: str = "") -> str:
    """Last error / stderr for MCP/conductor. ASCII-safe. Not a success stamp."""
    chunks: list[str] = []
    extra = str(stderr or "").strip()
    if extra:
        chunks.append(extra)
    text = str(exc).strip()
    if text and text not in chunks:
        chunks.append(text)
    winerror = getattr(exc, "winerror", None)
    if winerror is not None and f"WinError {winerror}" not in " ".join(chunks):
        chunks.append(f"WinError {winerror}")
    if not chunks:
        chunks.append(type(exc).__name__)
    return " | ".join(chunks)[-800:]


def retryable_keep_error(exc: BaseException) -> bool:
    """True only for transient wipe / Windows directory races. Never a schema miss."""
    from keep.wipe import retryable_wipe_error

    if retryable_wipe_error(exc):
        return True
    text = str(exc)
    markers = (
        "WinError 145",
        "[WinError 145]",
        "The directory is not empty",
        "Directory not empty",
        "ENOTEMPTY",
        "sharing violation",
        "WinError 32",
        "WinError 5",
    )
    return any(marker in text for marker in markers)


def keep_fail_payload(
    tool: str,
    exc: BaseException,
    *,
    retried: bool = False,
    work: Path | None = None,
    pack_in: Path | None = None,
    isolate_work: bool = False,
    stderr: str = "",
) -> dict[str, Any]:
    """Structured keep_status / keep_ciso fail. ok stays false."""
    err = keep_error_text(exc, stderr=stderr)
    fail_code = str(getattr(exc, "code", "") or "")
    return {
        "tool": tool,
        "ok": False,
        "live": False,
        "demo": True,
        "sample": True,
        "client_keep": False,
        "paying_day": "FAIL",
        "posted": False,
        "http": False,
        "wrap": "review-only",
        "fail_code": fail_code,
        "error": err,
        "stderr": err,
        "retried": bool(retried),
        "isolate_work": bool(isolate_work),
        "work": str(work) if work else "",
        "pack_in": str(pack_in) if pack_in else "",
        "cwd": os.getcwd(),
        "root": str(_repo_root()),
        "banners": list(KEEP_HONESTY_BANNERS),
        "note": (
            f"{tool} failed. Last error: {err}. "
            "SAMPLE != client. DEMO != client. paying_day FAIL."
        ),
    }


def keep_tool_fail_text(result: Any) -> str:
    """Non-empty last-error text when a keep MCP tool returned ok=false."""
    if not isinstance(result, dict):
        return ""
    if result.get("tool") not in {"keep_status", "keep_ciso", "lab_drop"}:
        return ""
    if result.get("ok") is not False:
        return ""
    return str(result.get("stderr") or result.get("error") or f"{result.get('tool')} failed")


def _want_exporters(extra: dict[str, Any] | None = None) -> bool:
    """Accept arguments.exporters (script --exporters). Does not start a second path."""
    extra = extra if isinstance(extra, dict) else {}
    raw = extra.get("exporters")
    if raw is True or raw == 1:
        return True
    if isinstance(raw, str) and raw.strip().lower() in {"1", "true", "yes", "on", "all"}:
        return True
    return False


def _cli_twin_payload(
    root: Path | None,
    *,
    name: str,
    kind: str,
    script_rel: str,
    make: str,
    ps1: str,
    note: str,
) -> dict[str, Any]:
    """Advertise one operator CLI twin. Tolerate missing script on older master."""
    root = Path(root or _repo_root())
    script = root / script_rel
    present = script.is_file()
    script_cmd = f"./{script_rel}"
    ps1_rel = ps1.replace("\\", "/").lstrip("./")
    return {
        "name": name,
        "kind": kind,
        "script": script_cmd if present else "",
        "make": make,
        "ps1": ps1,
        "ps1_present": (root / ps1_rel).is_file(),
        "present": present,
        "command": script_cmd if present else make,
        "note": note,
    }


def sample_to_sor_cli_twin(root: Path | None = None) -> dict[str, Any]:
    """Shell twin of keep_status → keep_ciso. Tolerate missing script on older master."""
    return _cli_twin_payload(
        root,
        name="sample_to_sor",
        kind="sample_keep",
        script_rel=SAMPLE_TO_SOR_SCRIPT,
        make=SAMPLE_TO_SOR_MAKE,
        ps1=SAMPLE_TO_SOR_PS1,
        note=(
            "Shell equivalent of MCP keep_status → keep_ciso. Same keep-lab cold path. "
            "Prefer ./scripts/sample_to_sor.sh when present; otherwise "
            "make sample-to-sor / .\\scripts\\sample_to_sor.ps1 / python -m keep lab. "
            "SAMPLE keep remains the primary KEEP path. SAMPLE≠client. paying_day FAIL."
        ),
    )


def farm_drop_to_sor_cli_twin(root: Path | None = None) -> dict[str, Any]:
    """Farm pack_drop leave-behind twin. Advertise only — keep_ciso does not run it."""
    return _cli_twin_payload(
        root,
        name="farm_drop_to_sor",
        kind="farm_pack_drop",
        script_rel=FARM_DROP_TO_SOR_SCRIPT,
        make=FARM_DROP_TO_SOR_MAKE,
        ps1=FARM_DROP_TO_SOR_PS1,
        note=(
            "Farm leave-behind twin of sample_to_sor: fixtures/pack_drop → "
            "prove/work/out/ciso-assistant via python3 scripts/prove_ciso.py. "
            "./scripts/farm_drop_to_sor.sh / make farm-drop-to-sor / "
            ".\\scripts\\farm_drop_to_sor.ps1. Never writes pack in/. "
            "SAMPLE keep remains the primary KEEP path. SAMPLE/DEMO ≠ client. "
            "paying_day FAIL. This hint does not invent KEEP or run prove_ciso."
        ),
    )


def lab_drop_to_sor_cli_twin(root: Path | None = None) -> dict[str, Any]:
    """LAB dest_in twin. Advertise the existing script; MCP lab_drop runs it."""
    return _cli_twin_payload(
        root,
        name="lab_drop_to_sor",
        kind="lab_dest_in",
        script_rel=LAB_DROP_TO_SOR_SCRIPT,
        make=LAB_DROP_TO_SOR_MAKE,
        ps1=LAB_DROP_TO_SOR_PS1,
        note=(
            "LAB dest_in twin of farm_drop_to_sor: already-populated work/in → "
            "CISO via python3 scripts/prove_ciso.py --use-existing-in. "
            "./scripts/lab_drop_to_sor.sh / .\\scripts\\lab_drop_to_sor.ps1 "
            "(no Makefile first-line). Never reseeds fixtures/pack_drop. "
            "Empty in/ is EXISTING_IN_FAIL. LAB.txt + DEMO trees is LAB_SHAPE_FAIL. "
            "LAB≠SAMPLE≠client. paying_day FAIL. MCP lab_drop is this same path. "
            "Console twin of that out/: OUT_DIR=<work>/out python -m product."
        ),
    )


def console_cli_twin(work: Path | None = None) -> dict[str, Any]:
    """Loopback console twin of a lab_drop prove out/. Advertise only.

    Same dest_in rails as lab_drop / lab_drop_to_sor. Points python -m product
    at that work/out. Never invents client=true. Never POSTs /api/risks.
    """
    if work:
        out_dir = Path(work).resolve() / "out"
        prove = Path(work).resolve() / "prove-ciso.json"
    else:
        out_dir = Path("<work>") / "out"
        prove = Path("<work>") / "prove-ciso.json"
    out_s = str(out_dir)
    posix = f"OUT_DIR={out_s} python -m product"
    windows = f"set OUT_DIR={out_s} && python -m product"
    return {
        "name": "product_console",
        "kind": "loopback_console",
        "out_dir": out_s,
        "prove": str(prove),
        "command": posix,
        "posix": posix,
        "windows": windows,
        "bind": "127.0.0.1",
        "http": False,
        "posted": False,
        "client": False,
        "lab": True,
        "sample": False,
        "paying_day": "FAIL",
        "note": (
            "Loopback console twin of this lab_drop out/. "
            f"{posix} (Windows: {windows}). "
            "Bind 127.0.0.1. Never POSTs /api/risks. "
            "Active out/ picker / PROVE_WORK_ROOT lists sibling prove out/. "
            "No DEMO reseed. LAB≠SAMPLE≠client. paying_day FAIL."
        ),
    }


def console_hint(work: Path | None = None) -> str:
    """One-line operator hint: point python -m product at this prove out/."""
    twin = console_cli_twin(work)
    return (
        f"{twin['posix']} (Windows: {twin['windows']}). "
        "Bind 127.0.0.1. Never POSTs /api/risks. LAB≠SAMPLE≠client."
    )


def keep_ciso_sor_paths(work: Path, stamp: dict[str, Any] | None = None) -> dict[str, Any]:
    """CISO + OpenGRC + Probo paths from keep-lab stamp, else filesystem. No second export."""
    stamp = stamp if isinstance(stamp, dict) else {}
    work_out = Path(work) / "out"
    ciso_dir = Path(stamp.get("ciso_dir") or (work_out / "ciso-assistant"))
    ciso_files = (
        [str(path) for path in sorted(ciso_dir.glob("*.csv"))] if ciso_dir.is_dir() else []
    )
    stamp_import = str(stamp.get("ciso_import") or "").strip()
    import_file = ciso_dir / "IMPORT.json"
    if stamp_import and Path(stamp_import).is_file():
        ciso_import = str(Path(stamp_import))
    elif import_file.is_file():
        ciso_import = str(import_file)
    else:
        ciso_import = stamp_import

    opengrc_dir = Path(stamp.get("opengrc") or (work_out / "opengrc"))
    opengrc_files: list[str] = []
    if opengrc_dir.is_dir():
        for name in OPENGRC_KEY_CSVS:
            path = opengrc_dir / name
            if path.is_file():
                opengrc_files.append(str(path))
    opengrc = {
        "dir": str(opengrc_dir) if opengrc_dir.is_dir() else "",
        "files": opengrc_files,
    }

    stamp_probo = str(stamp.get("probo") or "").strip()
    preview = work_out / "import_preview" / "probo.json"
    if stamp_probo and Path(stamp_probo).is_file():
        probo = str(Path(stamp_probo))
    elif preview.is_file():
        probo = str(preview)
    else:
        probo = stamp_probo

    return {
        "ciso_dir": str(ciso_dir),
        "ciso_files": ciso_files,
        "ciso_import": ciso_import,
        "opengrc": opengrc,
        "probo": probo,
    }


def _pack_fingerprint(folder: Path) -> dict[str, bytes]:
    """Relative path → bytes for non-skip files. Detect THIS-run pack in/ writes."""
    out: dict[str, bytes] = {}
    if not folder.is_dir():
        return out
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.name in {".gitkeep", ".DS_Store"}:
            continue
        rel = str(path.relative_to(folder)).replace("\\", "/")
        out[rel] = path.read_bytes()
    return out


def _keep_family_inventory(folder: Path) -> dict[str, Any]:
    """Four-set inventory via keep.adapters (same detect helpers keepmin uses)."""
    from keep.adapters import KEEP_FAMILIES, client_keep_ready, scan_keep_dir

    rows: list[dict[str, Any]] = []
    if folder.is_dir():
        for sensor in KEEP_SENSOR_DIRS:
            rows.extend(scan_keep_dir(folder / sensor))
    families: dict[str, Any] = {}
    for name in KEEP_FAMILIES:
        hits = [row for row in rows if str(row.get("group") or "") == name]
        present = bool(hits)
        sample = any(bool(row.get("sample")) for row in hits)
        real = present and not sample
        families[name] = {
            "present": present,
            "sample": sample,
            "real": real,
            "paths": [str(row.get("path") or "") for row in hits],
            "files": [str(row.get("name") or "") for row in hits],
        }
    real_count = sum(1 for row in families.values() if row["real"])
    return {
        "families": families,
        "keep_real": f"{real_count}/4",
        "keep_real_count": real_count,
        "keep_real_of": 4,
        "rows": rows,
        "client_keep": client_keep_ready(rows),
    }


def keep_status(
    scope_path: Path | None = None,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """SCOPE-gated KEEP four-set inventory. Detect + report only. Never scans."""
    root = _require_keep_package(_repo_root())
    extra = arguments if isinstance(arguments, dict) else {}
    pack_in = _keep_pack_in(extra)
    last: BaseException | None = None
    retried = False
    for attempt in range(2):
        try:
            payload = _keep_status_once(
                scope_path=scope_path,
                extra=extra,
                root=root,
                pack_in=pack_in,
            )
            payload["retried"] = retried
            payload["ok"] = True
            payload["error"] = ""
            payload["stderr"] = ""
            return payload
        except GateError:
            raise
        except KeepFixtureError as exc:
            return keep_fail_payload("keep_status", exc, retried=retried, pack_in=pack_in)
        except Exception as exc:
            last = exc
            if attempt == 0 and retryable_keep_error(exc):
                retried = True
                continue
            return keep_fail_payload("keep_status", exc, retried=retried, pack_in=pack_in)
    return keep_fail_payload(
        "keep_status",
        last or RuntimeError("keep_status failed"),
        retried=True,
        pack_in=pack_in,
    )


def _keep_status_once(
    *,
    scope_path: Path | None,
    extra: dict[str, Any],
    root: Path,
    pack_in: Path,
) -> dict[str, Any]:
    scope = load_scope(_keep_scope_path(scope_path))
    require_keep_samples(root)
    inventory = _keep_family_inventory(pack_in)
    samples_dir = root / "fixtures" / "keep-samples"
    keep_real = str(inventory["keep_real"])
    empty_pack = inventory["keep_real_count"] == 0
    return {
        "tool": "keep_status",
        "ok": True,
        "live": False,
        "plan_only": True,
        "scope_gated": True,
        "client": scope.client_name,
        "demo": True,
        "sample": True,
        "pack_in": str(pack_in),
        "pack_in_empty": empty_pack,
        "sensors": list(KEEP_SENSOR_DIRS),
        "families": inventory["families"],
        "keep_real": keep_real,
        "keep_real_count": inventory["keep_real_count"],
        "keep_real_of": 4,
        "client_keep": False,
        "lab_source": "fixtures/keep-samples",
        "sample_path": True,
        "densify": False,
        "fixtures_keep_samples": {
            "present": samples_dir.is_dir(),
            "path": str(samples_dir),
            "lab_only": True,
            "keep_real": "0/4",
            "note": (
                "keep_ciso / python -m keep lab uses fixtures/keep-samples. "
                "SAMPLE≠client KEEP. Not a densify path."
            ),
        },
        "cli_twin": sample_to_sor_cli_twin(root),
        "farm_drop_cli_twin": farm_drop_to_sor_cli_twin(root),
        "lab_drop_cli_twin": lab_drop_to_sor_cli_twin(root),
        "banners": list(KEEP_HONESTY_BANNERS),
        "paying_day": "FAIL",
        "posted": False,
        "http": False,
        "wrap": "review-only",
        "note": (
            f"Pack in/ keep_real {keep_real}. Empty pack in/ is 0/4. "
            "Operator lab path is fixtures/keep-samples → keep/work/out "
            "(SAMPLE≠client). Operator twins (hints only): "
            "./scripts/sample_to_sor.sh / make sample-to-sor / "
            ".\\scripts\\sample_to_sor.ps1 (SAMPLE keep) and "
            "./scripts/farm_drop_to_sor.sh / make farm-drop-to-sor / "
            ".\\scripts\\farm_drop_to_sor.ps1 (farm pack_drop; never pack in/) "
            "and ./scripts/lab_drop_to_sor.sh / MCP lab_drop "
            "(LAB dest_in; prove --use-existing-in; no DEMO reseed). "
            "Detect via keep.adapters (same helpers "
            "dropbox.orchestrator.keepmin uses). Does not densify pack in/. "
            "Does not invent non-sample files. Does not require signed "
            "self-SCOPE. DEMO≠client. paying_day FAIL. No POST /api/risks. No scan."
        ),
    }


def keep_ciso(
    scope_path: Path | None = None,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """SCOPE-gated SAMPLE keep-lab. Same rails as `python -m keep lab`.

    Always fixtures/keep-samples → keep/work/out (CISO + OpenGRC + Probo).
    DRY_RUN=1, GRC_LIVE_SCAN=0, CISO_PUSH=0, RISKREADY_PUSH=0. Never densifies
    pack in/. Never invents non-sample files. Never POST. Never spawns scanners.
    Return lists every SoR path so the operator does not memorize keep-lab layout.
    arguments.exporters is accepted (script --exporters re-write) but sinks
    always come from keep.lab — no second export path. Also advertises the
    farm pack_drop operator twin (farm_drop_to_sor) as a hint only.
    arguments.isolate_work is optional: unique subdirectory so overlapping
    calls do not share out/. Default on when work is the shared keep/work.
    One retry on transient wipe / Windows directory errors only.
    """
    root = _require_keep_package(_repo_root())
    extra = arguments if isinstance(arguments, dict) else {}
    operator_pack_in = _keep_pack_in(extra)
    base_work, work_explicit = _keep_work_choice(extra)
    isolate = _want_isolate_work(extra, work_explicit=work_explicit)
    work = atomic_keep_work(base_work) if isolate else base_work
    last: BaseException | None = None
    retried = False
    for attempt in range(2):
        try:
            return _keep_ciso_once(
                scope_path=scope_path,
                extra=extra,
                root=root,
                operator_pack_in=operator_pack_in,
                work=work,
                isolate_work=isolate,
                retried=retried,
            )
        except GateError:
            raise
        except KeepFixtureError as exc:
            return keep_fail_payload(
                "keep_ciso",
                exc,
                retried=retried,
                work=work,
                pack_in=operator_pack_in,
                isolate_work=isolate,
            )
        except Exception as exc:
            last = exc
            if attempt == 0 and retryable_keep_error(exc):
                retried = True
                continue
            return keep_fail_payload(
                "keep_ciso",
                exc,
                retried=retried,
                work=work,
                pack_in=operator_pack_in,
                isolate_work=isolate,
            )
    return keep_fail_payload(
        "keep_ciso",
        last or RuntimeError("keep_ciso failed"),
        retried=True,
        work=work,
        pack_in=operator_pack_in,
        isolate_work=isolate,
    )


def _keep_ciso_once(
    *,
    scope_path: Path | None,
    extra: dict[str, Any],
    root: Path,
    operator_pack_in: Path,
    work: Path,
    isolate_work: bool,
    retried: bool,
) -> dict[str, Any]:
    from keep.lab import keep_lab
    from keep.wipe import reset_dir

    scope = load_scope(_keep_scope_path(scope_path))
    before = _pack_fingerprint(operator_pack_in)
    # Twin wipe of this call's keep/work/{in,out} trees. Isolated calls
    # wipe only their unique subdirectory, not the shared keep/work/out.
    reset_dir(work / "in")
    reset_dir(work / "out")
    # Isolated empty pack_in so keep_lab lands fixtures/keep-samples only.
    # Do not pass operator pack in/ — this week's slice does not densify.
    isolated = work / "sample-pack-in"
    isolated.mkdir(parents=True, exist_ok=True)
    stamp = keep_lab(root, pack_in=isolated, work=work)
    after = _pack_fingerprint(operator_pack_in)
    wrote_pack = before != after
    sor = keep_ciso_sor_paths(work, stamp)
    handoff = work / "out" / "eval" / "handoff.json"
    estate = "SAMPLE/DEMO — not a client estate"
    exporters = _want_exporters(extra)
    ok = stamp.get("status") == "pass" and not wrote_pack
    reason = ""
    fail_code = str(stamp.get("fail_code") or "")
    if not ok:
        reason = str(stamp.get("reason") or "").strip()
        if wrote_pack and not reason:
            reason = "keep_ciso wrote pack in/"
        if not reason:
            reason = "keep_lab status is not pass"
        if not fail_code and reason:
            fail_code = reason.split(":", 1)[0].strip()
            if " " in fail_code or not fail_code.startswith("KEEP_"):
                fail_code = ""
    return {
        "tool": "keep_ciso",
        "ok": ok,
        "fail_code": fail_code,
        "error": reason,
        "stderr": reason,
        "retried": bool(retried),
        "isolate_work": bool(isolate_work),
        "live": False,
        "dry_run": True,
        "scope_gated": True,
        "client": scope.client_name,
        "demo": True,
        "sample": True,
        "client_keep": False,
        "origin": "keep-samples",
        "lab_source": "fixtures/keep-samples",
        "sample_path": True,
        "densify": False,
        "estate": estate,
        "pack_in": str(operator_pack_in),
        "pack_in_written": wrote_pack,
        "work": str(work),
        "ciso_dir": sor["ciso_dir"],
        "ciso_files": sor["ciso_files"],
        "ciso_import": sor["ciso_import"],
        "opengrc": sor["opengrc"],
        "probo": sor["probo"],
        "cli_twin": sample_to_sor_cli_twin(root),
        "farm_drop_cli_twin": farm_drop_to_sor_cli_twin(root),
        "lab_drop_cli_twin": lab_drop_to_sor_cli_twin(root),
        "exporters": exporters,
        "exporters_from": "keep-lab",
        "handoff": str(handoff) if handoff.is_file() else str(stamp.get("handoff") or ""),
        "keep_lab": str(work / "keep-lab.json"),
        "posted": False,
        "http": False,
        "wrap": "review-only",
        "ciso_push": "0",
        "riskready_push": "0",
        "grc_live_scan": "0",
        "dry_run_env": "1",
        "banners": list(KEEP_HONESTY_BANNERS),
        "paying_day": "FAIL",
        "stamp": stamp,
        "note": (
            "SAMPLE keep-lab path: fixtures/keep-samples → "
            "keep/work/out/ciso-assistant/*.csv + IMPORT.json + "
            "opengrc/{risks,assets,implementations}.csv + "
            "import_preview/probo.json + eval/handoff.json. "
            "Same rails as python -m keep lab and ./scripts/sample_to_sor.sh "
            "(or make sample-to-sor). Farm pack_drop twin (hint only; this "
            "tool does not run it): ./scripts/farm_drop_to_sor.sh / "
            "make farm-drop-to-sor / .\\scripts\\farm_drop_to_sor.ps1. "
            "LAB dest_in twin (hint; this tool does not run it): "
            "./scripts/lab_drop_to_sor.sh / MCP lab_drop "
            "(prove --use-existing-in; no DEMO reseed). "
            "Sinks always from keep-lab "
            "(arguments.exporters is optional re-write, not a second path). "
            "arguments.isolate_work is optional unique work (default on for "
            "shared keep/work). DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 "
            "RISKREADY_PUSH=0. "
            "Does not densify pack in/. Does not invent non-sample files. "
            "Does not require signed self-SCOPE. SAMPLE≠client. DEMO≠client. "
            "paying_day FAIL."
        ),
    }


def _lab_drop_work_and_dest_in(extra: dict[str, Any]) -> tuple[Path, Path]:
    """Resolve work + dest_in. dest_in must be work/in. Never invents a seed."""
    extra = extra if isinstance(extra, dict) else {}
    dest_in = _path_arg(extra, "dest_in", "in_dir")
    work = _path_arg(extra, "work")
    if dest_in:
        dest_in = _resolve_keep_path(dest_in)
        if dest_in.name != "in":
            raise RuntimeError(
                "EXISTING_IN_FAIL lab_drop dest_in must be named in/ (work/in); "
                "will not seed fixtures/pack_drop."
            )
        if work:
            work = _resolve_keep_path(work)
            expected = work / "in"
            if dest_in.resolve() != expected.resolve():
                raise RuntimeError(
                    "EXISTING_IN_FAIL lab_drop dest_in must be work/in; "
                    "will not seed fixtures/pack_drop."
                )
        else:
            work = dest_in.parent
        return work, dest_in
    if work:
        work = _resolve_keep_path(work)
        return work, work / "in"
    raise RuntimeError(
        "EXISTING_IN_FAIL lab_drop requires arguments.work or arguments.dest_in "
        "already populated; will not seed fixtures/pack_drop."
    )


def lab_drop_fail_payload(
    exc: BaseException,
    *,
    work: Path | None = None,
    dest_in: Path | None = None,
    pack_in: Path | None = None,
    seeded: bool = False,
) -> dict[str, Any]:
    """Structured lab_drop fail. ok stays false. LAB≠SAMPLE≠client."""
    err = keep_error_text(exc)
    fail_code = str(getattr(exc, "code", "") or "")
    if not fail_code:
        if "LAB_SHAPE_FAIL" in err:
            fail_code = "LAB_SHAPE_FAIL"
        elif "EXISTING_IN_FAIL" in err:
            fail_code = "EXISTING_IN_FAIL"
    return {
        "tool": "lab_drop",
        "ok": False,
        "live": False,
        "demo": True,
        "sample": False,
        "lab": True,
        "seeded": bool(seeded),
        "use_existing_in": True,
        "client": False,
        "client_keep": False,
        "paying_day": "FAIL",
        "posted": False,
        "http": False,
        "wrap": "review-only",
        "fail_code": fail_code,
        "error": err,
        "stderr": err,
        "work": str(work) if work else "",
        "dest_in": str(dest_in) if dest_in else "",
        "pack_in": str(pack_in) if pack_in else "",
        "cwd": os.getcwd(),
        "root": str(_repo_root()),
        "cli_twin": lab_drop_to_sor_cli_twin(_repo_root()),
        "farm_drop_cli_twin": farm_drop_to_sor_cli_twin(_repo_root()),
        "banners": list(LAB_HONESTY_BANNERS),
        "note": (
            f"lab_drop failed. Last error: {err}. "
            "LAB != SAMPLE != client. DEMO != client. paying_day FAIL. "
            "Did not reseed fixtures/pack_drop."
        ),
    }


def lab_drop(
    scope_path: Path | None = None,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """SCOPE-gated LAB dest_in prove. Same rails as lab_drop_to_sor / --use-existing-in.

    Requires populated work/in (or dest_in). Never reseeds fixtures/pack_drop.
    Empty in/ is EXISTING_IN_FAIL. LAB.txt + DEMO seed trees is LAB_SHAPE_FAIL.
    LAB≠SAMPLE≠client. paying_day FAIL. Never writes pack in/. Never POST.
    """
    extra = arguments if isinstance(arguments, dict) else {}
    load_scope(_keep_scope_path(scope_path))
    pack_in = _keep_pack_in(extra)
    work: Path | None = None
    dest_in: Path | None = None
    try:
        work, dest_in = _lab_drop_work_and_dest_in(extra)
        return _lab_drop_once(
            scope_path=scope_path,
            work=work,
            dest_in=dest_in,
            pack_in=pack_in,
        )
    except Exception as exc:
        return lab_drop_fail_payload(exc, work=work, dest_in=dest_in, pack_in=pack_in)


def _lab_drop_once(
    *,
    scope_path: Path | None,
    work: Path,
    dest_in: Path,
    pack_in: Path,
) -> dict[str, Any]:
    from scripts.prove_ciso import (
        ExistingInError,
        LabShapeError,
        dest_in_has_lab_stamp,
        prove_ciso,
        unexpected_demo_adapter_trees,
        verify_farm_drop_sor,
    )

    scope = load_scope(_keep_scope_path(scope_path))
    before_dest = _pack_fingerprint(dest_in)
    before_pack = _pack_fingerprint(pack_in)
    try:
        stamp = prove_ciso(root=_repo_root(), dest=work, use_existing_in=True)
        verify_farm_drop_sor(work)
    except (ExistingInError, LabShapeError):
        raise
    after_dest = _pack_fingerprint(dest_in)
    after_pack = _pack_fingerprint(pack_in)
    wrote_dest = before_dest != after_dest
    wrote_pack = before_pack != after_pack
    ok = (
        stamp.get("status") == "pass"
        and stamp.get("seeded") is False
        and stamp.get("use_existing_in") is True
        and stamp.get("lab") is True
        and stamp.get("sample") is False
        and stamp.get("client") is False
        and not wrote_dest
        and not wrote_pack
    )
    reason = ""
    fail_code = ""
    if not ok:
        if wrote_dest:
            reason = "LAB_SHAPE_FAIL lab_drop rewrote dest_in (silent reseed)"
            fail_code = "LAB_SHAPE_FAIL"
        elif wrote_pack:
            reason = "lab_drop wrote pack in/"
        else:
            reason = str(stamp.get("reason") or "lab prove status is not pass")
            if stamp.get("seeded") is True:
                fail_code = "LAB_SHAPE_FAIL"
                reason = f"LAB_SHAPE_FAIL {reason}"
    ciso_dir = Path(stamp.get("ciso_dir") or (work / "out" / "ciso-assistant"))
    ciso_files = (
        [str(path) for path in sorted(ciso_dir.glob("*.csv"))] if ciso_dir.is_dir() else []
    )
    poam = str(stamp.get("poam") or (work / "out" / "poam" / "poam.csv"))
    poam_md = str(stamp.get("poam_md") or (work / "out" / "poam" / "poam.md"))
    prove = work / "prove-ciso.json"
    out_dir = (work / "out").resolve()
    unexpected = unexpected_demo_adapter_trees(dest_in)
    estate = str(stamp.get("estate") or "LAB/DEMO — not a client estate")
    console = console_cli_twin(work)
    return {
        "tool": "lab_drop",
        "ok": ok,
        "fail_code": fail_code,
        "error": reason,
        "stderr": reason,
        "live": False,
        "dry_run": True,
        "scope_gated": True,
        "client": scope.client_name,
        "demo": True,
        "sample": False,
        "lab": True,
        "seeded": False,
        "use_existing_in": True,
        "client_keep": False,
        "estate": estate,
        "dest_in": str(dest_in),
        "dest_in_written": wrote_dest,
        "pack_in": str(pack_in),
        "pack_in_written": wrote_pack,
        "work": str(work),
        "out": str(out_dir),
        "ciso_dir": str(ciso_dir),
        "ciso_files": ciso_files,
        "poam": poam,
        "poam_md": poam_md,
        "prove": str(prove) if prove.is_file() else "",
        "lab_stamp": dest_in_has_lab_stamp(dest_in),
        "unexpected_demo_adapters": unexpected,
        "cli_twin": lab_drop_to_sor_cli_twin(_repo_root()),
        "farm_drop_cli_twin": farm_drop_to_sor_cli_twin(_repo_root()),
        "sample_cli_twin": sample_to_sor_cli_twin(_repo_root()),
        "console_cli_twin": console,
        "console_hint": console_hint(work),
        "posted": False,
        "http": False,
        "wrap": "review-only",
        "ciso_push": "0",
        "riskready_push": "0",
        "grc_live_scan": "0",
        "dry_run_env": "1",
        "banners": list(LAB_HONESTY_BANNERS),
        "paying_day": "FAIL",
        "stamp": stamp,
        "note": (
            "LAB dest_in path: populated work/in → out/ciso-assistant/*.csv "
            "+ out/poam/poam.csv via python3 scripts/prove_ciso.py --use-existing-in. "
            "Same rails as ./scripts/lab_drop_to_sor.sh / "
            ".\\scripts\\lab_drop_to_sor.ps1 (no Makefile first-line). "
            "Console twin: OUT_DIR=<work>/out python -m product "
            "(Windows: set OUT_DIR=... && python -m product). "
            "Bind 127.0.0.1. Never POSTs /api/risks. "
            "Never reseeds fixtures/pack_drop. Empty in/ is EXISTING_IN_FAIL. "
            "LAB.txt + DEMO seed trees is LAB_SHAPE_FAIL. "
            "Does not densify pack in/. LAB≠SAMPLE≠client. DEMO≠client. "
            "paying_day FAIL. SAMPLE keep remains the primary KEEP path. "
            "farm_drop_to_sor remains the fixture seed path. "
            "Does not invent client=true."
        ),
    }


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
    ciso_files = [
        str(path)
        for path in files
        if Path(path).parent.name == "ciso-assistant" and path.endswith(".csv")
    ]
    return {
        "tool": "export_ciso_poam",
        "ciso_dir": str(ciso),
        "poam_dir": str(poam),
        "simplerisk_dir": str(simplerisk),
        "files": files,
        "ciso_files": ciso_files,
        "sor": "ciso-assistant",
        "owner_due": "blank — human fills",
        "posted": posted,
        "http": False,
        "ciso_push": "1" if ciso_push else "0",
        "clica": "Desktop: clica or CISO UI import of out/ciso-assistant/*.csv — do not invent FindingsAssessment UUIDs",
        "push_ciso": "Desktop: bash push_ciso.sh (no make/gh). Dry unless CISO_PUSH=1 and DRY_RUN!=1; assets/evidences only",
        "scope_gated": True,
        "client": scope.client_name,
        "demo": "DEMO" in scope.client_name.upper(),
        "wrap": "review-only",
        "note": (
            "Operator SoR is out/ciso-assistant/*.csv. posted false unless "
            "CISO_PUSH=1 and DRY_RUN!=1. Conductor never HTTP. RISKREADY_PUSH "
            "is ignored. SimpleRisk is leave-behind under out/ only."
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
        "pack_truth": False,
        "farm_mcp_pack_truth": False,
        "cross_wire": "fail-closed",
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
            fail = keep_tool_fail_text(result)
            if fail:
                return {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {"code": 2, "message": fail, "data": result},
                }
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
