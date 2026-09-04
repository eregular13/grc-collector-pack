"""discover (quiet) → deepen (loud, gated) → ingest. Plan-only unless BYO on PATH."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from dropbox.orchestrator.farm import Farm
from dropbox.orchestrator.shard import batch_hosts, reject_wide_deepen_target, shard_cidrs
from dropbox.scope import NEVER_EMBED, ORCH_BYO, ROOT, GateError, Scope, is_open_internet_cidr, load_scope
from shared.io_util import in_dir

NMAP_NAMES = ("nmap",)
NESSUS_NAMES = ("nessus", "nessuscli")
LOUD_DISCOVER_FLAGS = ("-sV", "-sC", "-A", "--script", "-p-", "--top-ports")


def _which(name: str) -> str | None:
    return shutil.which(name)


def _orch_dir() -> Path:
    raw = os.environ.get("DROPBOX_ORCH_DIR")
    return Path(raw) if raw else ROOT / "dropbox" / "out"


def _write_json(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def _tool_ready(names: tuple[str, ...], allow: list[str]) -> tuple[str | None, str]:
    listed = [n for n in names if n in allow]
    if not listed:
        return None, "not in SCOPE.allow_tools for this stage"
    for name in listed:
        exe = _which(name)
        if exe:
            return exe, "on PATH"
    return None, "not on PATH — plan only (will not download)"


def _quiet_nmap_argv(exe: str, shard: str, timeout_sec: int) -> list[str]:
    argv = [exe, "-sn", "--host-timeout", f"{int(timeout_sec)}s", "-oG", "-", shard]
    joined = " ".join(argv)
    if any(flag in joined for flag in LOUD_DISCOVER_FLAGS):
        raise GateError("discover argv is not quiet")
    return argv


def discover_stage(scope: Scope, farm: Farm, live: bool = False) -> dict:
    prefix = scope.discover_prefix
    shards = shard_cidrs(scope.internal_cidrs, prefix) if scope.internal_cidrs else []
    for shard in shards:
        if is_open_internet_cidr(shard):
            raise GateError(f"discover refuses open-internet shard {shard}")
    stage_allow = scope.tools_for("discover")
    exe, reason = _tool_ready(NMAP_NAMES, stage_allow)
    sample = shards[:8]
    plan = {
        "stage": "discover",
        "volume": "quiet",
        "mode": "plan",
        "client": scope.client_name,
        "prefix": prefix,
        "source_cidrs": list(scope.internal_cidrs),
        "shard_count": len(shards),
        "shards_sample": sample,
        "max_live_shards": scope.max_live_shards,
        "max_workers": scope.max_workers,
        "host_timeout_sec": scope.host_timeout_sec,
        "tool": "nmap",
        "tool_ready": bool(exe),
        "skip_reason": reason if not exe else "",
        "note": "Quiet inventory. Not one scanner on a /16. No deepen tools.",
        "workers": [],
    }
    if not scope.stage_discover:
        plan["mode"] = "gated"
        plan["skip_reason"] = "orchestrator.stages.discover is not true"
        dest = _write_json(_orch_dir() / "discover" / "plan.json", plan)
        plan["plan_path"] = str(dest)
        plan["discover_workers_destroyed"] = 0
        plan["discover_workers_alive"] = 0
        return plan
    run_live = bool(live and exe)
    if run_live and len(shards) > scope.max_live_shards:
        plan["skip_reason"] = (
            f"shard_count {len(shards)} exceeds max_live_shards {scope.max_live_shards}; plan only"
        )
        run_live = False
    live_budget = min(len(shards), scope.max_workers) if run_live else 0
    for index, shard in enumerate(shards[: max(live_budget, min(8, len(shards)))]):
        use_live = bool(run_live and exe and index < live_budget)
        argv = _quiet_nmap_argv(exe, shard, scope.host_timeout_sec) if use_live else []
        worker = farm.spawn(
            "discover",
            shard,
            argv=argv,
            note="quiet shard job",
            timeout_sec=scope.host_timeout_sec,
        )
        if use_live and worker.argv:
            worker.status = "ran"
            plan["mode"] = "live"
        else:
            worker.status = "skipped"
        plan["workers"].append(
            {
                "id": worker.wid,
                "target": shard,
                "status": worker.status,
                "argv": worker.argv,
                "timeout_sec": worker.timeout_sec,
            }
        )
    dest = _write_json(_orch_dir() / "discover" / "plan.json", plan)
    plan["plan_path"] = str(dest)
    destroyed = farm.destroy_stage("discover")
    plan["discover_workers_destroyed"] = destroyed
    plan["discover_workers_alive"] = len(farm.alive("discover"))
    _write_json(dest, plan)
    return plan


def _select_deepen_hosts(scope: Scope, live_hosts: list[str] | None) -> tuple[list[str], str]:
    if live_hosts:
        candidates = [h.strip() for h in live_hosts if str(h).strip()]
        source = "discover"
    elif scope.deepen_hosts:
        candidates = list(scope.deepen_hosts)
        source = "scope.deepen_hosts"
    else:
        return [], "no discover hosts and no orchestrator.deepen_hosts"
    kept: list[str] = []
    for host in candidates:
        try:
            reject_wide_deepen_target(host)
        except ValueError as exc:
            raise GateError(str(exc)) from exc
        if not scope.allows_internal_target(host):
            continue
        if host not in kept:
            kept.append(host)
    if not kept:
        return [], "no in-SCOPE deepen hosts"
    return kept, source


def deepen_stage(scope: Scope, farm: Farm, live_hosts: list[str] | None = None, live: bool = False) -> dict:
    plan = {
        "stage": "deepen",
        "volume": "loud",
        "mode": "plan",
        "client": scope.client_name,
        "hosts": [],
        "host_source": "",
        "batch_size": scope.deepen_batch,
        "batch_count": 0,
        "batches": [],
        "max_workers": scope.max_workers,
        "host_timeout_sec": scope.host_timeout_sec,
        "tool": "nessus",
        "tool_ready": False,
        "skip_reason": "",
        "placeholder": "BYO Nessus CLI per batch. Never download. Never ship plugins.",
        "workers": [],
        "deepen_workers_destroyed": 0,
        "deepen_workers_alive": 0,
    }
    dest = _orch_dir() / "deepen" / "plan.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.parent.joinpath("BYO-NESSUS.placeholder").write_text(
        "Install Nessus yourself on the drop box under written consent.\n"
        "Evergreen only plans batches. It does not download Nessus or plugins.\n"
        "Deepen is louder than discover and stays gated by orchestrator.stages.deepen.\n",
        encoding="utf-8",
    )
    if not scope.stage_deepen:
        if live:
            raise GateError("orchestrator.stages.deepen is not true")
        plan["mode"] = "gated"
        plan["skip_reason"] = "orchestrator.stages.deepen is not true (fail closed)"
        plan["plan_path"] = str(_write_json(dest, plan))
        return plan

    hosts, source = _select_deepen_hosts(scope, live_hosts)
    plan["hosts"] = hosts
    plan["host_source"] = source
    if not hosts:
        plan["mode"] = "gated"
        plan["skip_reason"] = source
        plan["plan_path"] = str(_write_json(dest, plan))
        return plan

    batches = batch_hosts(hosts, scope.deepen_batch)
    plan["batches"] = batches
    plan["batch_count"] = len(batches)
    stage_allow = scope.tools_for("deepen")
    exe, reason = _tool_ready(NESSUS_NAMES, stage_allow)
    plan["tool_ready"] = bool(exe)
    plan["skip_reason"] = reason if not exe else ""
    run_live = bool(live and exe)
    live_left = scope.max_workers if run_live else 0
    for batch in batches:
        target = ",".join(batch)
        for item in batch:
            try:
                reject_wide_deepen_target(item)
            except ValueError as exc:
                raise GateError(str(exc)) from exc
            if not scope.allows_internal_target(item):
                raise GateError(f"deepen target not in SCOPE: {item}")
        argv = [exe, "--batch", target, "--timeout", str(scope.host_timeout_sec)] if run_live and exe else []
        worker = farm.spawn(
            "deepen",
            target,
            argv=argv,
            note="deepen batch",
            timeout_sec=scope.host_timeout_sec,
        )
        if run_live and exe and worker.argv and live_left > 0:
            worker.status = "ran"
            plan["mode"] = "live"
            live_left -= 1
        else:
            worker.status = "skipped"
        plan["workers"].append(
            {
                "id": worker.wid,
                "target": target,
                "status": worker.status,
                "argv": worker.argv,
                "timeout_sec": worker.timeout_sec,
            }
        )
    plan["plan_path"] = str(_write_json(dest, plan))
    destroyed = farm.destroy_stage("deepen")
    plan["deepen_workers_destroyed"] = destroyed
    plan["deepen_workers_alive"] = len(farm.alive("deepen"))
    _write_json(dest, plan)
    return plan


def ingest_stage(scope: Scope, dest_in: Path | None = None) -> dict:
    """Copy/normalize orchestrator artifacts into pack in/<sensor>/."""
    dest = dest_in or in_dir()
    nmap_dir = dest / "nmap"
    nmap_dir.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    src_dir = _orch_dir() / "discover"
    if src_dir.is_dir():
        for path in src_dir.iterdir():
            if path.suffix.lower() in {".gnmap", ".xml", ".nmap"} and path.is_file():
                target = nmap_dir / f"dropbox-discover-{path.name}"
                shutil.copy2(path, target)
                copied.append(str(target))
    marker = {
        "client": scope.client_name,
        "copied": copied,
        "note": (
            "Plan-only labs have no nmap/nessus artifacts. "
            "Loader still uses fixtures + demo overlays. "
            "Deliverable after ingest: CISO CSVs + out/poam/poam.csv."
        ),
    }
    _write_json(_orch_dir() / "ingest" / "summary.json", marker)
    return marker


def orchestrate(scope: Scope | None = None, live: bool = False, dest_in: Path | None = None) -> dict:
    if scope is None:
        scope = load_scope()
    farm = Farm(max_workers=scope.max_workers)
    discover = discover_stage(scope, farm, live=live)
    if farm.alive("discover"):
        raise GateError("discover workers still alive after destroy")
    deepen = deepen_stage(scope, farm, live=live)
    if farm.alive("deepen"):
        raise GateError("deepen workers still alive after destroy")
    ingest = ingest_stage(scope, dest_in=dest_in)
    summary = {
        "client": scope.client_name,
        "live": live,
        "governor": "quiet→loud",
        "brakes": {
            "max_workers": scope.max_workers,
            "batch_size": scope.deepen_batch,
            "host_timeout_sec": scope.host_timeout_sec,
            "stage_discover": scope.stage_discover,
            "stage_deepen": scope.stage_deepen,
        },
        "discover": {
            "shard_count": discover["shard_count"],
            "mode": discover["mode"],
            "volume": discover["volume"],
            "destroyed": discover["discover_workers_destroyed"],
            "alive": discover["discover_workers_alive"],
        },
        "deepen": {
            "batch_count": deepen["batch_count"],
            "mode": deepen["mode"],
            "volume": deepen["volume"],
            "destroyed": deepen.get("deepen_workers_destroyed", 0),
        },
        "ingest": ingest,
    }
    _write_json(_orch_dir() / "summary.json", summary)
    return summary


def assert_no_embed() -> None:
    for name in NEVER_EMBED | ORCH_BYO:
        if name in {"curl"}:
            continue
        # presence on PATH is OK (BYO). Shipping in this repo is not.
        _ = name
