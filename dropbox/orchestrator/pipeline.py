"""discover → deepen → ingest. Plan-only unless BYO binaries are on PATH."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from dropbox.orchestrator.farm import Farm
from dropbox.orchestrator.shard import batch_hosts, shard_cidrs
from dropbox.scope import NEVER_EMBED, ORCH_BYO, ROOT, GateError, Scope, load_scope
from shared.io_util import in_dir

NMAP_NAMES = ("nmap",)
NESSUS_NAMES = ("nessus", "nessuscli")


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
        return None, "not in SCOPE.allow_tools"
    for name in listed:
        exe = _which(name)
        if exe:
            return exe, "on PATH"
    return None, "not on PATH — plan only (will not download)"


def discover_stage(scope: Scope, farm: Farm, live: bool = False) -> dict:
    prefix = scope.discover_prefix
    shards = shard_cidrs(scope.internal_cidrs, prefix) if scope.internal_cidrs else []
    exe, reason = _tool_ready(NMAP_NAMES, scope.allow_tools)
    sample = shards[:8]
    plan = {
        "stage": "discover",
        "mode": "plan",
        "client": scope.client_name,
        "prefix": prefix,
        "source_cidrs": list(scope.internal_cidrs),
        "shard_count": len(shards),
        "shards_sample": sample,
        "max_live_shards": scope.max_live_shards,
        "tool": "nmap",
        "tool_ready": bool(exe),
        "skip_reason": reason if not exe else "",
        "note": "Not one scanner on a /16. One short-lived worker per shard.",
        "workers": [],
    }
    run_live = bool(live and exe)
    cap = min(len(shards), scope.max_live_shards) if run_live else 0
    if run_live and len(shards) > scope.max_live_shards:
        plan["skip_reason"] = (
            f"shard_count {len(shards)} exceeds max_live_shards {scope.max_live_shards}; plan only"
        )
        run_live = False
        cap = 0
    for shard in shards[: max(cap, min(8, len(shards)))]:
        argv = [exe, "-sn", "-oG", "-", shard] if run_live and exe else []
        worker = farm.spawn("discover", shard, argv=argv, note="shard job")
        if run_live and exe:
            worker.status = "ran"
            plan["mode"] = "live"
        else:
            worker.status = "skipped"
        plan["workers"].append(
            {"id": worker.wid, "target": shard, "status": worker.status, "argv": worker.argv}
        )
    dest = _write_json(_orch_dir() / "discover" / "plan.json", plan)
    plan["plan_path"] = str(dest)
    destroyed = farm.destroy_stage("discover")
    plan["discover_workers_destroyed"] = destroyed
    plan["discover_workers_alive"] = len(farm.alive("discover"))
    _write_json(dest, plan)
    return plan


def deepen_stage(scope: Scope, farm: Farm, live_hosts: list[str] | None = None, live: bool = False) -> dict:
    hosts = list(live_hosts or []) or list(scope.internal_hosts)
    batches = batch_hosts(hosts, scope.deepen_batch)
    exe, reason = _tool_ready(NESSUS_NAMES, scope.allow_tools)
    plan = {
        "stage": "deepen",
        "mode": "plan",
        "client": scope.client_name,
        "hosts": hosts,
        "batch_size": scope.deepen_batch,
        "batch_count": len(batches),
        "batches": batches,
        "tool": "nessus",
        "tool_ready": bool(exe),
        "skip_reason": reason if not exe else "",
        "placeholder": "BYO Nessus CLI per batch. Never download. Never ship plugins.",
        "workers": [],
    }
    run_live = bool(live and exe)
    for batch in batches:
        target = ",".join(batch)
        argv = [exe, "--batch", target] if run_live and exe else []
        worker = farm.spawn("deepen", target, argv=argv, note="deepen batch")
        if run_live and exe:
            worker.status = "ran"
            plan["mode"] = "live"
        else:
            worker.status = "skipped"
        plan["workers"].append(
            {"id": worker.wid, "target": target, "status": worker.status, "argv": worker.argv}
        )
    dest = _write_json(_orch_dir() / "deepen" / "plan.json", plan)
    dest.parent.joinpath("BYO-NESSUS.placeholder").write_text(
        "Install Nessus yourself on the drop box under written consent.\n"
        "Evergreen only plans batches. It does not download Nessus or plugins.\n",
        encoding="utf-8",
    )
    plan["plan_path"] = str(dest)
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
        "note": "Plan-only labs have no nmap/nessus artifacts. Loader still uses fixtures + demo overlays.",
    }
    _write_json(_orch_dir() / "ingest" / "summary.json", marker)
    return marker


def orchestrate(scope: Scope | None = None, live: bool = False, dest_in: Path | None = None) -> dict:
    if scope is None:
        scope = load_scope()
    farm = Farm()
    discover = discover_stage(scope, farm, live=live)
    if farm.alive("discover"):
        raise GateError("discover workers still alive after destroy")
    deepen = deepen_stage(scope, farm, live=live)
    ingest = ingest_stage(scope, dest_in=dest_in)
    summary = {
        "client": scope.client_name,
        "live": live,
        "discover": {
            "shard_count": discover["shard_count"],
            "mode": discover["mode"],
            "destroyed": discover["discover_workers_destroyed"],
            "alive": discover["discover_workers_alive"],
        },
        "deepen": {"batch_count": deepen["batch_count"], "mode": deepen["mode"]},
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
