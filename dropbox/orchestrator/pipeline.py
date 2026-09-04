"""discover (quiet) → deepen (loud, gated) → ingest. Plan-only unless BYO on PATH."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from dropbox.orchestrator import byo
from dropbox.orchestrator.farm import Farm
from dropbox.orchestrator.shard import batch_hosts, reject_wide_deepen_target, shard_cidrs
from dropbox.scope import NEVER_EMBED, ORCH_BYO, ROOT, GateError, Scope, is_open_internet_cidr, load_scope
from shared.io_util import in_dir


def _which(name: str) -> str | None:
    return shutil.which(name)


def _orch_dir() -> Path:
    raw = os.environ.get("DROPBOX_ORCH_DIR")
    return Path(raw) if raw else ROOT / "dropbox" / "out"


def _write_json(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def discover_stage(scope: Scope, farm: Farm, live: bool = False) -> dict:
    prefix = scope.discover_prefix
    shards = shard_cidrs(scope.internal_cidrs, prefix) if scope.internal_cidrs else []
    for shard in shards:
        if is_open_internet_cidr(shard):
            raise GateError(f"discover refuses open-internet shard {shard}")
    stage_allow = scope.tools_for("discover")
    exe, reason, _tool = byo.resolve_stage("discover", stage_allow, which=_which)
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
    if run_live and len(shards) > scope.max_workers:
        plan["skip_reason"] = "batch overflow (max_workers cap)"
    try:
        for index, shard in enumerate(shards[: max(live_budget, min(8, len(shards)))]):
            use_live = bool(run_live and exe and index < live_budget)
            argv = byo.nmap_quiet_argv(exe, shard, scope.host_timeout_sec) if use_live else []
            worker = farm.spawn(
                "discover",
                shard,
                argv=argv,
                note="quiet shard job",
                timeout_sec=scope.host_timeout_sec,
            )
            if "max_workers cap" in worker.note:
                plan["skip_reason"] = plan["skip_reason"] or "batch overflow (max_workers cap)"
            if use_live and worker.argv:
                dest_out = _orch_dir() / "discover" / f"{worker.wid}.gnmap"
                try:
                    rc = byo.run_allowed(
                        worker.argv,
                        dest_out,
                        scope.host_timeout_sec,
                        allow_tools=stage_allow,
                    )
                    worker.status = "ran" if rc == 0 else "failed"
                    plan["mode"] = "live"
                    if worker.status == "failed" and not plan["skip_reason"]:
                        plan["skip_reason"] = "worker failed"
                except (OSError, TimeoutError, GateError) as exc:
                    worker.status = "failed"
                    plan["skip_reason"] = classify_stop(exc)
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
    finally:
        destroyed = farm.destroy_stage("discover")
        plan["discover_workers_destroyed"] = destroyed
        plan["discover_workers_alive"] = len(farm.alive("discover"))
        dest = _write_json(_orch_dir() / "discover" / "plan.json", plan)
        plan["plan_path"] = str(dest)
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
        if candidates:
            return [], "scope miss (target not in SCOPE)"
        return [], "no discover hosts and no orchestrator.deepen_hosts"
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
    exe, reason, _tool = byo.resolve_stage("deepen", stage_allow, which=_which)
    plan["tool_ready"] = bool(exe)
    plan["skip_reason"] = reason if not exe else ""
    run_live = bool(live and exe)
    live_left = scope.max_workers if run_live else 0
    if run_live and len(batches) > scope.max_workers:
        plan["skip_reason"] = "batch overflow (max_workers cap)"
    try:
        for batch in batches:
            target = ",".join(batch)
            for item in batch:
                try:
                    reject_wide_deepen_target(item)
                except ValueError as exc:
                    raise GateError(str(exc)) from exc
                if not scope.allows_internal_target(item):
                    raise GateError(f"scope miss (target not in SCOPE): {item}")
            argv = byo.nessus_batch_argv(exe, target, scope.host_timeout_sec) if run_live and exe else []
            worker = farm.spawn(
                "deepen",
                target,
                argv=argv,
                note="deepen batch",
                timeout_sec=scope.host_timeout_sec,
            )
            if "max_workers cap" in worker.note:
                plan["skip_reason"] = plan["skip_reason"] or "batch overflow (max_workers cap)"
            if run_live and exe and worker.argv and live_left > 0:
                dest_out = _orch_dir() / "deepen" / f"{worker.wid}.txt"
                try:
                    rc = byo.run_allowed(
                        worker.argv,
                        dest_out,
                        scope.host_timeout_sec,
                        allow_tools=stage_allow,
                    )
                    worker.status = "ran" if rc == 0 else "failed"
                    plan["mode"] = "live"
                    live_left -= 1
                    if worker.status == "failed" and not plan["skip_reason"]:
                        plan["skip_reason"] = "worker failed"
                except (OSError, TimeoutError, GateError) as exc:
                    worker.status = "failed"
                    plan["skip_reason"] = classify_stop(exc)
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
    finally:
        destroyed = farm.destroy_stage("deepen")
        plan["deepen_workers_destroyed"] = destroyed
        plan["deepen_workers_alive"] = len(farm.alive("deepen"))
        plan["plan_path"] = str(_write_json(dest, plan))
    return plan


def collect_discover_hosts(discover_dir: Path | None = None) -> list[str]:
    """Parse discover *.gnmap Host lines. Up hosts only. No CIDR fallback."""
    folder = discover_dir or (_orch_dir() / "discover")
    hosts: list[str] = []
    if not folder.is_dir():
        return hosts
    for path in sorted(folder.glob("*.gnmap")):
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in raw.splitlines():
            if not line.startswith("Host:"):
                continue
            if "Status: Down" in line:
                continue
            rest = line[len("Host:") :].strip()
            addr = rest.split()[0] if rest.split() else ""
            hostname = ""
            if "(" in rest:
                hostname = rest.split("(", 1)[1].split(")", 1)[0].strip()
            name = hostname or addr
            if name and name not in hosts:
                hosts.append(name)
    return hosts


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
    live_hosts = collect_discover_hosts(_orch_dir() / "discover") if live else None
    deepen = deepen_stage(scope, farm, live=live, live_hosts=live_hosts)
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
            "skip_reason": discover.get("skip_reason") or "",
        },
        "deepen": {
            "batch_count": deepen["batch_count"],
            "mode": deepen["mode"],
            "volume": deepen["volume"],
            "destroyed": deepen.get("deepen_workers_destroyed", 0),
            "skip_reason": deepen.get("skip_reason") or "",
            "host_source": deepen.get("host_source") or "",
        },
        "ingest": ingest,
        "integrity_stops": integrity_stops(scope),
        "last_integrity_stop": (discover.get("skip_reason") or deepen.get("skip_reason") or ""),
        "path_matrix": byo.tool_matrix(scope.allow_tools),
    }
    _write_json(_orch_dir() / "summary.json", summary)
    return summary


def classify_stop(exc: BaseException | str) -> str:
    text = str(exc).lower()
    if "timeout" in text:
        return "timeout (host_timeout_sec)"
    if "max_workers" in text or "overflow" in text:
        return "batch overflow (max_workers cap)"
    if "not in scope" in text or "scope miss" in text:
        return "scope miss (target not in SCOPE)"
    return str(exc)[:240]


def integrity_stops(scope: Scope) -> list[str]:
    stops = [
        "SCOPE required",
        f"max_workers={scope.max_workers}",
        f"deepen_batch={scope.deepen_batch} (enforced 2-5)",
        f"host_timeout_sec={scope.host_timeout_sec}",
        "tear-down after discover and deepen",
        "timeout (host_timeout_sec) → destroy workers",
        "batch overflow (max_workers cap)",
        "scope miss (target not in SCOPE)",
        "no targets outside SCOPE",
        "no 0.0.0.0/0",
        "BYO nmap/nessus on PATH only; never apt/embed/download",
    ]
    if not scope.stage_deepen:
        stops.append("stages.deepen=false (deepen fail-closed)")
    else:
        stops.append("stages.deepen=true (loud stage armed)")
    if "DEMO" in scope.client_name.upper():
        stops.append("DEMO SCOPE — not a client estate")
    return stops


def assert_no_embed() -> None:
    for name in NEVER_EMBED | ORCH_BYO:
        if name in {"curl"}:
            continue
        # presence on PATH is OK (BYO). Shipping in this repo is not.
        _ = name
