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
from farm.adapters.catalog import plan_stage_slots, refuse_live_slot, select_stage_slots
from shared.io_util import in_dir

STAGE_GRAPH = (
    "plan → shard → discover (quiet) → destroy → "
    "deepen (loud, gated) → destroy → external (plan-only) → "
    "ingest (parse-only) → grc_export"
)
EXTERNAL_PLAN_REASON = (
    "file_drop or plan-only — operator lands artifacts in in/easm|…"
)

_SENSOR_COPY = (
    ("discover", "nmap", {".gnmap", ".xml", ".nmap"}),
    ("deepen", "vuln", {".nessus", ".xml", ".json", ".txt"}),
    ("external", "easm", {".jsonl", ".json", ".txt"}),
    ("endpoint", "wazuh", {".json", ".txt"}),
    ("cloud", "cloud", {".json"}),
    ("identity", "identity", {".json", ".xml", ".csv"}),
)


def _which(name: str) -> str | None:
    return shutil.which(name)


def _orch_dir() -> Path:
    raw = os.environ.get("DROPBOX_ORCH_DIR")
    return Path(raw) if raw else ROOT / "dropbox" / "out"


def _write_json(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def _choose_live_adapter(
    slot_plan: dict,
    target: str,
    timeout: int,
    allow_tools: list[str],
    which,
) -> tuple[str, str | None, list[str], str]:
    """First ready invoke slot whose argv is legal for target. Never LICENSE-LOCK."""
    from farm.adapters.stubs import argv_for

    last = "no invoke slot allowlisted and on PATH"
    for row in slot_plan.get("selected") or []:
        name = str(row.get("slot") or "")
        binary = str(row.get("binary") or name)
        refuse = refuse_live_slot(name, binary)
        if refuse:
            row["will_run"] = False
            row["reason"] = refuse
            last = refuse
            continue
        if not row.get("will_run"):
            last = str(row.get("reason") or last)
            continue
        exe, reason = byo.which_allowed(binary, allow_tools, which=which)
        if not exe:
            row["will_run"] = False
            row["on_path"] = False
            row["state"] = "missing"
            row["reason"] = reason
            last = reason
            continue
        try:
            argv = argv_for(name, exe, target, timeout)
        except GateError as exc:
            row["will_run"] = False
            row["reason"] = str(exc)
            last = str(exc)
            continue
        slot_plan["primary"] = name
        slot_plan["ready"] = [r["slot"] for r in slot_plan.get("selected") or [] if r.get("will_run")]
        return name, exe, argv, ""
    slot_plan["primary"] = ""
    slot_plan["ready"] = [r["slot"] for r in slot_plan.get("selected") or [] if r.get("will_run")]
    return "", None, [], last


def discover_stage(scope: Scope, farm: Farm, live: bool = False) -> dict:
    prefix = scope.discover_prefix
    shards = shard_cidrs(scope.internal_cidrs, prefix) if scope.internal_cidrs else []
    for shard in shards:
        if is_open_internet_cidr(shard):
            raise GateError(f"discover refuses open-internet shard {shard}")
    stage_allow = list(scope.allow_tools)
    slot_plan = select_stage_slots("discover", stage_allow, which=_which)
    sample = shards[:8]
    probe = sample[0] if sample else (scope.internal_hosts[0] if scope.internal_hosts else ".")
    primary, exe, _probe_argv, pick_reason = _choose_live_adapter(
        slot_plan, probe, scope.host_timeout_sec, stage_allow, _which
    )
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
        "tool": primary or "nmap",
        "tool_ready": bool(exe),
        "skip_reason": pick_reason if not exe else "",
        "slots": slot_plan,
        "note": "Quiet inventory. Farm discover invoke ∩ allow_tools ∩ PATH. No file_drop / LICENSE-LOCK.",
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
            argv: list[str] = []
            if use_live and exe and primary:
                try:
                    from farm.adapters.stubs import argv_for

                    argv = argv_for(primary, exe, shard, scope.host_timeout_sec)
                except GateError as exc:
                    use_live = False
                    plan["skip_reason"] = plan["skip_reason"] or str(exc)
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
                    "slot": primary if worker.argv else "",
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
        "slots": select_stage_slots("deepen", list(scope.allow_tools), which=_which),
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
    stage_allow = list(scope.allow_tools)
    slot_plan = select_stage_slots("deepen", stage_allow, which=_which)
    probe = hosts[0] if hosts else "."
    primary, exe, _probe_argv, pick_reason = _choose_live_adapter(
        slot_plan, probe, scope.host_timeout_sec, stage_allow, _which
    )
    plan["slots"] = slot_plan
    plan["tool"] = primary or "nessus"
    plan["tool_ready"] = bool(exe)
    plan["skip_reason"] = pick_reason if not exe else ""
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
            argv: list[str] = []
            if run_live and exe and primary and live_left > 0:
                try:
                    from farm.adapters.stubs import argv_for

                    argv = argv_for(primary, exe, target, scope.host_timeout_sec)
                except GateError as exc:
                    plan["skip_reason"] = plan["skip_reason"] or str(exc)
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
                    "slot": primary if worker.argv else "",
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


def _easm_fixture_present(dest_in: Path | None = None) -> bool:
    folder = (dest_in or in_dir()) / "easm"
    if not folder.is_dir():
        return False
    return any(path.is_file() and path.name != ".gitkeep" for path in folder.iterdir())


def plan_only_external_slots(
    allow_tools: list[str] | None = None,
    which=None,
    dest_in: Path | None = None,
) -> dict:
    """All external-category slots stay will_run=false. Never live-probe."""
    plan = select_stage_slots("external", allow_tools, which=which)
    fixture = _easm_fixture_present(dest_in)
    reason = EXTERNAL_PLAN_REASON
    if fixture:
        reason = f"{EXTERNAL_PLAN_REASON} (fixture already present)"
    for row in list(plan.get("selected") or []) + list(plan.get("skipped") or []):
        row["will_run"] = False
        if "LICENSE-LOCK" not in str(row.get("reason") or ""):
            row["reason"] = reason
    plan["ready"] = []
    plan["primary"] = ""
    plan["mode"] = "plan"
    plan["fixture_present"] = fixture
    return plan


def external_stage(
    scope: Scope,
    dest_in: Path | None = None,
    live: bool = False,
) -> dict:
    """Named-host plan only. Never curl/testssl the internet from this stage."""
    del live  # this slice never live-probes, even if orchestrate --live
    targets = list(dict.fromkeys(list(scope.external_hosts) + list(scope.external_ips)))
    slot_plan = plan_only_external_slots(scope.allow_tools, which=_which, dest_in=dest_in)
    plan = {
        "stage": "external",
        "volume": "named-only",
        "mode": "plan",
        "live": False,
        "plan_only": True,
        "client": scope.client_name,
        "targets": targets,
        "domains": list(scope.external_domains),
        "tool_ready": False,
        "skip_reason": EXTERNAL_PLAN_REASON,
        "slots": slot_plan,
        "note": (
            "Orchestrator external is plan-only. Operator lands files in in/easm/ "
            "(or make dropbox-external DEMO fixtures). Live BYO curl/testssl is "
            "operator-local under written SCOPE — not this stage."
        ),
        "workers": [],
    }
    dest = _write_json(_orch_dir() / "external" / "plan.json", plan)
    plan["plan_path"] = str(dest)
    return plan


def ingest_stage(scope: Scope, dest_in: Path | None = None) -> dict:
    """Copy/normalize orchestrator artifacts into pack in/<sensor>/."""
    dest = dest_in or in_dir()
    copied: list[str] = []
    for stage_name, sensor, suffixes in _SENSOR_COPY:
        src_dir = _orch_dir() / stage_name
        sensor_dir = dest / sensor
        sensor_dir.mkdir(parents=True, exist_ok=True)
        if not src_dir.is_dir():
            continue
        for path in src_dir.iterdir():
            if path.name in {"plan.json", "summary.json"}:
                continue
            if path.suffix.lower() in suffixes and path.is_file():
                target = sensor_dir / f"dropbox-{stage_name}-{path.name}"
                shutil.copy2(path, target)
                copied.append(str(target))
    marker = {
        "client": scope.client_name,
        "copied": copied,
        "sink": "Layer C parse-only via in/",
        "note": (
            "Plan-only labs have no nmap/nessus artifacts. "
            "Loader still uses fixtures + demo overlays. "
            "Deliverable after ingest: CISO CSVs + out/poam/poam.csv."
        ),
    }
    _write_json(_orch_dir() / "ingest" / "summary.json", marker)
    return marker


def grc_export_stage(scope: Scope, dest_in: Path | None = None) -> dict:
    """Point at Layer C CISO/POA&M rails. Does not scan. Does not POST."""
    return {
        "stage": "grc_export",
        "sink": "Layer C parse-only",
        "in_dir": str(dest_in or in_dir()),
        "ciso": "out/ciso-assistant/",
        "poam": "out/poam/poam.csv",
        "owner_due": "blank — human fills",
        "posted": False,
        "note": "Collectors + loader emit CISO/POA&M from in/. Orchestrator does not scan.",
    }


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
    external = external_stage(scope, dest_in=dest_in, live=False)
    ingest = ingest_stage(scope, dest_in=dest_in)
    grc_export = grc_export_stage(scope, dest_in=dest_in)
    summary = {
        "client": scope.client_name,
        "live": live,
        "governor": "quiet→loud",
        "stage_graph": STAGE_GRAPH,
        "brakes": {
            "max_workers": scope.max_workers,
            "batch_size": scope.deepen_batch,
            "host_timeout_sec": scope.host_timeout_sec,
            "stage_discover": scope.stage_discover,
            "stage_deepen": scope.stage_deepen,
            "stage_external": False,
        },
        "discover": {
            "shard_count": discover["shard_count"],
            "mode": discover["mode"],
            "volume": discover["volume"],
            "destroyed": discover["discover_workers_destroyed"],
            "alive": discover["discover_workers_alive"],
            "skip_reason": discover.get("skip_reason") or "",
            "slots": discover.get("slots") or {},
            "tool": discover.get("tool") or "",
        },
        "deepen": {
            "batch_count": deepen["batch_count"],
            "mode": deepen["mode"],
            "volume": deepen["volume"],
            "destroyed": deepen.get("deepen_workers_destroyed", 0),
            "skip_reason": deepen.get("skip_reason") or "",
            "host_source": deepen.get("host_source") or "",
            "slots": deepen.get("slots") or {},
            "tool": deepen.get("tool") or "",
        },
        "external": {
            "mode": external["mode"],
            "volume": external["volume"],
            "plan_only": True,
            "live": False,
            "skip_reason": external.get("skip_reason") or "",
            "slots": external.get("slots") or {},
            "targets": external.get("targets") or [],
        },
        "slots": {
            **plan_stage_slots(scope.allow_tools, which=_which),
            "external": external.get("slots") or plan_only_external_slots(
                scope.allow_tools, which=_which, dest_in=dest_in
            ),
        },
        "ingest": ingest,
        "grc_export": grc_export,
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
        "farm is private; binaries not vendored (not a public Hub image)",
        "allow_tools ∩ PATH ∩ SLOTS",
        "external stage plan-only (no live network probe)",
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
