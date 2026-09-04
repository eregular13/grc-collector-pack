from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dropbox.orchestrator import workers
from dropbox.orchestrator.adapters import nessus_byo, nmap_byo, noop_discover
from dropbox.orchestrator.plan import STAGES, build_plan, deepen_batches
from dropbox.orchestrator.scope import Scope

ROOT = Path(__file__).resolve().parents[2]


def run_stages(
    scope: Scope,
    stage: str = "all",
    fixture: bool = True,
    out_dir: Path | None = None,
    run_pack: bool = False,
) -> dict[str, Any]:
    out_dir = out_dir or (ROOT / "dropbox" / "out")
    out_dir.mkdir(parents=True, exist_ok=True)
    wanted = STAGES if stage == "all" else [stage]
    plan = build_plan(scope)
    log: list[dict[str, Any]] = [{"stage": "plan", **plan}]
    live: list[str] = []

    if "shard" in wanted or stage == "all":
        log.append({"stage": "shard", "shards": plan["shards"]})

    live_ok, reason = scope.live_ok()
    live_requested = stage in {"discover", "deepen", "all"} and not fixture

    if live_requested and not live_ok:
        return {"ok": False, "refused": True, "reason": reason, "log": log}

    if "discover" in wanted or stage == "all":
        if fixture or not live_ok:
            result = noop_discover.run(scope.targets(), out_dir)
            live = list(result.get("live") or [])
            log.append({"stage": "discover", **result, "label": "fixture"})
        else:
            nmap = nmap_byo.run_discover(scope.targets(), out_dir, scope.allow_tools)
            log.append({"stage": "discover", **nmap})
            live = list(nmap.get("live") or [])
            if not nmap.get("ran"):
                stub = noop_discover.run(scope.targets(), out_dir)
                live = list(stub.get("live") or [])
                log.append({"stage": "discover_fallback", **stub, "label": "fixture"})
        log.append({"stage": "destroy_discover_workers", "token": workers.destroy_workers("discover")})

    if "deepen" in wanted or stage == "all":
        if not live:
            live = [t for t in scope.internal_hosts + scope.external_hostnames if t][:5]
        batches = deepen_batches(live, scope)
        for batch in batches:
            assert len(batch) <= 5
            nessus_byo.run_deepen(batch, out_dir, scope.allow_tools)
        deepen_path = out_dir / "deepen.json"
        deepen_path.write_text(
            json.dumps(
                {
                    "label": "fixture" if fixture or not live_ok else "byo",
                    "client_estate": False if fixture else True,
                    "batches": batches,
                    "batch_size": plan["deepen_batch_size"],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        log.append({"stage": "deepen", "batches": batches, "path": str(deepen_path)})
        log.append({"stage": "destroy_deepen_workers", "token": workers.destroy_workers("deepen")})

    if "ingest" in wanted or "grc_export" in wanted or stage == "all":
        manifest = {
            "label": "fixture" if fixture else "ingest",
            "client_estate": False if fixture else True,
            "copied_to_in": False,
            "note": "Pack ingest stays parse-only. Empty in/ uses demo fixtures, not a client estate.",
        }
        if run_pack:
            _run_pack_collectors()
            manifest["pack_ran"] = True
        (out_dir / "ingest-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        log.append({"stage": "ingest", **manifest})
        log.append({"stage": "grc_export", "ciso": "out/ciso-assistant", "poam": "out/poam"})

    (out_dir / "last-run.json").write_text(json.dumps({"ok": True, "log": log}, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "refused": False, "live": live, "log": log, "plan": plan}


def _run_pack_collectors() -> None:
    import collectors.cloud_prowler as a
    import collectors.code_secrets as b
    import collectors.easm as c
    import collectors.grc_loader as d
    import collectors.host_wazuh as e
    import collectors.identity_ad as f
    import collectors.inventory_nmap as g
    import collectors.k8s_kubescape as h
    import collectors.saas_idp as i
    import collectors.vuln_scan as j

    for mod in (a, g, j, e, f, c, h, b, i, d):
        mod.main()
