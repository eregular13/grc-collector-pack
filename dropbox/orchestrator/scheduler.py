"""One-shot KEEP-minimum scheduler. Not cron. Not continuous monitoring."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dropbox.mcp_stub import farm_toolbin_status_tool
from dropbox.orchestrator.ciso_path import run_ciso_path
from dropbox.orchestrator.keepmin import (
    KEEP_MINIMUM,
    VANITY_SCHEDULE,
    inventory_keepmin,
    refuse_vanity,
)
from dropbox.orchestrator.permissions import classify, may_ingest, may_invoke
from dropbox.scope import ROOT, GateError, load_scope
from keep.adapters import client_keep_ready, scan_keep_dir


def _dest_in(explicit: Path | None = None) -> Path:
    if explicit:
        return Path(explicit)
    raw = os.environ.get("IN_DIR") or os.environ.get("DROPBOX_WORK_IN")
    return Path(raw) if raw else ROOT / "in"


def _dest_out(explicit: Path | None = None) -> Path:
    if explicit:
        return Path(explicit)
    raw = os.environ.get("OUT_DIR")
    return Path(raw) if raw else ROOT / "dropbox" / "work" / "schedule-out"


def schedule(
    scope_path: Path | None = None,
    *,
    live: bool = False,
    dest_in: Path | None = None,
    dest_out: Path | None = None,
    extra: list[str] | None = None,
) -> dict[str, Any]:
    """discover (quiet from drops) → deepen (fail-closed) → ingest → SoR.

    --live is HITL. DEMO SCOPE and live_ready=0 refuse PATH invoke.
    File-drop is the default. Vanity names stay off the schedule.
    """
    scope = load_scope(scope_path)
    dest_in = _dest_in(dest_in)
    dest_out = _dest_out(dest_out)
    demo_scope = "DEMO" in scope.client_name.upper()
    toolbin = farm_toolbin_status_tool(scope_path=scope_path)
    live_ready_count = int(toolbin.get("live_ready_count") or 0)
    if live and demo_scope:
        raise GateError("HITL/--live refused on DEMO SCOPE (DEMO e2e ≠ client)")
    if live and live_ready_count <= 0:
        raise GateError("HITL/--live refused: live_ready fail-closed on stubs")

    rows = inventory_keepmin(dest_in)
    on_disk = {str(row.get("family") or "") for row in rows}
    on_disk |= {Path(str(row.get("name") or "")).stem.lower() for row in rows}

    wanted = list(KEEP_MINIMUM)
    refused: list[dict[str, str]] = []
    for name in extra or []:
        tool = str(name).strip().lower()
        if not tool:
            continue
        vanity = refuse_vanity(tool, file_on_disk=tool in on_disk)
        if vanity:
            refused.append({"slot": tool, "reason": vanity})
            continue
        if tool in VANITY_SCHEDULE and tool not in on_disk:
            refused.append({"slot": tool, "reason": f"KEEP-minimum only: refuse {tool}"})
            continue
        if tool not in wanted:
            wanted.append(tool)

    identity_in_scope = bool(
        scope.allow_tools
        and any(t in {str(x).lower() for x in scope.allow_tools} for t in ("maester",))
        or getattr(scope, "internal_hosts", None)
    )
    cloud_in_scope = any(
        str(t).lower() in {"prowler", "scoutsuite", "cloud"} for t in (scope.allow_tools or [])
    )

    planned: list[dict[str, Any]] = []
    for name in wanted:
        if name == "maester" and not identity_in_scope and name not in on_disk:
            refused.append({"slot": name, "reason": "Maester only if identity in SCOPE or file landed"})
            continue
        if name == "cloud" and not cloud_in_scope and name not in on_disk:
            # Still allow ingest if a cloud file already landed; otherwise skip schedule
            if name not in on_disk:
                refused.append({"slot": name, "reason": "cloud only if SCOPE cloud or file landed"})
                continue
        perm = classify(name)
        ingest = may_ingest(name, file_on_disk=name in on_disk)
        invoke = may_invoke(
            name, hitl=live, live_ready=live_ready_count > 0, demo_scope=demo_scope
        )
        planned.append(
            {
                "slot": name,
                "permission": perm,
                "ingest": ingest,
                "invoke": invoke,
                "will_run": False,
                "live_ready": False,
                "on_disk": name in on_disk,
            }
        )

    discover = {
        "stage": "discover",
        "volume": "quiet",
        "source": "file_drop",
        "live": False,
        "landed": [row.get("name") for row in rows],
        "note": "quiet inventory from drops only",
    }
    deepen = {
        "stage": "deepen",
        "volume": "loud",
        "armed": bool(scope.stage_deepen and live and live_ready_count > 0 and not demo_scope),
        "live": False,
        "will_run": False,
        "note": "loud deepen fail-closed without signed SCOPE + HITL + live_ready",
    }
    ingest = {
        "stage": "ingest",
        "parse_only": True,
        "sensors": sorted({str(row.get("sensor") or "") for row in rows if row.get("sensor")}),
    }
    sor = run_ciso_path(dest_in, dest_out, scope_path=scope_path)
    return {
        "ok": True,
        "tool": "schedule",
        "live": False,
        "plan_only": True,
        "scope_gated": True,
        "hitl": bool(live),
        "client": scope.client_name,
        "demo": demo_scope,
        "demo_e2e": "DEMO e2e ≠ client",
        "sample_keep": "SAMPLE/fixture KEEP ≠ client KEEP",
        "client_keep_real": "4/4" if client_keep_ready(scan_keep_dir(dest_in)) else "0/4",
        "keep_minimum": list(KEEP_MINIMUM),
        "file_drop_default": True,
        "live_ready_count": live_ready_count,
        "discover": discover,
        "deepen": deepen,
        "ingest": ingest,
        "sor": sor,
        "planned": planned,
        "refused": refused,
        "posted": False,
        "http": False,
        "wrap": "review-only",
        "hexstrike": "pattern-only",
        "pack_truth": "evergreen_assessment_mcp",
        "farm_mcp_pack_truth": False,
        "note": (
            "One-shot KEEP-minimum. Not cron. Vanity (nuclei/trivy/nessus) not "
            "scheduled unless the file already landed. PATH/live needs HITL."
        ),
    }
