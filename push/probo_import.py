"""Probo findings plan. No createRisk storm. Dual-gate live; no default LAN URL."""
from __future__ import annotations

import json
import os
from typing import Any

from push.common import PACK, refuse_live_without_gate, split_canonical

DEST = PACK / "out" / "probo"
BATCH = 25


def write_files() -> dict[str, Any]:
    _assets, findings = split_canonical()
    DEST.mkdir(parents=True, exist_ok=True)
    items = []
    for rec in findings:
        items.append(
            {
                "operation": "addFinding",
                "title": str(rec.get("name") or rec.get("ref_id") or "")[:200],
                "severity": rec.get("severity") or "medium",
                "description": str(rec.get("description") or "")[:500],
                "assets": rec.get("related_assets") or [],
                "ref_id": rec.get("ref_id"),
            }
        )
    batches = [items[i : i + BATCH] for i in range(0, len(items), BATCH)] or [[]]
    payload = {
        "kind": "probo-finding-plan",
        "note": "dry-run GraphQL/REST plan. No createRisk. Batch size 25. Dual-gate live.",
        "batch_size": BATCH,
        "batches": len(batches),
        "count": len(items),
        "items": items,
    }
    path = DEST / "findings_plan.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"plan_json": str(path), "count": len(items), "batches": len(batches)}


def plan() -> dict[str, Any]:
    written = write_files()
    url = (os.environ.get("PROBO_URL") or "").rstrip("/")
    return {
        "target": "probo",
        "dry_run": True,
        "endpoint": (url + "/graphql") if url else "(set PROBO_URL — never default office LAN)",
        "method": "GraphQL addFinding batches of 25 (no createRisk)",
        "http": False,
        "files": written,
        "note": "No Probo on this Windows lab. Do not boot pve. Dual-gate --live.",
    }


def live() -> dict[str, Any]:
    refuse_live_without_gate("probo")
    url = (os.environ.get("PROBO_URL") or "").strip()
    token = (os.environ.get("PROBO_TOKEN") or "").strip()
    if not url or not token:
        raise SystemExit(2)
    if "192.168.10.130" in url:
        raise SystemExit(2)
    rec = plan()
    rec["dry_run"] = False
    rec["http"] = False
    rec["live_skipped"] = "no_probo_on_this_lab_no_createrisk"
    return rec
