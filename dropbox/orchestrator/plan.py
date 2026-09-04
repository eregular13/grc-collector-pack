from __future__ import annotations

from typing import Any

from dropbox.orchestrator.scope import Scope

STAGES = [
    "plan",
    "shard",
    "discover",
    "destroy_discover_workers",
    "deepen",
    "destroy_deepen_workers",
    "ingest",
    "grc_export",
]


def shard_targets(scope: Scope) -> list[list[str]]:
    size = max(1, scope.batch.discover_shard_size)
    targets = scope.targets()
    return [targets[i : i + size] for i in range(0, len(targets), size)] or []


def deepen_batches(live_hosts: list[str], scope: Scope) -> list[list[str]]:
    size = min(5, max(2, scope.batch.deepen_batch_size))
    return [live_hosts[i : i + size] for i in range(0, len(live_hosts), size)]


def build_plan(scope: Scope, live_hosts: list[str] | None = None) -> dict[str, Any]:
    shards = shard_targets(scope)
    live = live_hosts if live_hosts is not None else []
    deepen = deepen_batches(live, scope) if live else []
    ok, reason = scope.live_ok()
    return {
        "client": scope.client_legal_name,
        "profiles": scope.profiles,
        "consent_attested": scope.consent_attested,
        "signed": scope.signed,
        "live_ok": ok,
        "live_reason": reason,
        "stages": STAGES,
        "allow_tools": scope.allow_tools,
        "shards": shards,
        "shard_count": len(shards),
        "discover_shard_size": scope.batch.discover_shard_size,
        "deepen_batch_size": min(5, max(2, scope.batch.deepen_batch_size)),
        "deepen_batches": deepen,
        "max_concurrent_discover": scope.batch.max_concurrent_discover,
        "max_concurrent_deepen": scope.batch.max_concurrent_deepen,
        "fixture_label": True,
        "note": "Plan only. No live scan in this print. Empty in/ remains demo fixtures, not a client estate.",
    }
