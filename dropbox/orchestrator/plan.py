"""Shard plan from SCOPE. No live scan. Never expand a /16 into one deepen worker."""
from __future__ import annotations

import ipaddress
from typing import Any

from dropbox.orchestrator.scope import MAX_DEEPEN_BATCH_SIZE, Scope


# Do not materialize a /16 into RAM. Live exec still refuses a prefix this large on one argv.
MAX_MATERIALIZE_ADDRS = 8192
# Planning budget cannot be gamed with timeouts_seconds: 1.
MIN_WAVE_SECONDS = 30


def _cidr_host_capacity(cidr: str) -> int:
    net = ipaddress.ip_network(cidr, strict=False)
    # include network/broadcast in planning capacity so shards cover the prefix
    return int(net.num_addresses)


def cidr_ip_shards(cidr: str, shard_size: int) -> list[list[str]]:
    """Slice a prefix into host lists. Never hand the whole /16 to one worker."""
    size = max(1, int(shard_size))
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return [[cidr]] if cidr else []
    n = int(net.num_addresses)
    if n > MAX_MATERIALIZE_ADDRS:
        n_shards = max(1, (n + size - 1) // size)
        return [[cidr] for _ in range(n_shards)]
    shards: list[list[str]] = []
    batch: list[str] = []
    for ip in net:
        batch.append(str(ip))
        if len(batch) >= size:
            shards.append(batch)
            batch = []
    if batch:
        shards.append(batch)
    return shards or ([[cidr]] if cidr else [])


def shard_named(items: list[str], size: int) -> list[list[str]]:
    size = max(1, int(size))
    return [items[i : i + size] for i in range(0, len(items), size)]


def deepen_batches(live_hosts: list[str], batch_size: int) -> list[list[str]]:
    """Tiny batches so Nessus-class tools do not melt a /16."""
    size = max(1, min(int(batch_size), MAX_DEEPEN_BATCH_SIZE)) if batch_size else 3
    # still honor explicit 2–5 default window; allow 1
    if batch_size and int(batch_size) < 1:
        size = 1
    return shard_named(live_hosts, size)


def concurrent_waves(items: list[Any], cap: int) -> list[list[Any]]:
    """Never run more than max_concurrent workers at once."""
    size = max(1, int(cap) or 1)
    if not items:
        return []
    return [items[i : i + size] for i in range(0, len(items), size)]


def discover_unit_count(scope: Scope) -> int:
    size = max(1, scope.batch.discover_shard_size)
    units = 0
    for cidr in scope.discover_cidrs():
        capacity = _cidr_host_capacity(cidr)
        units += max(1, (capacity + size - 1) // size)
    hosts = scope.discover_hosts()
    if hosts:
        units += max(1, (len(hosts) + size - 1) // size)
    return units


def estimated_discover_seconds(scope: Scope) -> int:
    units = discover_unit_count(scope)
    if units <= 0:
        return 0
    waves = len(concurrent_waves(list(range(units)), scope.batch.max_concurrent_discover))
    per_wave = max(MIN_WAVE_SECONDS, max(1, int(scope.integrity.timeouts_seconds or 1)))
    return waves * per_wave


def runtime_over_budget(scope: Scope) -> str | None:
    """Refuse live for /16-class prefixes and when shard waves would exceed max_runtime.
    timeouts_seconds: 1 cannot make a huge prefix look cheap."""
    for cidr in scope.discover_cidrs():
        try:
            if _cidr_host_capacity(cidr) > MAX_MATERIALIZE_ADDRS:
                return "prefix_too_large"
        except ValueError:
            continue
    est = estimated_discover_seconds(scope)
    ceiling = max(1, scope.integrity.max_runtime_seconds)
    if est > ceiling:
        return "runtime_over_budget"
    return None


def build_plan(scope: Scope) -> dict[str, Any]:
    size = max(1, scope.batch.discover_shard_size)
    cidr_shards: list[dict[str, Any]] = []
    for cidr in scope.discover_cidrs():
        capacity = _cidr_host_capacity(cidr)
        n_shards = max(1, (capacity + size - 1) // size)
        cidr_shards.append(
            {
                "cidr": cidr,
                "capacity": capacity,
                "shard_size": size,
                "shard_count": n_shards,
                "note": "one discover worker per shard; never one worker for the whole prefix",
            }
        )
        if capacity > 4096:
            cidr_shards[-1]["brake"] = "prefix larger than /20-class; integrity prefers tighter SCOPE"
    host_shards = shard_named(scope.discover_hosts(), size)
    refuse = scope.refuse_live() or runtime_over_budget(scope)
    cidr_workers = sum(int(block["shard_count"]) for block in cidr_shards)
    host_workers = len(host_shards)
    discover_units = cidr_workers + host_workers
    est_seconds = estimated_discover_seconds(scope)
    return {
        "client": scope.client_legal_name,
        "signed": scope.signed,
        "consent_attested": scope.consent_attested,
        "profiles": scope.profiles,
        "allow_tools": scope.allow_tools,
        "usable_tools": scope.usable_tools(),
        "tool_gates": scope.tool_gates(),
        "stages": [
            "plan",
            "shard",
            "discover",
            "destroy_discover_workers",
            "deepen",
            "destroy_deepen_workers",
            "ingest",
            "grc_export",
        ],
        "brakes": {
            "discover_shard_size": scope.batch.discover_shard_size,
            "deepen_batch_size": scope.batch.deepen_batch_size,
            "max_concurrent_discover": scope.batch.max_concurrent_discover,
            "max_concurrent_deepen": scope.batch.max_concurrent_deepen,
            "timeouts_seconds": scope.integrity.timeouts_seconds,
            "max_runtime_seconds": scope.integrity.max_runtime_seconds,
            "estimated_discover_seconds": est_seconds,
            "runtime_over_budget": runtime_over_budget(scope),
            "allow_live_exec": scope.integrity.allow_live_exec,
            "refuse_live": refuse,
            "window_start": scope.window_start,
            "window_end": scope.window_end,
            "window": scope.window_reason(),
        },
        "profile_isolation": {
            "uses_internal": scope.uses_internal(),
            "uses_external": scope.uses_external(),
            "note": "external never uses internal CIDRs; internal never sprays public internet",
        },
        "discover_cidr_shards": cidr_shards,
        "discover_host_shards": host_shards,
        "discover_worker_count": discover_units,
        "discover_waves": len(
            concurrent_waves(list(range(max(discover_units, 0))), scope.batch.max_concurrent_discover)
        )
        if discover_units
        else 0,
        "deepen_batch_size": scope.batch.deepen_batch_size,
        "external": {
            "hostnames": list(scope.external_hostnames) if scope.uses_external() else [],
            "urls": list(scope.external_urls) if scope.uses_external() else [],
            "note": "external profile never uses internal CIDRs",
        },
        "label": "plan-only" if refuse else "live-eligible",
    }
