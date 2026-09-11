"""Lock global pack_drop service→host address referential integrity.

Parametrized over the shared sixteen E2E_PROVEN set so fixtures/pack_drop/
cannot drift from prove_ciso / honesty inventory locks. No 17th adapter.

Every kind:service row's address (or ip) in
fixtures/pack_drop/<adapter>/assets.jsonl must match a same-file
kind:host address OR a kind:asset ip/hostname/name. Host-only
adapters invent zero service rows. nmap asset+ports-only is OK
with zero kind:service rows (nested ports on the asset do not
require service kinds). Port/service adapters that emit service
rows must satisfy the address lock. SAMPLE/DEMO ≠ client stays true.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.prove_ciso import E2E_PROVEN_PACK_DROP_ADAPTERS
from tests.test_status_honesty import COVEY_E2E_PROVEN, COVEY_E2E_UNPROVEN

ROOT = Path(__file__).resolve().parents[1]
PACK_DROP = ROOT / "fixtures" / "pack_drop"

HOST_ONLY = frozenset(
    {"hping3", "fping", "onesixtyone", "braa", "nbtscan", "ike-scan"}
)
NMAP_ASSET_PORTS = frozenset({"nmap"})
SERVICE_EMITTERS = frozenset(
    {
        "rustscan",
        "naabu",
        "nping",
        "httpx",
        "sslscan",
        "tlsx",
        "whatweb",
        "unicornscan",
        "svmap",
    }
)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        row = json.loads(text)
        assert isinstance(row, dict), f"{path} JSONL row must be an object"
        rows.append(row)
    return rows


def _extra(row: dict[str, Any]) -> dict[str, Any]:
    extra = row.get("extra") or {}
    return extra if isinstance(extra, dict) else {}


def _kind(row: dict[str, Any]) -> str:
    return str(row.get("kind") or "").strip().lower()


def _norm(val: Any) -> str:
    if val in (None, ""):
        return ""
    if isinstance(val, (dict, list)):
        return ""
    return str(val).strip()


def _add_key(keys: set[str], val: Any) -> None:
    text = _norm(val)
    if text:
        keys.add(text)


def _field(row: dict[str, Any], name: str) -> str:
    extra = _extra(row)
    text = _norm(row.get(name))
    if text:
        return text
    return _norm(extra.get(name))


def _service_addr(row: dict[str, Any]) -> str:
    """Service identity is address, else ip (top-level then extra)."""
    return _field(row, "address") or _field(row, "ip")


def _host_addrs(row: dict[str, Any]) -> set[str]:
    """kind:host join keys — address (ip accepted as the same locator)."""
    keys: set[str] = set()
    extra = _extra(row)
    for bag in (row, extra):
        _add_key(keys, bag.get("address"))
        _add_key(keys, bag.get("ip"))
    return keys


def _asset_keys(row: dict[str, Any]) -> set[str]:
    """kind:asset join keys — ip / hostname / name."""
    keys: set[str] = set()
    extra = _extra(row)
    for bag in (row, extra):
        for field in ("ip", "hostname", "name"):
            _add_key(keys, bag.get(field))
    return keys


def test_service_host_ref_set_matches_e2e_proven_sixteen() -> None:
    assert frozenset(E2E_PROVEN_PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert E2E_PROVEN_PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(
        E2E_PROVEN_PACK_DROP_ADAPTERS
    ) == tuple(COVEY_E2E_PROVEN)
    assert len(E2E_PROVEN_PACK_DROP_ADAPTERS) == 16
    assert len(set(E2E_PROVEN_PACK_DROP_ADAPTERS)) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in E2E_PROVEN_PACK_DROP_ADAPTERS


def test_unproven_adapters_absent_from_pack_drop_service_host_refs() -> None:
    names = {path.name for path in PACK_DROP.iterdir() if path.is_dir()}
    for name in COVEY_E2E_UNPROVEN:
        assert name not in names, f"UNPROVEN {name} must not be a pack_drop fixture dir"
    assert names == set(E2E_PROVEN_PACK_DROP_ADAPTERS)
    assert names == set(COVEY_E2E_PROVEN)
    assert len(names) == 16


def test_service_host_class_partition_matches_e2e_proven_sixteen() -> None:
    parts = (HOST_ONLY, NMAP_ASSET_PORTS, SERVICE_EMITTERS)
    union: set[str] = set()
    for group in parts:
        overlap = union & group
        assert not overlap, f"service-host-class overlap: {sorted(overlap)}"
        union |= set(group)
    assert union == set(E2E_PROVEN_PACK_DROP_ADAPTERS)
    assert union == set(COVEY_E2E_PROVEN)
    assert len(union) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in union


@pytest.mark.parametrize(
    "adapter",
    list(E2E_PROVEN_PACK_DROP_ADAPTERS),
    ids=list(E2E_PROVEN_PACK_DROP_ADAPTERS),
)
def test_pack_drop_service_host_address_refs(adapter: str) -> None:
    dest = PACK_DROP / adapter
    assert dest.is_dir(), f"missing fixtures/pack_drop/{adapter}/"

    assets_path = dest / "assets.jsonl"
    assert assets_path.is_file(), f"missing fixtures/pack_drop/{adapter}/assets.jsonl"

    asset_rows = _load_jsonl(assets_path)
    assert asset_rows, f"{adapter}/assets.jsonl must have at least one JSONL object"

    hosts = [
        (idx, row) for idx, row in enumerate(asset_rows, start=1) if _kind(row) == "host"
    ]
    assets = [
        (idx, row) for idx, row in enumerate(asset_rows, start=1) if _kind(row) == "asset"
    ]
    services = [
        (idx, row)
        for idx, row in enumerate(asset_rows, start=1)
        if _kind(row) == "service"
    ]

    host_keys: set[str] = set()
    for _, row in hosts:
        host_keys |= _host_addrs(row)
    asset_keys: set[str] = set()
    for _, row in assets:
        asset_keys |= _asset_keys(row)
    known = host_keys | asset_keys

    if adapter in HOST_ONLY:
        assert not services, (
            f"{adapter} is host-only and must invent no kind:service rows: "
            f"{[row.get('id') for _, row in services]}"
        )
        assert hosts, f"{adapter} host-only has no kind:host rows"
        return

    if adapter in NMAP_ASSET_PORTS:
        # Nested ports on the asset do not require kind:service rows.
        if not services:
            assert assets, f"{adapter} asset+ports-only has no kind:asset rows"
            return

    if adapter in SERVICE_EMITTERS:
        assert services, (
            f"{adapter} emits port/service rows and must have at least one "
            f"kind:service in assets.jsonl"
        )

    assert known, (
        f"{adapter} has kind:service rows but no same-file host address "
        f"or asset ip/hostname/name to resolve against"
    )

    for idx, row in services:
        loc = f"{adapter}/assets.jsonl:{idx}"
        addr = _service_addr(row)
        assert addr, (
            f"{loc} kind:service has no address or ip to resolve against a "
            f"same-file host|asset: {row}"
        )
        assert addr in known, (
            f"{loc} kind:service address {addr!r} does not match a same-file "
            f"kind:host address or kind:asset ip/hostname/name "
            f"(known {sorted(known)}): {row}"
        )
