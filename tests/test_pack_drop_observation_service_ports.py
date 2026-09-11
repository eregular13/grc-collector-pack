"""Lock global pack_drop observation/finding port→service refs.

Parametrized over the shared sixteen E2E_PROVEN set so fixtures/pack_drop/
cannot drift from prove_ciso / honesty inventory locks. No 17th adapter.

Every findings.jsonl row that carries a port field (top-level or
extra.port) must resolve to a same-file assets.jsonl kind:service on
address+port+protocol, OR a same-file kind:asset nested ports[] entry
(nmap-style: port number, and protocol when both sides publish one).
Host-only adapters (hping3, fping, onesixtyone, braa, nbtscan,
ike-scan) must have zero findings/observations with a port field.
SAMPLE/DEMO ≠ client stays true.

Broader than CoS #39 open_port_observed / sip_udp_port_observed →
service (tests/test_pack_drop_observation_asset_refs.py). This lock is
any ported finding → service-or-nested-ports plus explicit host-only
zero-ported-observations.
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
NMAP_NESTED = frozenset({"nmap"})
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
OBS_KINDS = frozenset({"finding", "observation"})


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


def _port(row: dict[str, Any]) -> str:
    return _field(row, "port")


def _protocol(row: dict[str, Any]) -> str:
    return _field(row, "protocol").lower()


def _has_port_field(row: dict[str, Any]) -> bool:
    """True when the row publishes a non-blank port (top-level or extra)."""
    return bool(_port(row))


def _keys_from_assets_list(raw: Any, keys: set[str]) -> None:
    """nmap-style assets[] — string hostname, or {hostname, extra.ip, name}."""
    if not isinstance(raw, list):
        return
    for item in raw:
        if isinstance(item, str):
            _add_key(keys, item)
            continue
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        for bag in (item, extra):
            for field in ("address", "ip", "addr", "hostname", "host", "name"):
                _add_key(keys, bag.get(field))


def _obs_keys(row: dict[str, Any]) -> set[str]:
    """Finding/observation join keys — not title/name (nmap name is the claim)."""
    extra = _extra(row)
    keys: set[str] = set()
    for bag in (row, extra):
        for field in ("address", "ip", "addr", "hostname", "host"):
            _add_key(keys, bag.get(field))
    _keys_from_assets_list(row.get("assets"), keys)
    _keys_from_assets_list(extra.get("assets"), keys)
    return keys


def _service_keys(row: dict[str, Any]) -> set[str]:
    extra = _extra(row)
    keys: set[str] = set()
    for bag in (row, extra):
        for field in ("address", "ip"):
            _add_key(keys, bag.get(field))
    return keys


def _asset_keys(row: dict[str, Any]) -> set[str]:
    extra = _extra(row)
    keys: set[str] = set()
    for bag in (row, extra):
        for field in ("ip", "hostname", "name", "address"):
            _add_key(keys, bag.get(field))
    return keys


def _nested_ports(row: dict[str, Any]) -> list[tuple[str, str]]:
    extra = _extra(row)
    out: list[tuple[str, str]] = []
    for raw in (row.get("ports"), extra.get("ports")):
        if not isinstance(raw, list):
            continue
        for item in raw:
            if isinstance(item, dict):
                port = _norm(item.get("port"))
                proto = _norm(item.get("protocol") or item.get("proto")).lower()
                if port:
                    out.append((port, proto))
            else:
                port = _norm(item)
                if port:
                    out.append((port, ""))
    return out


def _service_matches(
    obs_keys: set[str],
    port: str,
    proto: str,
    svc: dict[str, Any],
) -> bool:
    keys = _service_keys(svc)
    if not (obs_keys & keys):
        return False
    if _port(svc) != port:
        return False
    sproto = _protocol(svc)
    if proto and sproto != proto:
        return False
    return True


def _nested_matches(
    obs_keys: set[str],
    port: str,
    proto: str,
    asset: dict[str, Any],
) -> bool:
    if not (obs_keys & _asset_keys(asset)):
        return False
    for nport, nproto in _nested_ports(asset):
        if nport != port:
            continue
        if proto and nproto and proto != nproto:
            continue
        return True
    return False


def test_observation_service_port_set_matches_e2e_proven_sixteen() -> None:
    assert frozenset(E2E_PROVEN_PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert E2E_PROVEN_PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(
        E2E_PROVEN_PACK_DROP_ADAPTERS
    ) == tuple(COVEY_E2E_PROVEN)
    assert len(E2E_PROVEN_PACK_DROP_ADAPTERS) == 16
    assert len(set(E2E_PROVEN_PACK_DROP_ADAPTERS)) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in E2E_PROVEN_PACK_DROP_ADAPTERS


def test_unproven_adapters_absent_from_pack_drop_observation_service_ports() -> None:
    names = {path.name for path in PACK_DROP.iterdir() if path.is_dir()}
    for name in COVEY_E2E_UNPROVEN:
        assert name not in names, f"UNPROVEN {name} must not be a pack_drop fixture dir"
    assert names == set(E2E_PROVEN_PACK_DROP_ADAPTERS)
    assert names == set(COVEY_E2E_PROVEN)
    assert len(names) == 16


def test_observation_service_port_class_partition_matches_e2e_proven_sixteen() -> None:
    parts = (HOST_ONLY, NMAP_NESTED, SERVICE_EMITTERS)
    union: set[str] = set()
    for group in parts:
        overlap = union & group
        assert not overlap, f"observation-service-port-class overlap: {sorted(overlap)}"
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
def test_pack_drop_observation_finding_port_service_refs(adapter: str) -> None:
    dest = PACK_DROP / adapter
    assert dest.is_dir(), f"missing fixtures/pack_drop/{adapter}/"

    assets_path = dest / "assets.jsonl"
    findings_path = dest / "findings.jsonl"
    assert assets_path.is_file(), f"missing fixtures/pack_drop/{adapter}/assets.jsonl"
    assert findings_path.is_file(), f"missing fixtures/pack_drop/{adapter}/findings.jsonl"

    asset_rows = _load_jsonl(assets_path)
    finding_rows = _load_jsonl(findings_path)
    assert asset_rows, f"{adapter}/assets.jsonl must have at least one JSONL object"
    assert finding_rows, f"{adapter}/findings.jsonl must have at least one JSONL object"

    services = [
        (idx, row)
        for idx, row in enumerate(asset_rows, start=1)
        if _kind(row) == "service"
    ]
    assets = [
        (idx, row)
        for idx, row in enumerate(asset_rows, start=1)
        if _kind(row) == "asset"
    ]
    observations = [
        (idx, row)
        for idx, row in enumerate(finding_rows, start=1)
        if _kind(row) in OBS_KINDS
    ]
    assert observations, f"{adapter} has no finding/observation rows to lock"

    ported = [
        (idx, row) for idx, row in observations if _has_port_field(row)
    ]

    if adapter in HOST_ONLY:
        assert not services, (
            f"{adapter} is host-only and must invent no kind:service rows: "
            f"{[row.get('id') for _, row in services]}"
        )
        assert not ported, (
            f"{adapter} is host-only and must have zero findings/observations "
            f"with a port field: "
            f"{[(idx, row.get('id'), _port(row)) for idx, row in ported]}"
        )
        for idx, row in enumerate(finding_rows, start=1):
            assert not _has_port_field(row), (
                f"{adapter}/findings.jsonl:{idx} host-only invents a port "
                f"field: {row}"
            )
        return

    for idx, row in ported:
        loc = f"{adapter}/findings.jsonl:{idx}"
        port = _port(row)
        proto = _protocol(row)
        keys = _obs_keys(row)
        assert keys, (
            f"{loc} ported finding {port}/{proto or '?'} has no address / "
            f"assets[] / extra.ip to resolve against a service or asset: {row}"
        )
        svc_hits = [
            svc
            for _, svc in services
            if _service_matches(keys, port, proto, svc)
        ]
        nest_hits = [
            asset
            for _, asset in assets
            if _nested_matches(keys, port, proto, asset)
        ]
        assert svc_hits or nest_hits, (
            f"{loc} ported finding {port}/{proto or '?'} keys {sorted(keys)} "
            f"matches neither a same-file kind:service on address+port+protocol "
            f"nor a same-file kind:asset nested ports[] entry: {row}"
        )
        if adapter in NMAP_NESTED and not services:
            assert nest_hits, (
                f"{loc} nmap-style port {port!r} has no kind:service rows and "
                f"did not match kind:asset ports[]: {row}"
            )
        if adapter in SERVICE_EMITTERS:
            assert svc_hits, (
                f"{loc} {adapter} emits services but port {port}/{proto or '?'} "
                f"did not match a same-file kind:service on "
                f"address+port+protocol: {row}"
            )
