"""Lock global pack_drop observation→asset/service referential integrity.

Parametrized over the shared sixteen E2E_PROVEN set so fixtures/pack_drop/
cannot drift from prove_ciso / honesty inventory locks. No 17th adapter.

Every findings.jsonl observation/finding must resolve to a same-adapter
assets.jsonl host|asset (address, or nmap-style assets[] hostname /
extra.ip / asset name). Port findings on adapters that emit service rows
must match a same-adapter service on address+port+protocol. Host-only
adapters invent no ports/services. SAMPLE/DEMO ≠ client stays true.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.prove_ciso import E2E_PROVEN_PACK_DROP_ADAPTERS
from tests.test_pack_drop_claim_class import (
    OPEN_PORT_CLAIM,
    _invents_tcp_open_port,
)
from tests.test_status_honesty import COVEY_E2E_PROVEN, COVEY_E2E_UNPROVEN

ROOT = Path(__file__).resolve().parents[1]
PACK_DROP = ROOT / "fixtures" / "pack_drop"

HOST_ONLY = frozenset(
    {"fping", "hping3", "onesixtyone", "braa", "nbtscan", "ike-scan"}
)
PORT_SERVICE = frozenset(
    {
        "nmap",
        "rustscan",
        "httpx",
        "unicornscan",
        "sslscan",
        "tlsx",
        "whatweb",
        "naabu",
        "nping",
    }
)
SIP = frozenset({"svmap"})
PORT_FINDING_CLAIMS = frozenset(
    {"open_port_observed", "sip_udp_port_observed"}
)
OBS_KINDS = frozenset({"finding", "observation"})
HOST_KINDS = frozenset({"asset", "host"})


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


def _claims(row: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    extra = _extra(row)
    for val in (row.get("claim"), extra.get("claim")):
        if isinstance(val, str) and val.strip():
            out.add(val.strip())
        elif isinstance(val, list):
            out.update(str(item).strip() for item in val if item)
    return out


def _port(row: dict[str, Any]) -> str:
    extra = _extra(row)
    val = row.get("port") if row.get("port") not in (None, "") else extra.get("port")
    if val in (None, ""):
        return ""
    return str(val).strip()


def _protocol(row: dict[str, Any]) -> str:
    extra = _extra(row)
    return str(row.get("protocol") or extra.get("protocol") or "").strip().lower()


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


def _host_keys(row: dict[str, Any], *, is_observation: bool) -> set[str]:
    """Identity keys that can join an observation to a host|asset.

    Observations do not treat title/name as a host — nmap finding name
    is 'SMB 445 exposed', not filesrv.corp.local. Host|asset rows may
    use name (nmap-style asset name).
    """
    extra = _extra(row)
    keys: set[str] = set()
    fields = ("address", "ip", "addr", "hostname", "host")
    for bag in (row, extra):
        for field in fields:
            _add_key(keys, bag.get(field))
    if not is_observation:
        _add_key(keys, row.get("name"))
        _add_key(keys, extra.get("name"))
    _keys_from_assets_list(row.get("assets"), keys)
    _keys_from_assets_list(extra.get("assets"), keys)
    return keys


def _nested_ports(row: dict[str, Any]) -> set[str]:
    extra = _extra(row)
    out: set[str] = set()
    for raw in (row.get("ports"), extra.get("ports")):
        if not isinstance(raw, list):
            continue
        for item in raw:
            if isinstance(item, dict):
                port = item.get("port")
                if port not in (None, ""):
                    out.add(str(port).strip())
            elif item not in (None, ""):
                out.add(str(item).strip())
    return out


def _is_observation(row: dict[str, Any]) -> bool:
    return _kind(row) in OBS_KINDS or bool(_claims(row))


def _needs_service_ref(row: dict[str, Any]) -> bool:
    if _port(row):
        return True
    return bool(_claims(row) & PORT_FINDING_CLAIMS)


def _service_proto(row: dict[str, Any]) -> str:
    proto = _protocol(row)
    if proto:
        return proto
    claims = _claims(row)
    if "sip_udp_port_observed" in claims:
        return "udp"
    if "open_port_observed" in claims:
        return "tcp"
    return ""


def _iter_rows(adapter: str, filename: str) -> list[tuple[Path, int, dict[str, Any]]]:
    path = PACK_DROP / adapter / filename
    assert path.is_file(), f"missing {path.relative_to(ROOT)}"
    return [(path, idx, row) for idx, row in enumerate(_load_jsonl(path), start=1)]


def test_observation_asset_ref_set_matches_e2e_proven_sixteen() -> None:
    assert frozenset(E2E_PROVEN_PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert E2E_PROVEN_PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(
        E2E_PROVEN_PACK_DROP_ADAPTERS
    ) == tuple(COVEY_E2E_PROVEN)
    assert len(E2E_PROVEN_PACK_DROP_ADAPTERS) == 16
    assert len(set(E2E_PROVEN_PACK_DROP_ADAPTERS)) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in E2E_PROVEN_PACK_DROP_ADAPTERS


def test_unproven_adapters_absent_from_pack_drop_observation_asset_refs() -> None:
    names = {path.name for path in PACK_DROP.iterdir() if path.is_dir()}
    for name in COVEY_E2E_UNPROVEN:
        assert name not in names, f"UNPROVEN {name} must not be a pack_drop fixture dir"
    assert names == set(E2E_PROVEN_PACK_DROP_ADAPTERS)
    assert names == set(COVEY_E2E_PROVEN)
    assert len(names) == 16


def test_referential_partition_matches_e2e_proven_sixteen() -> None:
    parts = (HOST_ONLY, PORT_SERVICE, SIP)
    union: set[str] = set()
    for group in parts:
        overlap = union & group
        assert not overlap, f"referential-class overlap: {sorted(overlap)}"
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
def test_pack_drop_observation_asset_service_refs_per_adapter(adapter: str) -> None:
    dest = PACK_DROP / adapter
    assert dest.is_dir(), f"missing fixtures/pack_drop/{adapter}/"

    asset_rows = _iter_rows(adapter, "assets.jsonl")
    finding_rows = _iter_rows(adapter, "findings.jsonl")
    assert asset_rows, f"{adapter} assets.jsonl is empty"
    assert finding_rows, f"{adapter} findings.jsonl is empty"

    hosts = [
        (path, idx, row)
        for path, idx, row in asset_rows
        if _kind(row) in HOST_KINDS
    ]
    services = [
        (path, idx, row)
        for path, idx, row in asset_rows
        if _kind(row) == "service"
    ]
    observations = [
        (path, idx, row)
        for path, idx, row in finding_rows
        if _is_observation(row)
    ]
    assert hosts, f"{adapter} has no host|asset rows to resolve against"
    assert observations, f"{adapter} has no observation/finding rows to lock"

    host_key_sets = [_host_keys(row, is_observation=False) for _, _, row in hosts]
    all_host_keys = set().union(*host_key_sets) if host_key_sets else set()
    assert all_host_keys, f"{adapter} host|asset rows have no address/name keys"

    if adapter in HOST_ONLY:
        assert not services, (
            f"{adapter} is host-only and must invent no service rows: "
            f"{[row.get('id') for _, _, row in services]}"
        )
        for path, idx, row in asset_rows + finding_rows:
            rel = path.relative_to(ROOT)
            assert not _invents_tcp_open_port(row), (
                f"{rel}:{idx} host-only invents TCP open_port / kind=service: {row}"
            )
            assert OPEN_PORT_CLAIM not in _claims(row), (
                f"{rel}:{idx} host-only claims {OPEN_PORT_CLAIM}: {row}"
            )
            assert not _port(row), (
                f"{rel}:{idx} host-only invents a port field (no service rows): {row}"
            )

    service_index: list[tuple[set[str], str, str, dict[str, Any]]] = []
    for _, _, row in services:
        keys = _host_keys(row, is_observation=False)
        service_index.append((keys, _port(row), _service_proto(row), row))

    for path, idx, row in observations:
        rel = path.relative_to(ROOT)
        obs_keys = _host_keys(row, is_observation=True)
        assert obs_keys, (
            f"{rel}:{idx} observation/finding has no address / assets[] / extra.ip "
            f"to resolve against a host|asset: {row}"
        )
        matched_hosts = [
            (hpath, hidx, hrow)
            for (hpath, hidx, hrow), hkeys in zip(hosts, host_key_sets)
            if obs_keys & hkeys
        ]
        assert matched_hosts, (
            f"{rel}:{idx} observation keys {sorted(obs_keys)} do not resolve to a "
            f"same-adapter host|asset (known {sorted(all_host_keys)}): {row}"
        )

        if adapter in HOST_ONLY:
            continue

        if not _needs_service_ref(row):
            continue

        port = _port(row)
        proto = _service_proto(row)
        if services:
            hits = [
                svc
                for keys, sport, sproto, svc in service_index
                if obs_keys & keys
                and (not port or sport == port)
                and (not proto or sproto == proto)
            ]
            assert hits, (
                f"{rel}:{idx} port finding {port}/{proto or '?'} keys "
                f"{sorted(obs_keys)} has no matching same-adapter service "
                f"on address+port+protocol: {row}"
            )
            continue

        # nmap-style: ports live on the host|asset, not as kind=service rows.
        assert adapter in PORT_SERVICE, (
            f"{rel}:{idx} {adapter} has a port finding but no service rows "
            f"and is not nmap-style port/service: {row}"
        )
        nested = set()
        for _, _, hrow in matched_hosts:
            nested |= _nested_ports(hrow)
        assert port and port in nested, (
            f"{rel}:{idx} nmap-style port {port!r} is not on the resolved "
            f"host|asset ports[] {sorted(nested)}: {row}"
        )
