"""Lock per-adapter pack_drop claim-class + DEMO labels.

Parametrized over the shared sixteen E2E_PROVEN set so fixtures/pack_drop/
cannot drift from prove_ciso / honesty inventory locks. No 17th adapter.
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

ALLOWED_SCHEMAS = frozenset({"covey.pack_drop.v1"})

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
HOST_ONLY_ICMP = frozenset({"fping", "hping3"})
SNMP = frozenset({"onesixtyone", "braa"})
NETBIOS = frozenset({"nbtscan"})
IKE = frozenset({"ike-scan"})
SIP = frozenset({"svmap"})

SIP_CLAIMS = frozenset({"sip_user_agent_observed", "sip_udp_port_observed"})
IKE_CLAIMS = frozenset({"ike_handshake_observed", "ike_responder_observed"})
SNMP_CLAIMS = frozenset(
    {"snmp_community_observed", "sysdescr_observed", "oid_observed"}
)
HOST_UP_CLAIM = "host_up_observed"
OPEN_PORT_CLAIM = "open_port_observed"
NETBIOS_CLAIM = "netbios_name_observed"
REJECT_UA = frozenset({"unknown", "", "user agent", "disabled"})
UNKNOWN_NETBIOS = frozenset({"<unknown>", "unknown", ""})


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} must be a JSON object"
    return data


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


def _claims(row: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    extra = _extra(row)
    for val in (row.get("claim"), extra.get("claim")):
        if isinstance(val, str) and val:
            out.add(val)
        elif isinstance(val, list):
            out.update(str(item) for item in val if item)
    return out


def _all_claims(rows: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for row in rows:
        out |= _claims(row)
    return out


def _kind(row: dict[str, Any]) -> str:
    return str(row.get("kind") or "").lower()


def _protocol(row: dict[str, Any]) -> str:
    return str(row.get("protocol") or _extra(row).get("protocol") or "").lower()


def _port(row: dict[str, Any]) -> str:
    extra = _extra(row)
    val = row.get("port") if row.get("port") is not None else extra.get("port")
    return "" if val is None else str(val)


def _service(row: dict[str, Any]) -> str:
    return str(row.get("service") or _extra(row).get("service") or "").lower()


def _title(row: dict[str, Any]) -> str:
    return str(row.get("title") or row.get("name") or "")


def _user_agent(row: dict[str, Any]) -> str | None:
    extra = _extra(row)
    if "user_agent" in row:
        return str(row.get("user_agent") or "")
    if "user_agent" in extra:
        return str(extra.get("user_agent") or "")
    return None


def _is_tcp_service(row: dict[str, Any]) -> bool:
    return _kind(row) == "service" and _protocol(row) == "tcp"


def _ports_invent_tcp(row: dict[str, Any]) -> bool:
    extra = _extra(row)
    ports = row.get("ports") or extra.get("ports") or []
    if not isinstance(ports, list):
        return False
    for item in ports:
        if not isinstance(item, dict):
            continue
        proto = str(item.get("protocol") or item.get("proto") or "").lower()
        state = str(item.get("state") or "").lower()
        if not item.get("port") and item.get("port") != 0:
            continue
        if state not in {"", "open"}:
            continue
        if proto == "tcp" or proto == "":
            return True
    return False


def _invents_tcp_open_port(row: dict[str, Any]) -> bool:
    if _is_tcp_service(row):
        return True
    if OPEN_PORT_CLAIM in _claims(row):
        proto = _protocol(row)
        if proto in {"udp", "icmp", "ike", "snmp", "netbios"}:
            return False
        return True
    return _ports_invent_tcp(row)


def _demo_text(meta: dict[str, Any]) -> str:
    honesty = meta.get("honesty") if isinstance(meta.get("honesty"), dict) else {}
    return " ".join(
        str(part or "")
        for part in (
            meta.get("note"),
            meta.get("source"),
            honesty.get("note") if isinstance(honesty, dict) else "",
        )
    )


def _assert_no_invented_tcp(rows: list[dict[str, Any]], adapter: str) -> None:
    for row in rows:
        assert not _invents_tcp_open_port(row), (
            f"{adapter} invents TCP open_port_observed / kind=service protocol=tcp: {row}"
        )
        assert OPEN_PORT_CLAIM not in _claims(row), (
            f"{adapter} claims {OPEN_PORT_CLAIM}: {row}"
        )


def test_claim_class_partition_matches_e2e_proven_sixteen() -> None:
    assert frozenset(E2E_PROVEN_PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert E2E_PROVEN_PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(
        E2E_PROVEN_PACK_DROP_ADAPTERS
    ) == tuple(COVEY_E2E_PROVEN)
    parts = (PORT_SERVICE, HOST_ONLY_ICMP, SNMP, NETBIOS, IKE, SIP)
    union: set[str] = set()
    for group in parts:
        overlap = union & group
        assert not overlap, f"claim-class overlap: {sorted(overlap)}"
        union |= set(group)
    assert union == set(E2E_PROVEN_PACK_DROP_ADAPTERS)
    assert len(union) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in union


def test_unproven_adapters_absent_from_pack_drop() -> None:
    names = {path.name for path in PACK_DROP.iterdir() if path.is_dir()}
    for name in COVEY_E2E_UNPROVEN:
        assert name not in names, f"UNPROVEN {name} must not be a pack_drop fixture dir"
    assert names == set(E2E_PROVEN_PACK_DROP_ADAPTERS)
    assert names == set(COVEY_E2E_PROVEN)


@pytest.mark.parametrize(
    "adapter",
    list(E2E_PROVEN_PACK_DROP_ADAPTERS),
    ids=list(E2E_PROVEN_PACK_DROP_ADAPTERS),
)
def test_pack_drop_claim_class_and_demo_label(adapter: str) -> None:
    dest = PACK_DROP / adapter
    assert dest.is_dir(), f"missing fixtures/pack_drop/{adapter}/"

    meta_path = dest / "meta.json"
    assets_path = dest / "assets.jsonl"
    findings_path = dest / "findings.jsonl"
    assert meta_path.is_file()
    assert assets_path.is_file() and assets_path.stat().st_size > 0
    assert findings_path.is_file() and findings_path.stat().st_size > 0

    meta = _load_json(meta_path)
    demo = meta.get("demo")
    assert isinstance(demo, bool) and demo is True, f"{adapter} meta.demo must be JSON true"
    assert meta.get("adapter") == adapter
    assert meta.get("schema") in ALLOWED_SCHEMAS, (
        f"{adapter} schema={meta.get('schema')!r} not in {sorted(ALLOWED_SCHEMAS)}"
    )
    label = _demo_text(meta).lower()
    assert "sample" in label or "demo" in label, f"{adapter} note/source missing SAMPLE/DEMO"
    assert "client" in label, f"{adapter} note/source missing client (DEMO ≠ client)"

    assets = _load_jsonl(assets_path)
    findings = _load_jsonl(findings_path)
    assert assets, f"{adapter} assets.jsonl is empty"
    assert findings, f"{adapter} findings.jsonl is empty"
    rows = assets + findings
    claims = _all_claims(findings)

    if adapter in PORT_SERVICE:
        assert not (claims & SIP_CLAIMS), f"{adapter} invented SIP claims: {claims & SIP_CLAIMS}"
        assert not (claims & IKE_CLAIMS), f"{adapter} invented IKE claims: {claims & IKE_CLAIMS}"
        return

    if adapter in HOST_ONLY_ICMP:
        for row in findings:
            row_claims = _claims(row)
            if row_claims:
                extra = row_claims - {HOST_UP_CLAIM}
                assert not extra, f"{adapter} findings claim {extra}; host-only allows {HOST_UP_CLAIM}"
            else:
                title = _title(row).lower()
                assert "host up" in title or "host_up" in title, (
                    f"{adapter} empty claim set without host_up in title: {row}"
                )
        _assert_no_invented_tcp(rows, adapter)
        return

    if adapter in SNMP:
        unexpected = claims - SNMP_CLAIMS
        assert not unexpected, f"{adapter} unexpected claims {unexpected}"
        assert claims & SNMP_CLAIMS, f"{adapter} missing SNMP claim-class"
        _assert_no_invented_tcp(rows, adapter)
        return

    if adapter in NETBIOS:
        assert NETBIOS_CLAIM in claims, f"{adapter} missing {NETBIOS_CLAIM}"
        for row in findings:
            extra = _extra(row)
            name = str(
                row.get("netbios_name")
                or extra.get("netbios_name")
                or row.get("name")
                or extra.get("name")
                or ""
            ).strip()
            assert name, f"{adapter} empty NetBIOS name: {row}"
            assert name.lower() not in UNKNOWN_NETBIOS, f"{adapter} rejected NetBIOS name {name!r}"
        _assert_no_invented_tcp(rows, adapter)
        return

    if adapter in IKE:
        assert "ike_handshake_observed" in claims, f"{adapter} missing ike_handshake_observed"
        assert "ike_responder_observed" in claims, f"{adapter} missing ike_responder_observed"
        _assert_no_invented_tcp(rows, adapter)
        return

    if adapter in SIP:
        assert "sip_user_agent_observed" in claims, f"{adapter} missing sip_user_agent_observed"
        assert "sip_udp_port_observed" in claims, f"{adapter} missing sip_udp_port_observed"
        for row in rows:
            proto = _protocol(row)
            port = _port(row)
            if port or _kind(row) == "service":
                assert proto == "udp", f"{adapter} non-UDP service/port: {row}"
                assert port in {"", "5060"}, f"{adapter} SIP port must be UDP/5060: {row}"
                if _service(row):
                    assert _service(row) == "sip", f"{adapter} non-SIP service: {row}"
            assert proto != "tcp", f"{adapter} invented TCP: {row}"
            ua = _user_agent(row)
            if ua is not None:
                assert ua.strip().lower() not in REJECT_UA, (
                    f"{adapter} rejected UA {ua!r} as a live asset"
                )
        _assert_no_invented_tcp(rows, adapter)
        return

    raise AssertionError(f"{adapter} is not in a known claim class")
