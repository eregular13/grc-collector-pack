"""Argus B5: pack_drop row ids are not weakness identity.

Farm DEMO nmap assets.jsonl ports[] mint nmap-port-{port}/{proto}.
findings.jsonl copies extra.id (nmap-10-microsoftds-445). Those are the
same host/port and must share one EGP. SAMPLE/DEMO ≠ client KEEP.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path

from collectors import inventory_nmap
from shared.estate_pages import _exec_top_findings
from shared.kev import KevCatalog
from shared.poam_ledger import (
    _is_pack_drop_row_id,
    _is_scanner_identity,
    apply_ledger,
    fp_v1,
    weakness_key,
)

ROOT = Path(__file__).resolve().parents[1]
NMAP_DROP = ROOT / "fixtures" / "pack_drop" / "nmap"


def _unevaluated() -> KevCatalog:
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _run(when: str) -> datetime:
    return datetime.fromisoformat(when.replace("Z", "+00:00"))


def _nmap_findings() -> list[dict]:
    recs: list[dict] = []
    recs.extend(inventory_nmap.parse_file(NMAP_DROP / "assets.jsonl"))
    recs.extend(inventory_nmap.parse_file(NMAP_DROP / "findings.jsonl"))
    return [r for r in recs if r.get("kind") == "finding"]


def test_pack_drop_row_ids_are_not_scanner_identity() -> None:
    assert _is_pack_drop_row_id("nmap-10-microsoftds-445")
    assert _is_pack_drop_row_id("nmap-20-telnet-23")
    assert _is_pack_drop_row_id("rustscan-7-tcp-80")
    assert not _is_pack_drop_row_id("nmap-port-445/tcp")
    assert not _is_pack_drop_row_id("svmap-96-sip-ua")
    assert not _is_pack_drop_row_id("FIRE-4590")
    assert not _is_scanner_identity("nmap-10-microsoftds-445")
    assert _is_scanner_identity("nmap-port-445/tcp")


def test_pack_drop_smb445_falls_through_to_nmap_port_check() -> None:
    xml_style = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-dc-445/tcp",
        "name": "SMB 445 exposed",
        "severity": "high",
        "category": "exposure",
        "assets": ["dc.corp.local"],
        "labels": ["nmap"],
        "extra": {
            "port": "445",
            "protocol": "tcp",
            "service": "microsoft-ds",
            "ip": "10.0.0.10",
            "check_id": "nmap-port-445/tcp",
            "tool": "nmap",
        },
    }
    pack_row = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-nmap-10-microsoftds-445",
        "name": "SMB 445 exposed",
        "severity": "high",
        "category": "exposure",
        "assets": ["dc.corp.local"],
        "labels": ["nmap", "covey"],
        "extra": {
            "port": "445",
            "protocol": "tcp",
            "service": "microsoft-ds",
            "ip": "10.0.0.10",
            "id": "nmap-10-microsoftds-445",
            "adapter": "nmap",
            "pack_drop": "covey",
        },
    }
    assert weakness_key(xml_style) == weakness_key(pack_row) == "nmap:nmap-port-445/tcp"
    assert fp_v1(xml_style) == fp_v1(pack_row)


def test_farm_demo_nmap_host_port_collapses_to_one_egp() -> None:
    findings = _nmap_findings()
    emit = next(
        r
        for r in findings
        if (r.get("extra") or {}).get("check_id") == "nmap-port-445/tcp"
        and "dc.corp.local" in (r.get("assets") or [])
    )
    row = next(
        r
        for r in findings
        if (r.get("extra") or {}).get("id") == "nmap-10-microsoftds-445"
    )
    assert weakness_key(emit) == weakness_key(row) == "nmap:nmap-port-445/tcp"
    assert fp_v1(emit) == fp_v1(row)

    telnet_keys = {
        weakness_key(r)
        for r in findings
        if "telnet-legacy.corp.local" in (r.get("assets") or [])
        and str((r.get("extra") or {}).get("port") or "") == "23"
    }
    assert telnet_keys == {"nmap:nmap-port-23/tcp"}

    ledger = apply_ledger(
        findings,
        catalog=_unevaluated(),
        run_at=_run("2026-09-26T00:00:00Z"),
        prior_existed=False,
    )
    by_host_port: dict[tuple[str, str], set[str]] = defaultdict(set)
    for item in ledger["items"].values():
        wk = str(item.get("weakness_key") or "")
        if not wk.startswith("nmap:nmap-port-"):
            continue
        port_proto = wk.split("nmap-port-", 1)[1]
        host = str(item.get("display_asset") or item.get("asset_key") or "")
        by_host_port[(host, port_proto)].add(str(item.get("poam_id") or ""))
    assert by_host_port
    for (host, port_proto), ids in sorted(by_host_port.items()):
        assert len(ids) == 1, f"{host} {port_proto} minted {sorted(ids)}"
    dc_445 = [
        ids
        for (host, port_proto), ids in by_host_port.items()
        if "dc.corp.local" in host and port_proto == "445/tcp"
    ]
    assert dc_445 and len(dc_445[0]) == 1
    telnet = [
        ids
        for (host, port_proto), ids in by_host_port.items()
        if "telnet-legacy" in host and port_proto == "23/tcp"
    ]
    assert telnet and len(telnet[0]) == 1


def test_exec_top5_collapses_farm_demo_telnet_pairs() -> None:
    findings = _nmap_findings()
    mapped = {
        str(r.get("ref_id")): {"include_poam": True, "framework_refs": "csf_PR"}
        for r in findings
    }
    top = _exec_top_findings(findings, mapped, 5)
    telnet_hosts = [
        str((r.get("assets") or [""])[0])
        for r in top
        if "telnet" in str(r.get("name") or "").lower()
        or str((r.get("extra") or {}).get("port") or "") == "23"
    ]
    assert len(telnet_hosts) == len(set(telnet_hosts)), telnet_hosts
    ids = {str((r.get("extra") or {}).get("id") or "") for r in top}
    assert "nmap-20-telnet-23" not in ids
    assert "nmap-l60-telnet-23" not in ids
