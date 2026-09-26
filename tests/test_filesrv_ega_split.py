"""FILESRV / 10.0.0.50 POA&M EGA split + jenkins principal vs host.

Real-sample shaped identity (nbtscan / smbmap / nmap FILESRV). SAMPLE ≠ client.
"""

from __future__ import annotations

from pathlib import Path

from collectors import identity_ad, inventory_nmap
from shared.asset_ids import ids_from_record
from shared.asset_key import asset_key, ega_asset_id
from shared.asset_ledger import AssetLedger, attach_asset_uids, make_asset_uid
from shared.poam_ledger import weakness_key
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
DEMO = ROOT / "fixtures" / "demo"
NOW = "2026-09-01T00:00:00Z"


def _filesrv_records() -> list[dict]:
    recs: list[dict] = []
    recs.extend(inventory_nmap.parse_file(DEMO / "nmap" / "scan.xml"))
    recs.extend(inventory_nmap.parse_file(SAMPLES / "nbtscan.txt"))
    recs.extend(inventory_nmap.parse_file(SAMPLES / "smbmap.txt"))
    return recs


def _is_filesrv(rec: dict) -> bool:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    blob = " ".join(
        [
            str(rec.get("name") or ""),
            " ".join(str(a) for a in (rec.get("assets") or [])),
            str(extra.get("ip") or ""),
            str(extra.get("netbios") or ""),
            str(extra.get("hostname") or ""),
            str(extra.get("fqdn") or ""),
        ]
    ).lower()
    return "10.0.0.50" in blob or "filesrv" in blob


def test_finding_title_is_not_netbios() -> None:
    rec = {
        "kind": "finding",
        "source": "inventory-nmap",
        "name": "Open port 445/microsoft-ds",
        "assets": ["10.0.0.50"],
        "extra": {"ip": "10.0.0.50", "port": "445", "protocol": "tcp"},
    }
    ids = ids_from_record(rec)
    assert "445" not in str(ids.get("netbios") or "")
    assert "OPEN PORT" not in str(ids.get("netbios") or "")
    assert ids.get("ip") == ["10.0.0.50"]


def test_filesrv_poam_rows_share_ledger_ega() -> None:
    """One host, two issues — not four POA&M rows on two EGAs."""
    raw = _filesrv_records()
    assert any(_is_filesrv(r) and r["kind"] == "asset" for r in raw)
    ledger = AssetLedger()
    attached = attach_asset_uids(raw, ledger, now=NOW)
    host = next(
        r
        for r in attached
        if r.get("kind") == "asset" and _is_filesrv(r)
    )
    uid = str((host.get("extra") or {}).get("asset_uid") or "")
    assert uid.startswith("EGA-")
    assert uid in ledger.assets
    aliases = ledger._ids_of(ledger.assets[uid])
    assert "10.0.0.50" in (aliases.get("ip") or [])
    assert str(aliases.get("netbios") or "").upper() == "FILESRV"
    assert "filesrv" in {
        str(aliases.get("hostname") or "").lower(),
        str(aliases.get("fqdn") or "").split(".", 1)[0].lower(),
    }

    findings = [
        r
        for r in attached
        if r.get("kind") == "finding" and _is_filesrv(r)
    ]
    assert findings
    egas = {str((r.get("extra") or {}).get("asset_uid") or "") for r in findings}
    assert egas == {uid}
    for rec in findings:
        assert ega_asset_id(rec) == uid
        assert asset_key(rec).startswith(uid)
        assert ega_asset_id(rec) in ledger.assets

    pairs = {(weakness_key(r), ega_asset_id(r)) for r in findings}
    issues = {weakness_key(r) for r in findings}
    assert len(issues) >= 2
    assert len(pairs) == len(issues)


def test_filesrv_title_plus_ip_does_not_mint_orphan_ega() -> None:
    """Argus split: MAC-anchored ledger host vs IP-only POA&M EGA."""
    mac_uid = make_asset_uid("mac", "00:11:22:33:44:55")
    ip_uid = make_asset_uid("ip", "10.0.0.50")
    assert mac_uid != ip_uid
    host = make_record(
        kind="asset",
        source="inventory-nmap",
        ref_id="NMAP-asset-filesrv",
        name="filesrv.corp.local",
        category="host",
        assets=["filesrv.corp.local"],
        collected_at=NOW,
        extra={
            "asset_type": "PR",
            "ip": "10.0.0.50",
            "mac": "00:11:22:33:44:55",
            "fqdn": "filesrv.corp.local",
            "hostname": "filesrv",
            "netbios": "FILESRV",
        },
    )
    smb = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-filesrv-corp-local-445-tcp",
        name="SMB 445 exposed",
        category="exposure",
        assets=["filesrv.corp.local"],
        collected_at=NOW,
        extra={"ip": "10.0.0.50", "port": "445", "protocol": "tcp", "service": "microsoft-ds"},
    )
    share = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-filesrv-share-c",
        name="Writable SMB share C$ on FILESRV",
        category="exposure",
        assets=["FILESRV"],
        collected_at=NOW,
        extra={"ip": "10.0.0.50", "port": "445", "protocol": "tcp", "share": "C$"},
    )
    ip_only = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-10-0-0-50-445-tcp",
        name="Open port 445/microsoft-ds",
        category="exposure",
        assets=["10.0.0.50"],
        collected_at=NOW,
        extra={"ip": "10.0.0.50", "port": "445", "protocol": "tcp", "service": "microsoft-ds"},
    )
    ip_share = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-10-0-0-50-share-c",
        name="Writable SMB share C$ on 10.0.0.50",
        category="exposure",
        assets=["10.0.0.50"],
        collected_at=NOW,
        extra={"ip": "10.0.0.50", "port": "445", "protocol": "tcp", "share": "C$"},
    )
    ledger = AssetLedger()
    attached = attach_asset_uids([host, smb, share, ip_only, ip_share], ledger, now=NOW)
    assets = [r for r in attached if r["kind"] == "asset"]
    assert len(assets) == 1
    uid = str((assets[0].get("extra") or {}).get("asset_uid") or "")
    assert uid in ledger.assets
    findings = [r for r in attached if r["kind"] == "finding"]
    assert len(findings) == 4
    assert {ega_asset_id(r) for r in findings} == {uid}
    assert ip_uid not in {ega_asset_id(r) for r in findings}
    assert all(ega_asset_id(r) in ledger.assets for r in findings)
    pairs = {(weakness_key(r), ega_asset_id(r)) for r in findings}
    assert len(pairs) == 2


def test_jenkins_principal_and_host_stay_distinct_on_shared_ledger() -> None:
    user = make_record(
        kind="asset",
        source="saas-idp",
        ref_id="SAAS-jenkins",
        name="jenkins",
        category="identity",
        assets=["jenkins"],
        collected_at=NOW,
        extra={"asset_type": "SP", "tenant": "okta-prod"},
    )
    host = make_record(
        kind="asset",
        source="inventory-nmap",
        ref_id="NMAP-jenkins",
        name="jenkins",
        category="host",
        assets=["jenkins"],
        collected_at=NOW,
        extra={"asset_type": "PR", "hostname": "jenkins"},
    )
    principal = make_record(
        kind="asset",
        source="identity-ad",
        ref_id="ID-jenkins",
        name="jenkins@corp.local",
        category="identity",
        assets=["jenkins@corp.local"],
        collected_at=NOW,
        extra={"asset_type": "SP", "kind": "User", "principal": "jenkins@corp.local"},
    )
    ledger = AssetLedger()
    attached = attach_asset_uids([user, host, principal], ledger, now=NOW)
    by_src = {
        r["source"]: str((r.get("extra") or {}).get("asset_uid") or "")
        for r in attached
        if r.get("kind") == "asset"
    }
    assert len(set(by_src.values())) == 3
    assert all(u.startswith("EGA-") and u in ledger.assets for u in by_src.values())
    assert not ledger._ids_of(ledger.assets[by_src["inventory-nmap"]]).get("principal")


def test_identity_ad_user_is_principal_computer_is_host() -> None:
    users = identity_ad.parse_file(SAMPLES / "bloodhound" / "bhce_v6_users.json")
    computers = identity_ad.parse_file(SAMPLES / "bloodhound" / "bhce_v6_computers.json")
    user_assets = [r for r in users if r["kind"] == "asset"]
    comp_assets = [r for r in computers if r["kind"] == "asset"]
    assert user_assets
    assert all((r.get("extra") or {}).get("principal") for r in user_assets)
    assert all((r.get("extra") or {}).get("asset_type") == "SP" for r in user_assets)
    if comp_assets:
        assert all((r.get("extra") or {}).get("asset_type") == "PR" for r in comp_assets)
        assert not any((r.get("extra") or {}).get("principal") for r in comp_assets)
