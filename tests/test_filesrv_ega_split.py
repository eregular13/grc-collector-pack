"""FILESRV / 10.0.0.50 EGA-unify + jenkins principal vs host.

Finding titles are not asset anchors; FILESRV rows share one ledger EGA.
Distinct SMB/share/port findings stay separate rows (EGA-unify, not fold).
SAMPLE ≠ client.
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
    """FILESRV findings share one ledger EGA. Distinct issues stay distinct rows."""
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


def _seed_pre_principal(ledger: AssetLedger, token: str, *, typ: str = "hostname") -> str:
    """Master-era identity: hostname/name alias, no principal stamp."""
    ids = {typ: token, "name": token}
    uid, anchor = ledger._new_uid(ids)
    asset = {
        "asset_uid": uid,
        "created": NOW,
        "anchor": dict(anchor),
        "status": "active",
        "merged_into": "",
        "replaces": "",
        "ephemeral": False,
        "class_uid": "",
        "poam_status": "open",
        "absent_covered_runs": 0,
        "sources": ["identity-ad"],
        "aliases": [
            {
                "type": typ,
                "value": token,
                "scope": "",
                "first_seen": NOW,
                "last_seen": NOW,
                "valid_to": "",
                "sources": ["identity-ad"],
            },
            {
                "type": "name",
                "value": token,
                "scope": "",
                "first_seen": NOW,
                "last_seen": NOW,
                "valid_to": "",
                "sources": ["identity-ad"],
            },
        ],
        "iiw": {},
        "events": [],
        "uai": token,
    }
    ledger.assets[uid] = asset
    return uid


def test_pre_principal_hostname_upgrade_keeps_ega() -> None:
    """Stored identity without principal must not mint a twin on upgrade."""
    ledger = AssetLedger()
    old = _seed_pre_principal(ledger, "svc-krbtgt-roast", typ="hostname")
    rec = make_record(
        kind="asset",
        source="identity-ad",
        ref_id="ID-svc-krbtgt-roast",
        name="svc-krbtgt-roast",
        category="identity",
        assets=["svc-krbtgt-roast"],
        collected_at=NOW,
        extra={"asset_type": "SP", "kind": "User", "principal": "svc-krbtgt-roast"},
    )
    uid = ledger.observe(rec, now=NOW)
    assert uid == old
    assert str(ledger._ids_of(ledger.assets[old]).get("principal") or "") == "svc-krbtgt-roast"
    actives = [a for a in ledger.assets.values() if a.get("status") == "active"]
    assert len(actives) == 1


def test_pre_principal_spaced_name_upgrade_keeps_ega() -> None:
    """Groups like Domain Admins / Backup Operators upgrade onto the stored EGA."""
    ledger = AssetLedger()
    kept: dict[str, str] = {}
    for name in ("domain admins", "backup operators"):
        kept[name] = _seed_pre_principal(ledger, name, typ="name")
        rec = make_record(
            kind="asset",
            source="identity-ad",
            ref_id=f"ID-{name.replace(' ', '-')}",
            name=name,
            category="identity",
            assets=[name],
            collected_at=NOW,
            extra={"asset_type": "SP", "kind": "Group", "principal": name},
        )
        assert ledger.observe(rec, now=NOW) == kept[name]
    assert len([a for a in ledger.assets.values() if a.get("status") == "active"]) == 2


def test_hardeningkitty_win_dc01_is_host_not_principal() -> None:
    recs = identity_ad.parse_file(DEMO / "identity" / "hardeningkitty.csv")
    host = next(r for r in recs if r["kind"] == "asset")
    assert host["name"] == "win-dc01"
    assert host["category"] == "host"
    assert (host.get("extra") or {}).get("asset_type") == "PR"
    assert (host.get("extra") or {}).get("tool") == "hardeningkitty"
    ids = ids_from_record(host)
    assert not ids.get("principal")
    assert ids.get("hostname") == "win-dc01"


def test_hardeningkitty_and_nmap_win_dc01_share_ega() -> None:
    """Metis: master 1 EGA, #174-before-fix 2 (HK misclassed as principal)."""
    hk = next(
        r
        for r in identity_ad.parse_file(DEMO / "identity" / "hardeningkitty.csv")
        if r["kind"] == "asset"
    )
    nmap = make_record(
        kind="asset",
        source="inventory-nmap",
        ref_id="NMAP-win-dc01",
        name="win-dc01",
        category="host",
        assets=["win-dc01"],
        collected_at=NOW,
        extra={"asset_type": "PR", "hostname": "win-dc01", "ip": "10.0.0.10"},
    )
    ledger = AssetLedger()
    attached = attach_asset_uids([hk, nmap], ledger, now=NOW)
    assets = [r for r in attached if r["kind"] == "asset"]
    uids = {str((r.get("extra") or {}).get("asset_uid") or "") for r in assets}
    assert len(uids) == 1
    uid = next(iter(uids))
    assert uid in ledger.assets
    ids = ledger._ids_of(ledger.assets[uid])
    assert not ids.get("principal")
    assert "10.0.0.10" in (ids.get("ip") or [])


def test_demo_identity_upgrade_does_not_mint_principal_twins() -> None:
    """Master-era hostname/name aliases must absorb the new principal stamp."""
    recs: list[dict] = []
    recs.extend(identity_ad.parse_file(DEMO / "identity" / "bloodhound.json"))
    recs.extend(identity_ad.parse_file(DEMO / "identity" / "hardeningkitty.csv"))
    assets = [r for r in recs if r.get("kind") == "asset"]
    assert assets

    fresh = AssetLedger()
    fresh_n = len({fresh.observe(r, now=NOW) for r in assets})

    upgrade = AssetLedger()
    seeded: set[str] = set()
    for rec in assets:
        ids = ids_from_record(rec)
        token = str(ids.get("principal") or "").strip()
        if not token:
            continue
        typ = "name" if (" " in token or "@" in token) else "hostname"
        seeded.add(_seed_pre_principal(upgrade, token, typ=typ))
    before = {
        str(a["asset_uid"])
        for a in upgrade.assets.values()
        if a.get("status") == "active"
    }
    for rec in assets:
        uid = upgrade.observe(rec, now=NOW)
        ids = ids_from_record(rec)
        if ids.get("principal"):
            assert uid in seeded
    upgrade.late_merge_pass(now=NOW)
    after = {
        str(a["asset_uid"])
        for a in upgrade.assets.values()
        if a.get("status") == "active"
    }
    minted = after - before
    assert not (minted & seeded)
    assert len(after) == fresh_n
