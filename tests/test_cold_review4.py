"""Cold review #4 items 4–7: ledger carry, stable IDs, asset identity, timestamps."""

from __future__ import annotations

import csv
import importlib
import json
from datetime import datetime, timezone
from pathlib import Path

from shared.asset_ids import classify_name, is_placeholder_id
from shared.asset_key import legacy_name_asset_key
from shared.asset_ledger import AssetLedger, asset_uid
from shared.kev import KevCatalog
from shared.poam_ledger import (
    apply_ledger,
    empty_ledger,
    fp_v1,
    item_maps_to_current,
    legacy_title_weakness_key,
    migrate_finding_refs,
    payload_sha256,
    weakness_key,
)
from shared.scan_time import extra_scan_raw, format_detection_date
from shared.schema import make_record, make_ref

NOW = "2026-09-01T00:00:00Z"


def _unevaluated() -> KevCatalog:
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _run(when: str) -> datetime:
    return datetime.fromisoformat(when.replace("Z", "+00:00"))


def _nmap_port(
    host: str,
    port: str,
    proto: str = "tcp",
    *,
    service: str = "unknown",
    title: str | None = None,
    check_id: str | None = None,
    ref: str | None = None,
    extra: dict | None = None,
) -> dict:
    blob = {
        "port": port,
        "protocol": proto,
        "service": service,
        "tool": "nmap",
        "ip": host if host[0].isdigit() else "",
    }
    if check_id:
        blob["check_id"] = check_id
    if extra:
        blob.update(extra)
    return {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": ref or make_ref("inventory-nmap", f"{host}-{port}/{proto}"),
        "name": title or f"Open port {port}/{service}",
        "description": "fixture",
        "severity": "high",
        "category": "exposure",
        "assets": [host],
        "labels": ["nmap"],
        "collected_at": NOW,
        "extra": blob,
    }


def test_migrate_finding_refs_nmap_slug() -> None:
    assert "NMAP-filesrv-445-tcp" in migrate_finding_refs("NMAP-filesrv-445")
    assert "NMAP-filesrv-445" in migrate_finding_refs("NMAP-filesrv-445-tcp")


def test_weakness_key_prefers_check_id_not_title_or_service() -> None:
    kerb_sec = _nmap_port(
        "10.0.0.5",
        "88",
        service="kerberos-sec",
        title="kerberos-sec 88/tcp",
        check_id="nmap-port-88/tcp",
    )
    kerb = _nmap_port(
        "10.0.0.5",
        "88",
        service="kerberos",
        title="kerberos 88/tcp",
        check_id="nmap-port-88/tcp",
    )
    assert weakness_key(kerb_sec) == weakness_key(kerb) == "nmap:nmap-port-88/tcp"
    titled = _nmap_port(
        "10.0.0.5",
        "445",
        service="microsoft-ds",
        title="SMB 445 exposed",
        check_id="nmap-port-445/tcp",
    )
    renamed = {**titled, "name": "SMB exposed on TCP/445"}
    assert weakness_key(titled) == weakness_key(renamed)


def test_weakness_key_strips_host_from_share_title() -> None:
    ip_row = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-10-0-0-50-share-c",
        "name": "Writable SMB share C$ on 10.0.0.50",
        "severity": "high",
        "category": "exposure",
        "assets": ["10.0.0.50"],
        "extra": {"port": "445", "share": "C$", "ip": "10.0.0.50", "tool": "nmap"},
    }
    host_row = {
        **ip_row,
        "name": "Writable SMB share C$ on FILESRV",
        "assets": ["FILESRV"],
        "extra": {**ip_row["extra"], "ip": "10.0.0.50"},
    }
    assert weakness_key(ip_row) == weakness_key(host_row) == "nmap:share:c$"


def test_item_maps_to_current_via_ref_migration() -> None:
    item = {"poam_id": "EGP-OLD445000", "ref_id": "NMAP-filesrv-445", "fp": "abc"}
    assert item_maps_to_current(
        item,
        listed_ids=set(),
        observed_refs={"NMAP-filesrv-445-tcp"},
        observed_fps=set(),
    )
    assert not item_maps_to_current(
        item,
        listed_ids=set(),
        observed_refs={"NMAP-other-22-tcp"},
        observed_fps=set(),
    )


def test_old_ledger_slug_change_zero_ghost_rows(tmp_path: Path, monkeypatch) -> None:
    """1f8d347-style ``-445`` ledger + current ``-445-tcp`` → 0 ghost rows."""
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    incoming = tmp_path / "in"
    incoming.mkdir()
    rec = _nmap_port(
        "filesrv.corp.local",
        "445",
        service="microsoft-ds",
        title="SMB 445 exposed",
        check_id="nmap-port-445/tcp",
        extra={"scan_time": "2026-07-02T00:00:00Z"},
    )
    new_fp = fp_v1(rec)
    old_ref = "NMAP-filesrv-445"
    old_rec = {**rec, "ref_id": old_ref, "extra": {k: v for k, v in rec["extra"].items() if k != "check_id"}}
    old_fp = fp_v1(old_rec, weakness_key_fn=legacy_title_weakness_key)
    seeded = empty_ledger()
    seeded["items"] = {
        old_fp: {
            "poam_id": "EGP-KEEP44501",
            "fp": old_fp,
            "source_family": "inventory-nmap",
            "weakness_key": legacy_title_weakness_key(old_rec),
            "asset_key": legacy_name_asset_key(old_rec),
            "ref_id": old_ref,
            "name": "SMB 445 exposed",
            "description": "old title",
            "original_detection_date": "2026-07-02",
            "first_seen": "2026-07-02T00:00:00Z",
            "status": "open",
            "severity": "high",
            "missed_covered_runs": 0,
            "kev_comments": [],
        }
    }
    seeded["sha256"] = payload_sha256(seeded)
    dest = incoming / "poam"
    dest.mkdir()
    (dest / "poam-ledger.json").write_text(json.dumps(seeded), encoding="utf-8")
    with (out / "canonical" / "x.jsonl").open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
        fh.write(
            json.dumps(
                {
                    "kind": "asset",
                    "source": "inventory-nmap",
                    "ref_id": "NMAP-asset-filesrv",
                    "name": "filesrv.corp.local",
                    "description": "host",
                    "severity": "info",
                    "category": "host",
                    "assets": ["filesrv.corp.local"],
                    "labels": ["nmap"],
                    "collected_at": NOW,
                    "extra": {"fqdn": "filesrv.corp.local"},
                }
            )
            + "\n"
        )
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(incoming))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary.get("pending_carried") == 0
    with (out / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["poam_id"] == "EGP-KEEP44501"
    assert rows[0]["original_detection_date"] == "2026-07-02"
    ledger = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    assert new_fp in ledger["items"]
    assert ledger["items"][new_fp]["poam_id"] == "EGP-KEEP44501"
    assert ledger["items"][new_fp]["original_detection_date"] == "2026-07-02"


def test_classify_upn_is_principal_not_fqdn() -> None:
    got = classify_name("ga@contoso.onmicrosoft.com")
    assert got.get("principal") == "ga@contoso.onmicrosoft.com"
    assert "fqdn" not in got


def test_name_only_keys_are_account_scoped() -> None:
    a = make_record(
        kind="asset",
        source="cloud-prowler",
        ref_id="CLD-sg-a",
        name="sg-default",
        category="cloud-resource",
        assets=["sg-default"],
        extra={"account_id": "111111111111", "region": "us-east-1"},
    )
    b = make_record(
        kind="asset",
        source="cloud-prowler",
        ref_id="CLD-sg-b",
        name="sg-default",
        category="cloud-resource",
        assets=["sg-default"],
        extra={"account_id": "222222222222", "region": "us-east-1"},
    )
    assert asset_uid(a) != asset_uid(b)


def test_web01_fqdn_ip_merge_when_evidence_links() -> None:
    ledger = AssetLedger()
    host = make_record(
        kind="asset",
        source="inventory-nmap",
        ref_id="NMAP-web01",
        name="web01",
        category="host",
        assets=["web01"],
        extra={"hostname": "web01"},
        collected_at=NOW,
    )
    fqdn = make_record(
        kind="asset",
        source="inventory-nmap",
        ref_id="NMAP-web01-fqdn",
        name="web01.corp.local",
        category="host",
        assets=["web01.corp.local"],
        extra={"fqdn": "web01.corp.local", "ip": "10.0.0.5"},
        collected_at=NOW,
    )
    ip = make_record(
        kind="asset",
        source="vuln-scan",
        ref_id="VULN-ip",
        name="10.0.0.5",
        category="host",
        assets=["10.0.0.5"],
        extra={"ip": "10.0.0.5"},
        collected_at=NOW,
    )
    u1 = ledger.observe(host, now=NOW)
    u2 = ledger.observe(fqdn, now=NOW)
    u3 = ledger.observe(ip, now=NOW)
    ledger.late_merge_pass(now=NOW)
    keep = {ledger.assets[u]["merged_into"] or u for u in (u1, u2, u3)}
    assert len(keep) == 1


def test_jenkins_user_host_principal_stay_distinct() -> None:
    user = make_record(
        kind="asset",
        source="saas-idp",
        ref_id="SAAS-jenkins",
        name="jenkins",
        category="identity",
        assets=["jenkins"],
        extra={"tenant": "okta-prod"},
    )
    host = make_record(
        kind="asset",
        source="inventory-nmap",
        ref_id="NMAP-jenkins",
        name="jenkins",
        category="host",
        assets=["jenkins"],
        extra={"hostname": "jenkins"},
    )
    principal = make_record(
        kind="asset",
        source="identity-ad",
        ref_id="ID-jenkins",
        name="jenkins@corp.local",
        category="identity",
        assets=["jenkins@corp.local"],
    )
    assert len({asset_uid(user), asset_uid(host), asset_uid(principal)}) == 3


def test_placeholder_id_helper() -> None:
    assert is_placeholder_id("<resource_uid>")
    assert is_placeholder_id("arn:aws:iam::<account_uid>:root")
    assert not is_placeholder_id("arn:aws:s3:::bucket")


def test_scan_time_ocsf_and_timestamp_keys() -> None:
    prowler = {
        "extra": {
            "finding_info": {"created_time": "2024-02-14T14:27:03Z"},
        }
    }
    greenbone = {"extra": {"Timestamp": "2023-09-28T14:48:02Z"}}
    scuba = {"extra": {"TimestampZulu": "2024-03-20T18:42:05.043Z"}}
    testssl = {"extra": {"scanTime": "2025-01-02T03:04:05Z"}}
    assert extra_scan_raw(prowler) == "2024-02-14T14:27:03Z"
    assert extra_scan_raw(greenbone) == "2023-09-28T14:48:02Z"
    assert extra_scan_raw(scuba) == "2024-03-20T18:42:05.043Z"
    assert extra_scan_raw(testssl) == "2025-01-02T03:04:05Z"
    assert format_detection_date(extra_scan_raw(prowler)) == "2024-02-14"


def test_ledger_lost_does_not_stick() -> None:
    rec = _nmap_port("10.0.0.9", "22", check_id="nmap-port-22/tcp")
    first = apply_ledger(
        [rec],
        catalog=_unevaluated(),
        run_at=_run("2026-09-10T00:00:00Z"),
        prior_existed=False,
    )
    assert "LEDGER_LOST" in first["warnings"]
    second = apply_ledger(
        [rec],
        catalog=_unevaluated(),
        run_at=_run("2026-09-11T00:00:00Z"),
        ledger_in=first,
        prior_existed=True,
    )
    assert "LEDGER_LOST" not in second["warnings"]
