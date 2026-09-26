"""Cold review #4 items 4–7: ledger carry, stable IDs, asset identity, timestamps."""

from __future__ import annotations

import csv
import importlib
import json
from datetime import datetime, timezone
from pathlib import Path

from shared.asset_ids import classify_name, is_placeholder_id, stamp_ids
from shared.asset_key import legacy_name_asset_key
from shared.asset_ledger import AssetLedger, asset_uid, attach_asset_uids
from shared.kev import KevCatalog
from shared.poam_ledger import (
    _is_scanner_identity,
    apply_ledger,
    empty_ledger,
    fingerprints_for,
    fp_v1,
    item_maps_to_current,
    legacy_master_asset_key,
    legacy_master_weakness_key,
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
    ledger = AssetLedger()
    u1 = ledger.observe(user, now=NOW)
    u2 = ledger.observe(host, now=NOW)
    u3 = ledger.observe(principal, now=NOW)
    ledger.late_merge_pass(now=NOW)
    keep = {ledger.assets[u].get("merged_into") or u for u in (u1, u2, u3)}
    assert len(keep) == 3


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


def test_scanner_ids_are_accepted_not_titles() -> None:
    samples = (
        ("lynis", "FIRE-4590", "host-wazuh"),
        ("lynis", "SSH-7408", "host-wazuh"),
        ("k8s", "C-0013", "k8s-kubescape"),
        ("trivy", "KSV-0017", "code-secrets"),
        ("trivy", "AVD-AWS-0086", "code-secrets"),
        ("trivy", "DS-0002", "code-secrets"),
        ("oscap", "V-230221", "host-wazuh"),
        ("greenbone", "1.3.6.1.4.1.25623.1.0.103234", "vuln-scan"),
    )
    for tool, check, source in samples:
        assert _is_scanner_identity(check), check
        rec = {
            "source": source,
            "name": f"{tool} {check}: pass-sounding title",
            "assets": ["host-a"],
            "extra": {"id": check, "check_id": check, "tool": tool},
        }
        assert weakness_key(rec) == f"{tool}:{check}"
        assert not weakness_key(rec).startswith("name:")


def test_scanner_identity_denylist() -> None:
    assert not _is_scanner_identity("kerberos-sec")
    assert not _is_scanner_identity("obs-12")
    assert not _is_scanner_identity("10.0.0.50-445")
    assert not _is_scanner_identity("filesrv-445-tcp")
    assert not _is_scanner_identity("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    # pack_drop lift keys are not plugin/check ids (Argus B5).
    assert not _is_scanner_identity("nmap-10-microsoftds-445")
    assert not _is_scanner_identity("nmap-l10-ssh-22")
    assert not _is_scanner_identity("rustscan-7-tcp-80")
    assert _is_scanner_identity("nmap-port-445/tcp")
    assert _is_scanner_identity("AVD-AWS-0086")


def test_distinct_findings_on_one_asset_do_not_share_id() -> None:
    a = {
        "source": "identity-ad",
        "name": "AS-REP roastable",
        "assets": ["ga@contoso.onmicrosoft.com"],
        "extra": {"id": "ASREPRoasting", "tool": "bloodhound", "objectid": "S-1-5-21-aaa"},
    }
    b = {
        "source": "identity-ad",
        "name": "AS-REP roastable admin",
        "assets": ["ga@contoso.onmicrosoft.com"],
        "extra": {"id": "ASREPRoastable", "tool": "bloodhound", "objectid": "S-1-5-21-bbb"},
    }
    assert weakness_key(a) != weakness_key(b)
    assert fp_v1(a) != fp_v1(b)
    port_a = {
        "source": "inventory-nmap",
        "name": "Admin interface",
        "assets": ["10.0.0.9"],
        "extra": {"port": "443", "protocol": "tcp", "nse_script": "http-auth", "tool": "nmap"},
    }
    port_b = {
        "source": "inventory-nmap",
        "name": "TLS expired",
        "assets": ["10.0.0.9"],
        "extra": {"port": "443", "protocol": "tcp", "nse_script": "ssl-cert", "tool": "nmap"},
    }
    assert weakness_key(port_a) != weakness_key(port_b)


def test_pre161_upgrade_zero_new_ids_no_ghost_open() -> None:
    """Master-keyed ledger → head: 0 created IDs, Open count unchanged."""
    recs = [
        {
            "source": "host-wazuh",
            "ref_id": "WAZ-lynis-FIRE-4590",
            "name": "Lynis FIRE-4590: No firewall software installed",
            "severity": "high",
            "assets": ["web-01"],
            "extra": {"id": "FIRE-4590", "check_id": "FIRE-4590", "tool": "lynis"},
        },
        {
            "source": "k8s-kubescape",
            "ref_id": "K8S-c-0013-prod-cluster",
            "name": "Anonymous Kubernetes API access",
            "severity": "critical",
            "assets": ["prod-cluster"],
            "extra": {"id": "C-0013", "check_id": "C-0013", "tool": "k8s"},
        },
        {
            "source": "vuln-scan",
            "ref_id": "VULN-heartbleed",
            "name": "OpenSSL Heartbleed",
            "severity": "critical",
            "assets": ["app.corp.local"],
            "extra": {
                "id": "1.3.6.1.4.1.25623.1.0.103234",
                "tool": "greenbone",
                "cve": "CVE-2014-0160",
            },
        },
        {
            "source": "identity-ad",
            "ref_id": "ID-dcsync",
            "name": "BloodHound DCSync",
            "severity": "critical",
            "assets": ["ga@contoso.onmicrosoft.com"],
            "extra": {"tool": "bloodhound"},
        },
        {
            "source": "cloud-prowler",
            "ref_id": "CLD-s3-public",
            "name": "S3 bucket prohibits public access",
            "severity": "high",
            "assets": ["demo-public-assets"],
            "extra": {"id": "s3_bucket_public", "tool": "prowler", "account_id": "111111111111"},
        },
    ]
    seeded = empty_ledger()
    old_ids: list[str] = []
    for i, rec in enumerate(recs, start=1):
        old_fp = fp_v1(
            rec,
            asset_key_fn=legacy_master_asset_key,
            weakness_key_fn=legacy_master_weakness_key,
        )
        pid = f"EGP-KEEP{i:04d}XX"
        old_ids.append(pid)
        seeded["items"][old_fp] = {
            "poam_id": pid,
            "fp": old_fp,
            "source_family": rec["source"],
            "weakness_key": legacy_master_weakness_key(rec),
            "asset_key": legacy_master_asset_key(rec),
            "ref_id": rec["ref_id"],
            "name": rec["name"],
            "original_detection_date": "2024-01-15",
            "first_seen": "2024-01-15T00:00:00Z",
            "status": "open",
            "severity": rec["severity"],
            "missed_covered_runs": 0,
            "kev_comments": [],
        }
    seeded["sha256"] = payload_sha256(seeded)
    out = apply_ledger(
        recs,
        catalog=_unevaluated(),
        run_at=_run("2026-09-20T00:00:00Z"),
        ledger_in=seeded,
        prior_existed=True,
    )
    created = [e for e in (out.get("events_this_run") or []) if e.get("kind") == "created"]
    assert created == []
    open_items = [it for it in out["items"].values() if str(it.get("status") or "") != "closed"]
    assert len(open_items) == len(recs)
    assert {it["poam_id"] for it in open_items} == set(old_ids)
    assert all(it.get("original_detection_date") == "2024-01-15" for it in open_items)
    assert all(m.get("from") != m.get("to") for m in (out.get("fp_migrations") or []))


def test_asset_upn_and_cloud_name_reclass_keep_uid() -> None:
    from shared.asset_ledger import AssetLedger, make_asset_uid

    ledger = AssetLedger()
    upn = "ga@contoso.onmicrosoft.com"
    old_upn = make_record(
        kind="asset",
        source="saas-idp",
        ref_id="SAAS-ga-old",
        name=upn,
        category="identity",
        assets=[upn],
        extra={"ids": {"fqdn": upn}},
        collected_at=NOW,
    )
    old_uid = ledger.observe(old_upn, now=NOW)
    assert old_uid == make_asset_uid("fqdn", upn)
    new_upn = make_record(
        kind="asset",
        source="saas-idp",
        ref_id="SAAS-ga-new",
        name=upn,
        category="identity",
        assets=[upn],
        collected_at=NOW,
    )
    assert ledger.observe(new_upn, now=NOW) == old_uid

    old_cloud = make_record(
        kind="asset",
        source="k8s-kubescape",
        ref_id="K8S-cluster-old",
        name="prod-cluster",
        category="cluster",
        assets=["prod-cluster"],
        extra={"hostname": "prod-cluster"},
        collected_at=NOW,
    )
    cloud_uid = ledger.observe(old_cloud, now=NOW)
    new_cloud = make_record(
        kind="asset",
        source="k8s-kubescape",
        ref_id="K8S-cluster-new",
        name="prod-cluster",
        category="cluster",
        assets=["prod-cluster"],
        collected_at=NOW,
    )
    assert ledger.observe(new_cloud, now=NOW) == cloud_uid


def test_lab_sh_does_not_copy_ledger_into_in() -> None:
    text = Path(__file__).resolve().parents[1].joinpath("scripts/lab.sh").read_text(encoding="utf-8")
    assert "in/poam" not in text
    assert "asset-ledger.json" not in text


def test_ledger_files_do_not_count_as_live_inputs(tmp_path: Path, monkeypatch) -> None:
    from shared.io_util import SKIP_INPUT_NAMES, in_dir_has_live_inputs

    assert "poam-ledger.json" in SKIP_INPUT_NAMES
    assert "AUTHORIZATION.txt" in SKIP_INPUT_NAMES
    assert "AUTHORIZATION.md" in SKIP_INPUT_NAMES
    assert "AUTH.txt" in SKIP_INPUT_NAMES
    dest = tmp_path / "in"
    (dest / "poam").mkdir(parents=True)
    (dest / "poam" / "poam-ledger.json").write_text("{}", encoding="utf-8")
    (dest / "assets").mkdir()
    (dest / "assets" / "asset-ledger.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("IN_DIR", str(dest))
    assert in_dir_has_live_inputs() is False


def test_scan_time_epoch_ms_and_ignores_creation_time() -> None:
    from shared.scan_time import extra_scan_raw, format_detection_date, parse_scan_datetime

    parsed = parse_scan_datetime(1_700_000_000_000)
    assert parsed is not None
    assert parsed[0].year == 2023
    only_created = {"extra": {"CreationTime": "2018-01-01T00:00:00Z", "creation_time": "2018-01-01T00:00:00Z"}}
    assert extra_scan_raw(only_created) in (None, "")
    assert format_detection_date(extra_scan_raw(only_created)) == "not recorded"


def test_saas_inventory_rows_keep_distinct_keys() -> None:
    mfa = {
        "source": "saas-idp",
        "name": "MFA not registered",
        "assets": ["bob@contoso.onmicrosoft.com"],
        "extra": {"mfa_registered": False, "roles": ["User"]},
    }
    ga = {
        "source": "saas-idp",
        "name": "Standing Global Administrator",
        "assets": ["ga@contoso.onmicrosoft.com"],
        "extra": {"role": "Global Administrator", "pim_eligible": False},
    }
    policy = {
        "source": "saas-idp",
        "name": "Okta admin MFA gap",
        "assets": ["example.okta.com"],
        "extra": {"policy": "pol-mfa-admins"},
    }
    assert len({weakness_key(mfa), weakness_key(ga), weakness_key(policy)}) == 3
    assert "unkeyed" not in weakness_key(mfa)
    assert "unkeyed" not in weakness_key(ga)
    first = apply_ledger(
        [mfa, ga, policy],
        catalog=_unevaluated(),
        run_at=_run("2026-09-20T00:00:00Z"),
        prior_existed=False,
    )
    second = apply_ledger(
        [mfa, ga, policy],
        catalog=_unevaluated(),
        run_at=_run("2026-09-21T00:00:00Z"),
        ledger_in=first,
        prior_existed=True,
    )
    created = [e for e in (second.get("events_this_run") or []) if e.get("kind") == "created"]
    assert created == []
    assert len(second["items"]) == len(first["items"]) == 3


def test_fingerprints_for_includes_master_alias() -> None:
    rec = {
        "source": "host-wazuh",
        "name": "Lynis FIRE-4590: No firewall software installed",
        "assets": ["web-01"],
        "extra": {"id": "FIRE-4590", "check_id": "FIRE-4590", "tool": "lynis"},
    }
    master_fp = fp_v1(
        rec,
        asset_key_fn=legacy_master_asset_key,
        weakness_key_fn=legacy_master_weakness_key,
    )
    assert master_fp in fingerprints_for(rec)


def test_legacy_master_asset_key_uses_first_asset_not_title() -> None:
    """Finding titles must not classify as NetBIOS and steal the host EGA."""
    from shared.asset_ledger import make_asset_uid

    k8s = {
        "source": "k8s-kubescape",
        "name": "Write below binary dir",
        "assets": ["prod-cluster"],
        "extra": {"rule": "Write below binary dir"},
    }
    assert legacy_master_asset_key(k8s) == make_asset_uid("hostname", "prod-cluster")
    upn = {
        "source": "identity-ad",
        "name": "BloodHound GenericAll",
        "assets": ["HELPDESK@CORP.LOCAL"],
        "extra": {"edge": "GenericAll"},
    }
    assert legacy_master_asset_key(upn) == make_asset_uid("fqdn", "helpdesk@corp.local")
    saas = {
        "source": "saas-idp",
        "name": "MFA not registered",
        "assets": ["bob@contoso.onmicrosoft.com"],
        "extra": {"mfa_registered": False},
    }
    assert legacy_master_asset_key(saas) == make_asset_uid(
        "fqdn", "bob@contoso.onmicrosoft.com"
    )


def test_no_check_id_fallback_keeps_record_and_stage_distinct() -> None:
    domain = "mail.example.invalid"
    spf = {
        "source": "dns-email",
        "name": f"SPF softfail-only on {domain}",
        "assets": [domain],
        "extra": {"finding_id": "spf_softfail_only", "lane": "email_dns"},
    }
    dmarc = {
        "source": "dns-email",
        "name": f"DMARC missing on {domain}",
        "assets": [domain],
        "extra": {"finding_id": "dmarc_missing", "lane": "email_dns"},
    }
    dkim = {
        "source": "dns-email",
        "name": f"DKIM selector s1 missing on {domain}",
        "assets": [domain],
        "extra": {"finding_id": "dkim_missing-s1", "selector": "s1", "lane": "email_dns"},
    }
    assert len({weakness_key(spf), weakness_key(dmarc), weakness_key(dkim)}) == 3
    assert "unkeyed" not in weakness_key(spf)
    host = "ssh-canary-01"
    s1 = {
        "source": "honeypot",
        "name": f"Deception-sensor stage-1 hit on {host}",
        "assets": [host],
        "extra": {"stage": 1, "event": "hit", "family": "palisade"},
    }
    s2 = {
        "source": "honeypot",
        "name": f"Deception-sensor stage-2 hit on {host}",
        "assets": [host],
        "extra": {"stage": 2, "event": "hit", "family": "palisade"},
    }
    sess = {
        "source": "honeypot",
        "name": f"Deception-sensor session abc on {host}",
        "assets": [host],
        "extra": {"stage": 1, "event": "session", "family": "palisade"},
    }
    assert len({weakness_key(s1), weakness_key(s2), weakness_key(sess)}) == 3
    waz_agent = {
        "source": "host-wazuh",
        "name": "Wazuh agent disconnected",
        "assets": ["web-01"],
        "extra": {"agent_status": "disconnected"},
    }
    waz_disk = {
        "source": "host-wazuh",
        "name": "Disk encryption disabled",
        "assets": ["web-01"],
        "extra": {"disk_encryption_enabled": False},
    }
    assert weakness_key(waz_agent) != weakness_key(waz_disk)
    easm_path = {
        "source": "easm",
        "name": "Admin path exposed",
        "assets": ["legacy.corp.local"],
        "extra": {"path": "/admin/", "url": "https://legacy.corp.local/admin/"},
    }
    easm_host = {
        "source": "easm",
        "name": "Sensitive hostname",
        "assets": ["legacy.corp.local"],
        "extra": {"page_type": "hostname", "url": "https://legacy.corp.local/"},
    }
    assert weakness_key(easm_path) != weakness_key(easm_host)
    # Same title, two URL shapes — stay distinct (Metis #161 follow-up).
    easm_a = {
        "source": "easm",
        "name": "Exposed admin interface on admin.example.com",
        "assets": ["admin.example.com"],
        "extra": {"path": "/login", "url": "https://admin.example.com/login"},
    }
    easm_b = {
        "source": "easm",
        "name": "Exposed admin interface on admin.example.com",
        "assets": ["admin.example.com"],
        "extra": {"path": "https://admin.example.com", "url": "https://admin.example.com"},
    }
    assert weakness_key(easm_a) != weakness_key(easm_b)
    from shared.poam_ledger import legacy_pre_location_weakness_key

    assert legacy_pre_location_weakness_key(easm_a) == legacy_pre_location_weakness_key(
        easm_b
    )


def test_trivy_two_secrets_weakness_keys_stay_distinct() -> None:
    a = {
        "source": "vuln-scan",
        "name": "AWS Access Key ID",
        "assets": ["deploy.sh"],
        "labels": ["trivy"],
        "extra": {
            "rule": "aws-access-key-id",
            "check_id": "aws-access-key-id",
            "class": "secret",
            "tool": "trivy",
        },
    }
    b = {
        "source": "vuln-scan",
        "name": "My Secret",
        "assets": ["deploy.sh"],
        "labels": ["trivy"],
        "extra": {
            "rule": "generic-secret",
            "check_id": "generic-secret",
            "class": "secret",
            "tool": "trivy",
        },
    }
    assert weakness_key(a) != weakness_key(b)
    assert "unkeyed" not in weakness_key(a)
    assert weakness_key(a) == "trivy:aws-access-key-id"
    assert weakness_key(b) == "trivy:generic-secret"


def test_trivy_cve_rows_stay_on_cve_key() -> None:
    rec = {
        "source": "vuln-scan",
        "name": "xz-utils supply chain backdoor",
        "ref_id": "VULN-CVE-2024-3094-app",
        "assets": ["app:latest"],
        "labels": ["trivy"],
        "extra": {
            "cve": "CVE-2024-3094",
            "pkg": "xz-utils",
            "class": "vuln",
            "tool": "trivy",
        },
    }
    assert weakness_key(rec) == "cve:CVE-2024-3094"
    assert not rec["extra"].get("check_id")
    master_fp = fp_v1(
        rec,
        asset_key_fn=legacy_master_asset_key,
        weakness_key_fn=legacy_master_weakness_key,
    )
    assert master_fp in fingerprints_for(rec)


def test_netbios_ns_pod_reclass_keeps_uid() -> None:
    from shared.asset_ledger import AssetLedger, make_asset_uid

    ledger = AssetLedger()
    name = "test/test-pod-1"
    old = make_record(
        kind="asset",
        source="k8s-kubescape",
        ref_id="K8S-pod-old",
        name=name,
        category="workload",
        assets=[name],
        extra={"ids": {"netbios": "TEST/TEST-POD-1"}},
        collected_at=NOW,
    )
    old_uid = ledger.observe(old, now=NOW)
    assert old_uid == make_asset_uid("netbios", "TEST/TEST-POD-1")
    new = make_record(
        kind="asset",
        source="k8s-kubescape",
        ref_id="K8S-pod-new",
        name=name,
        category="workload",
        assets=[name],
        collected_at=NOW,
    )
    assert ledger.observe(new, now=NOW) == old_uid


def test_demo_fedramp_open_matches_poam(tmp_path: Path, monkeypatch) -> None:
    from tests.test_poam_breakdown import _run_lab

    _run_lab(tmp_path, monkeypatch)
    poam = tmp_path / "poam" / "poam.csv"
    fed = tmp_path / "poam" / "poam_fedramp.csv"
    assert fed.is_file()
    with poam.open(encoding="utf-8", newline="") as fh:
        plan = list(csv.DictReader(fh))
    with fed.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    plan_ids = {r.get("poam_id") or "" for r in plan if r.get("poam_id")}
    fed_ids = {r.get("POAM ID") or "" for r in rows if r.get("POAM ID")}
    assert fed_ids == plan_ids
    assert len(rows) == len(plan_ids)
    # #177 fixed DEMO dup-row remints; Open is still unique poam.csv IDs.
    assert len(plan_ids) <= len(plan)


def _farm_drop_out(tmp_path: Path) -> Path:
    import os
    import subprocess

    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "farm_drop_to_sor.sh"
    work = tmp_path / "farm-work"
    proc = subprocess.run(
        ["bash", str(script), "--work", str(work)],
        check=False,
        cwd=root,
        env={
            **os.environ,
            "PYTHONPATH": str(root),
            "DRY_RUN": "1",
            "GRC_LIVE_SCAN": "0",
            "CISO_PUSH": "0",
            "RISKREADY_PUSH": "0",
            "DROPBOX_LIVE": "0",
        },
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return work / "out"


def test_farm_fedramp_open_matches_poam(tmp_path: Path) -> None:
    out = _farm_drop_out(tmp_path)
    poam = out / "poam" / "poam.csv"
    fed = out / "poam" / "poam_fedramp.csv"
    assert fed.is_file()
    with poam.open(encoding="utf-8", newline="") as fh:
        plan = list(csv.DictReader(fh))
    with fed.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    plan_ids = {r.get("poam_id") or "" for r in plan if r.get("poam_id")}
    fed_ids = {r.get("POAM ID") or "" for r in rows if r.get("POAM ID")}
    assert fed_ids == plan_ids
    assert len(rows) == len(plan_ids)


def test_farm_fedramp_open_stays_109(tmp_path: Path) -> None:
    """#180 farm lock: pack_drop fold leaves farm ledger Open at 109.

    FedRAMP Open follows unique poam.csv IDs (#179), so this locks the
    ledger, not a fat export dump.
    """
    out = _farm_drop_out(tmp_path)
    ledger = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    open_items = [
        it for it in (ledger.get("items") or {}).values() if str(it.get("status") or "") != "closed"
    ]
    assert len(open_items) == 109, f"farm ledger Open={len(open_items)} expected 109"


def test_master_demo_ledger_upgrade_splits_admin_url_zero_ghosts(
    tmp_path: Path, monkeypatch
) -> None:
    """master→this-branch: first Exposed-admin URL keeps its EGP; sibling is new.

    #170: upgrade must not stay at 126 — the newly discriminated /login
    (or apex) URL is tracked. 0 ghosts. FedRAMP Open follows unique
    poam.csv IDs, not the full ledger (#179).
    """
    from tests.test_poam_breakdown import _run_lab

    prior = json.loads(
        Path(__file__).resolve().parent.joinpath(
            "fixtures", "demo-poam-ledger-master.json"
        ).read_text(encoding="utf-8")
    )
    prior_ids = {it["poam_id"] for it in prior["items"].values()}
    assert len(prior_ids) == 126
    (tmp_path / "poam").mkdir(parents=True, exist_ok=True)
    (tmp_path / "poam" / "poam-ledger.json").write_text(
        json.dumps(prior, indent=2) + "\n", encoding="utf-8"
    )
    summary = _run_lab(tmp_path, monkeypatch)
    ledger = json.loads((tmp_path / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    created = [
        e for e in (ledger.get("events_this_run") or []) if e.get("kind") == "created"
    ]
    open_items = [
        it for it in ledger["items"].values() if str(it.get("status") or "") != "closed"
    ]
    with (tmp_path / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        fed_rows = list(csv.DictReader(fh))
    with (tmp_path / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        plan_rows = list(csv.DictReader(fh))
    reseen_ids = {it["poam_id"] for it in open_items}
    ghosts = prior_ids - reseen_ids
    plan_ids = {r.get("poam_id") or "" for r in plan_rows if r.get("poam_id")}
    fed_ids = {r.get("POAM ID") or "" for r in fed_rows if r.get("POAM ID")}
    new_ids = reseen_ids - prior_ids
    assert ghosts == set(), f"ghosts {sorted(ghosts)}"
    assert len(created) == 1, [e.get("poam_id") for e in created]
    assert {e.get("poam_id") for e in created} == new_ids
    assert len(open_items) == 127
    assert fed_ids == plan_ids
    assert len(fed_rows) == len(plan_ids)
    assert prior_ids <= reseen_ids
    admin_rows = [
        it
        for it in open_items
        if str(it.get("name") or "").startswith("Exposed admin interface on")
    ]
    assert len(admin_rows) == 2
    assert len({it["poam_id"] for it in admin_rows}) == 2
    assert summary.get("demo") is True


def test_7ebc697_demo_ledger_upgrade_zero_dup_opens_one_new(
    tmp_path: Path, monkeypatch
) -> None:
    """Upgrade a 7ebc697 DEMO ledger: 0 duplicate opens, 1 new (#170 split), 127 open.

    Pre-#172 title-keyed host-less Wazuh rows rematch. The #170 admin URL
    sibling is the only mint. No ghosts.
    """
    from tests.test_poam_breakdown import _run_lab

    prior = json.loads(
        Path(__file__).resolve().parent.joinpath(
            "fixtures", "demo-poam-ledger-7ebc697.json"
        ).read_text(encoding="utf-8")
    )
    prior_ids = {it["poam_id"] for it in prior["items"].values()}
    assert len(prior_ids) == 126
    (tmp_path / "poam").mkdir(parents=True, exist_ok=True)
    (tmp_path / "poam" / "poam-ledger.json").write_text(
        json.dumps(prior, indent=2) + "\n", encoding="utf-8"
    )
    summary = _run_lab(tmp_path, monkeypatch)
    ledger = json.loads((tmp_path / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    created = [
        e for e in (ledger.get("events_this_run") or []) if e.get("kind") == "created"
    ]
    open_items = [
        it for it in ledger["items"].values() if str(it.get("status") or "") != "closed"
    ]
    with (tmp_path / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        fed_rows = list(csv.DictReader(fh))
    with (tmp_path / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        plan_rows = list(csv.DictReader(fh))
    reseen_ids = {it["poam_id"] for it in open_items}
    ghosts = prior_ids - reseen_ids
    new_ids = reseen_ids - prior_ids
    plan_ids = {r.get("poam_id") or "" for r in plan_rows if r.get("poam_id")}
    fed_ids = {r.get("POAM ID") or "" for r in fed_rows if r.get("POAM ID")}
    assert ghosts == set(), f"ghosts {sorted(ghosts)}"
    assert len(created) == 1, [e.get("poam_id") for e in created]
    assert {e.get("poam_id") for e in created} == new_ids
    assert len(open_items) == 127
    assert fed_ids == plan_ids
    assert len(fed_rows) == len(plan_ids)
    assert prior_ids <= reseen_ids
    assert len({it["poam_id"] for it in open_items}) == 127
    admin_rows = [
        it
        for it in open_items
        if str(it.get("name") or "").startswith("Exposed admin interface on")
    ]
    assert len(admin_rows) == 2
    assert len({it["poam_id"] for it in admin_rows}) == 2
    assert summary.get("demo") is True


def _nmap_fqdn_asset(fqdn: str, ip: str) -> dict:
    return make_record(
        kind="asset",
        source="inventory-nmap",
        ref_id=make_ref("inventory-nmap", f"asset-{fqdn}"),
        name=fqdn,
        description=f"Host {fqdn}",
        category="host",
        assets=[fqdn],
        labels=["nmap"],
        collected_at=NOW,
        extra=stamp_ids({}, fqdn=fqdn, ip=ip),
    )


def _fleet_short_asset(name: str) -> dict:
    return make_record(
        kind="asset",
        source="host-wazuh",
        ref_id=make_ref("host-wazuh", f"asset-{name}"),
        name=name,
        description=f"Fleet host {name}",
        category="host",
        assets=[name],
        labels=["wazuh", "host"],
        collected_at=NOW,
        extra=stamp_ids({}, hostname=name),
    )


def _wazuh_disconnected(host: str) -> dict:
    return {
        "kind": "finding",
        "source": "host-wazuh",
        "ref_id": make_ref("host-wazuh", f"coverage-{host}"),
        "name": f"Wazuh agent disconnected: {host}",
        "description": f"Endpoint {host} is disconnected; coverage gap.",
        "severity": "high",
        "category": "coverage-gap",
        "assets": [host],
        "labels": ["wazuh", "host", "coverage"],
        "collected_at": NOW,
        "extra": {"agent_status": "disconnected"},
    }


def _poam_open(records: list[dict]) -> list[dict]:
    ledger = AssetLedger()
    stamped = attach_asset_uids(records, ledger, now=NOW)
    findings = [r for r in stamped if r.get("kind") == "finding"]
    out = apply_ledger(
        findings,
        catalog=_unevaluated(),
        run_at=_run(NOW),
        ledger_in=empty_ledger(),
        prior_existed=True,
    )
    return [
        it for it in out["items"].values() if str(it.get("status") or "") != "closed"
    ]


def test_ambiguous_bare_web01_four_rows_both_orders() -> None:
    """Bare web01 must not fold into web01.corp-a or web01.corp-b. 4 rows either order.

    Two nmap hosts (port-22) plus the Fleet coverage row on the bare name, and
    one FQDN coverage row so a fold would collapse a POA&M ID. Master keeps
    four rows; FQDN-first and wazuh-first (grc_loader) must too.
    """
    pair = (
        ("web01.corp-a.local", "10.1.0.10"),
        ("web01.corp-b.local", "10.2.0.10"),
    )
    for order in (pair, tuple(reversed(pair))):
        nmap_block = []
        for fqdn, ip in order:
            nmap_block.append(_nmap_fqdn_asset(fqdn, ip))
            nmap_block.append(_nmap_port(fqdn, "22", service="ssh", extra={"ip": ip}))
        wazuh_block = [
            _fleet_short_asset("web01"),
            _wazuh_disconnected("web01"),
        ]
        fqdn_finding = [_wazuh_disconnected(order[0][0])]
        for records, label in (
            (nmap_block + fqdn_finding + wazuh_block, f"fqdn-first:{order[0][0]}"),
            (wazuh_block + nmap_block + fqdn_finding, f"wazuh-first:{order[0][0]}"),
        ):
            ledger = AssetLedger()
            stamped = attach_asset_uids(records, ledger, now=NOW)
            uids = {
                str((r.get("extra") or {}).get("asset_uid") or "")
                for r in stamped
                if r.get("kind") == "asset"
            }
            assert len(uids) == 3, f"{label} folded to {uids}"
            open_items = _poam_open(records)
            assert len(open_items) == 4, (
                f"{label} → {len(open_items)} rows "
                f"{[(it.get('name'), it.get('poam_id')) for it in open_items]}"
            )


def test_wazuh_ip_reuse_keeps_two_egps() -> None:
    """hostb may join hosta's EGA by IP; Wazuh rows stay two distinct EGPs."""
    hosta = make_record(
        kind="asset",
        source="host-wazuh",
        ref_id=make_ref("host-wazuh", "asset-hosta"),
        name="hosta",
        category="host",
        assets=["hosta"],
        labels=["wazuh"],
        collected_at=NOW,
        extra=stamp_ids({}, hostname="hosta", ip="10.5.0.5"),
    )
    hostb = make_record(
        kind="asset",
        source="host-wazuh",
        ref_id=make_ref("host-wazuh", "asset-hostb"),
        name="hostb",
        category="host",
        assets=["hostb"],
        labels=["wazuh"],
        collected_at=NOW,
        extra=stamp_ids({}, hostname="hostb", ip="10.5.0.5"),
    )
    fa = _wazuh_disconnected("hosta")
    fb = _wazuh_disconnected("hostb")
    assert weakness_key(fa) != weakness_key(fb)
    assert weakness_key(fa).endswith(":hosta")
    assert weakness_key(fb).endswith(":hostb")
    hostless = {
        **fa,
        "assets": ["hosta"],
        "extra": {"agent_status": "disconnected"},
    }
    from shared.poam_ledger import _legacy_fps_for, _weakness_key_core

    assert _weakness_key_core(hostless) == "wazuh:agent_status:disconnected"
    assert any(reason == "wazuh_add_host" for _fp, reason in _legacy_fps_for(fa))
    assert fp_v1(fa, weakness_key_fn=_weakness_key_core) in fingerprints_for(fa)
    ledger = AssetLedger()
    stamped = attach_asset_uids([hosta, hostb, fa, fb], ledger, now=NOW)
    findings = [r for r in stamped if r.get("kind") == "finding"]
    assert len({str((r.get("extra") or {}).get("asset_uid") or "") for r in findings}) == 1
    out = apply_ledger(
        findings,
        catalog=_unevaluated(),
        run_at=_run(NOW),
        ledger_in=empty_ledger(),
        prior_existed=True,
    )
    open_items = [
        it for it in out["items"].values() if str(it.get("status") or "") != "closed"
    ]
    assert len(open_items) == 2
    assert {it["poam_id"] for it in open_items}.__len__() == 2
    assert {it["weakness_key"] for it in open_items} == {
        weakness_key(fa),
        weakness_key(fb),
    }


def test_wazuh_ip_reuse_upgrade_keeps_hosta_egp() -> None:
    """29c4c3e hosta ledger + hostb same IP: hosta keeps EGP-946F27C7C3, hostb is new."""
    from shared.poam_ledger import _weakness_key_core

    hosta_egp = "EGP-946F27C7C3"
    hosta = make_record(
        kind="asset",
        source="host-wazuh",
        ref_id=make_ref("host-wazuh", "asset-hosta"),
        name="hosta",
        category="host",
        assets=["hosta"],
        labels=["wazuh"],
        collected_at=NOW,
        extra=stamp_ids({}, hostname="hosta", ip="10.5.0.5"),
    )
    hostb = make_record(
        kind="asset",
        source="host-wazuh",
        ref_id=make_ref("host-wazuh", "asset-hostb"),
        name="hostb",
        category="host",
        assets=["hostb"],
        labels=["wazuh"],
        collected_at=NOW,
        extra=stamp_ids({}, hostname="hostb", ip="10.5.0.5"),
    )
    fa = _wazuh_disconnected("hosta")
    fb = _wazuh_disconnected("hostb")
    first = AssetLedger()
    stamped_a = attach_asset_uids([hosta, fa], first, now=NOW)
    fa1 = next(r for r in stamped_a if r.get("kind") == "finding")
    old_fp = fp_v1(fa1, weakness_key_fn=_weakness_key_core)
    prior = empty_ledger()
    prior["items"][old_fp] = {
        "poam_id": hosta_egp,
        "fp": old_fp,
        "source_family": "host-wazuh",
        "weakness_key": _weakness_key_core(fa1),
        "asset_key": fa1["extra"]["asset_uid"],
        "display_asset": "hosta",
        "name": "Wazuh agent disconnected: hosta",
        "description": "Endpoint hosta is disconnected; coverage gap.",
        "ref_id": fa1["ref_id"],
        "original_detection_date": "2026-08-01",
        "first_seen": "2026-08-01T00:00:00Z",
        "last_seen": "2026-08-01T00:00:00Z",
        "status": "open",
        "severity": "high",
        "missed_covered_runs": 0,
        "kev_comments": [],
    }
    for order in ((fb, fa), (fa, fb)):
        second = AssetLedger()
        stamped = attach_asset_uids([hosta, hostb, fa, fb], second, now=NOW)
        by_host = {
            str((r.get("assets") or [""])[0]): r
            for r in stamped
            if r.get("kind") == "finding"
        }
        incoming = [by_host["hostb"] if rec is fb else by_host["hosta"] for rec in order]
        out = apply_ledger(
            incoming,
            catalog=_unevaluated(),
            run_at=_run("2026-09-02T00:00:00Z"),
            ledger_in=prior,
            prior_existed=True,
        )
        open_items = [
            it for it in out["items"].values() if str(it.get("status") or "") != "closed"
        ]
        assert len(open_items) == 2, order[0]["assets"]
        by_wk = {it["weakness_key"]: it for it in open_items}
        assert weakness_key(fa) in by_wk
        assert weakness_key(fb) in by_wk
        assert by_wk[weakness_key(fa)]["poam_id"] == hosta_egp
        assert by_wk[weakness_key(fa)]["original_detection_date"] == "2026-08-01"
        hostb_id = by_wk[weakness_key(fb)]["poam_id"]
        assert hostb_id != hosta_egp
        assert hostb_id.startswith("EGP-")


def _wazuh_host_asset(name: str, **ids: object) -> dict:
    blob: dict = {"fqdn": name} if "." in name else {"hostname": name}
    blob.update(ids)
    return make_record(
        kind="asset",
        source="host-wazuh",
        ref_id=make_ref("host-wazuh", f"asset-{name}"),
        name=name,
        category="host",
        assets=[name],
        labels=["wazuh"],
        collected_at=NOW,
        extra=stamp_ids({}, **blob),
    )


def test_wazuh_short_name_and_fqdn_same_id_fresh_both_directions() -> None:
    """hosta and hosta.corp.local stay one EGP, either observation order."""
    from shared.poam_ledger import _stored_wazuh_hosts, _wazuh_host_token

    short = _wazuh_disconnected("hosta")
    fqdn = _wazuh_disconnected("hosta.corp.local")
    assert weakness_key(short) == weakness_key(fqdn)
    assert weakness_key(short).endswith(":hosta")
    assert _wazuh_host_token(fqdn) == "hosta"
    assert _stored_wazuh_hosts({"display_asset": "hosta.corp.local"}) == {"hosta"}
    assert _stored_wazuh_hosts(
        {"display_asset": "hosta", "name": "Ensure disk encryption on application"}
    ) == {"hosta"}
    assert "disk" not in _stored_wazuh_hosts(
        {"display_asset": "hosta", "name": "Ensure disk encryption on application"}
    )
    for first, second in ((short, fqdn), (fqdn, short)):
        records = [
            _wazuh_host_asset("hosta"),
            _wazuh_host_asset("hosta.corp.local", ip="10.5.0.8"),
            first,
            second,
        ]
        open_items = _poam_open(records)
        assert len(open_items) == 1, first["assets"]
        assert open_items[0]["weakness_key"] == weakness_key(short)


def test_wazuh_short_name_and_fqdn_upgrade_from_29c4c3e_both_directions() -> None:
    """29c4c3e ledger on one name, upgrade on the other: same EGP, no ghost."""
    from shared.poam_ledger import _weakness_key_core

    pairs = (
        ("hosta", "hosta.corp.local"),
        ("hosta.corp.local", "hosta"),
    )
    for prior_name, next_name in pairs:
        prior_rec = _wazuh_disconnected(prior_name)
        next_rec = _wazuh_disconnected(next_name)
        first = AssetLedger()
        stamped = attach_asset_uids(
            [_wazuh_host_asset(prior_name), prior_rec], first, now=NOW
        )
        old = next(r for r in stamped if r.get("kind") == "finding")
        old_fp = fp_v1(old, weakness_key_fn=_weakness_key_core)
        prior = empty_ledger()
        prior["items"][old_fp] = {
            "poam_id": "EGP-SHORTFQDN1",
            "fp": old_fp,
            "source_family": "host-wazuh",
            "weakness_key": _weakness_key_core(old),
            "asset_key": old["extra"]["asset_uid"],
            "display_asset": prior_name,
            "name": prior_rec["name"],
            "description": prior_rec["description"],
            "ref_id": old["ref_id"],
            "original_detection_date": "2026-08-01",
            "first_seen": "2026-08-01T00:00:00Z",
            "last_seen": "2026-08-01T00:00:00Z",
            "status": "open",
            "severity": "high",
            "missed_covered_runs": 0,
            "kev_comments": [],
        }
        second = AssetLedger()
        incoming = attach_asset_uids(
            [
                _wazuh_host_asset("hosta"),
                _wazuh_host_asset("hosta.corp.local", ip="10.5.0.8"),
                next_rec,
            ],
            second,
            now=NOW,
        )
        findings = [r for r in incoming if r.get("kind") == "finding"]
        out = apply_ledger(
            findings,
            catalog=_unevaluated(),
            run_at=_run("2026-09-02T00:00:00Z"),
            ledger_in=prior,
            prior_existed=True,
        )
        open_items = [
            it for it in out["items"].values() if str(it.get("status") or "") != "closed"
        ]
        created = [
            e for e in (out.get("events_this_run") or []) if e.get("kind") == "created"
        ]
        ghosts = [
            it
            for it in out["items"].values()
            if str(it.get("status") or "") != "closed"
            and it.get("poam_id") == "EGP-SHORTFQDN1"
            and str(it.get("last_seen") or "").startswith("2026-08-01")
        ]
        assert len(open_items) == 1, (prior_name, next_name, [it["poam_id"] for it in open_items])
        assert open_items[0]["poam_id"] == "EGP-SHORTFQDN1"
        assert created == []
        assert ghosts == []


def _seed_29c4c3e_wazuh(host: str, ip: str, poam_id: str) -> tuple[str, dict]:
    from shared.poam_ledger import _weakness_key_core

    rec = _wazuh_disconnected(host)
    stamped = attach_asset_uids(
        [_wazuh_host_asset(host, ip=ip), rec], AssetLedger(), now=NOW
    )
    finding = next(r for r in stamped if r.get("kind") == "finding")
    old_fp = fp_v1(finding, weakness_key_fn=_weakness_key_core)
    item = {
        "poam_id": poam_id,
        "fp": old_fp,
        "source_family": "host-wazuh",
        "weakness_key": _weakness_key_core(finding),
        "asset_key": finding["extra"]["asset_uid"],
        "display_asset": host,
        "name": rec["name"],
        "description": rec["description"],
        "ref_id": finding["ref_id"],
        "original_detection_date": "2026-08-01",
        "first_seen": "2026-08-01T00:00:00Z",
        "last_seen": "2026-08-01T00:00:00Z",
        "status": "open",
        "severity": "high",
        "missed_covered_runs": 0,
        "kev_comments": [],
    }
    return old_fp, item


def _x2dom_hosts() -> tuple[tuple[str, str, str], tuple[str, str, str]]:
    return (
        ("web01.corp-a.local", "10.1.0.10", "EGP-1D468451C2"),
        ("web01.corp-b.local", "10.2.0.20", "EGP-D9A5F91ED9"),
    )


def _apply_x2dom(prior: dict, hosts: list[tuple[str, str]]) -> dict:
    records: list[dict] = []
    for host, ip in hosts:
        records.append(_wazuh_host_asset(host, ip=ip))
        records.append(_wazuh_disconnected(host))
    stamped = attach_asset_uids(records, AssetLedger(), now=NOW)
    findings = [r for r in stamped if r.get("kind") == "finding"]
    return apply_ledger(
        findings,
        catalog=_unevaluated(),
        run_at=_run("2026-09-02T00:00:00Z"),
        ledger_in=prior,
        prior_existed=True,
    )


def test_x2dom_both_hosts_both_runs_keep_two_egps() -> None:
    """web01.corp-a and web01.corp-b stay two EGPs on upgrade, either order."""
    from shared.poam_ledger import _wazuh_hostless_item_matches

    a, b = _x2dom_hosts()
    assert not _wazuh_hostless_item_matches(
        _wazuh_disconnected(b[0]), {"display_asset": a[0]}
    )
    for order in ((a, b), (b, a)):
        prior = empty_ledger()
        for host, ip, pid in order:
            fp, item = _seed_29c4c3e_wazuh(host, ip, pid)
            prior["items"][fp] = item
        out = _apply_x2dom(prior, [(h, ip) for h, ip, _pid in order])
        open_items = [
            it for it in out["items"].values() if str(it.get("status") or "") != "closed"
        ]
        ids = {it["poam_id"] for it in open_items}
        aliases = {x for it in open_items for x in (it.get("aliased_poam_ids") or [])}
        remaps = [
            e for e in (out.get("events_this_run") or []) if e.get("kind") == "migrated"
        ]
        stolen = [
            e
            for e in (out.get("events_this_run") or [])
            if e.get("kind") == "migrated_alias"
        ]
        assert ids == {a[2], b[2]}, (order[0][0], ids)
        assert not aliases
        assert stolen == []
        assert {e.get("poam_id") for e in remaps} <= {a[2], b[2]}


def test_x2dom_a_then_b_does_not_steal_egp() -> None:
    """corp-a only on 29c4c3e, corp-b only on upgrade: both IDs, no steal."""
    a, b = _x2dom_hosts()
    prior = empty_ledger()
    fp, item = _seed_29c4c3e_wazuh(a[0], a[1], a[2])
    prior["items"][fp] = item
    out = _apply_x2dom(prior, [(b[0], b[1])])
    open_items = [
        it for it in out["items"].values() if str(it.get("status") or "") != "closed"
    ]
    ids = {it["poam_id"] for it in open_items}
    assert a[2] in ids
    assert len(ids) == 2
    assert a[2] not in {
        it["poam_id"]
        for it in open_items
        if str(it.get("display_asset") or "") == b[0]
    }
    b_row = next(it for it in open_items if str(it.get("display_asset") or "") == b[0])
    assert b_row["poam_id"] != a[2]
    assert b_row["poam_id"].startswith("EGP-")


def test_wazuh_empty_display_asset_never_matches() -> None:
    """A stored host-less row must not crash or match any incoming host."""
    from shared.poam_ledger import _wazuh_hostless_item_matches, _weakness_key_core

    rec = _wazuh_disconnected("hosta")
    assert not _wazuh_hostless_item_matches(rec, {"display_asset": ""})
    assert not _wazuh_hostless_item_matches(rec, {"display_asset": None})
    assert not _wazuh_hostless_item_matches(rec, {})
    prior = empty_ledger()
    prior["items"]["deadbeef"] = {
        "poam_id": "EGP-HOSTLESS01",
        "fp": "deadbeef",
        "source_family": "host-wazuh",
        "weakness_key": _weakness_key_core(rec),
        "asset_key": "EGA-MISSING00",
        "display_asset": "",
        "name": "Wazuh agent disconnected",
        "description": "no host",
        "ref_id": "WAZ-coverage-unknown",
        "original_detection_date": "2026-08-01",
        "first_seen": "2026-08-01T00:00:00Z",
        "last_seen": "2026-08-01T00:00:00Z",
        "status": "open",
        "severity": "high",
        "missed_covered_runs": 0,
        "kev_comments": [],
    }
    out = apply_ledger(
        [rec],
        catalog=_unevaluated(),
        run_at=_run("2026-09-02T00:00:00Z"),
        ledger_in=prior,
        prior_existed=True,
    )
    open_items = [
        it for it in out["items"].values() if str(it.get("status") or "") != "closed"
    ]
    ids = {it["poam_id"] for it in open_items}
    assert "EGP-HOSTLESS01" in ids
    assert any(pid != "EGP-HOSTLESS01" and str(pid).startswith("EGP-") for pid in ids)
    stolen = [
        e for e in (out.get("events_this_run") or []) if e.get("kind") == "migrated_alias"
    ]
    assert stolen == []


def test_x_short_only_ambiguous_mints_new_id() -> None:
    """Bare web01 vs two stored FQDNs is ambiguous: new EGP, no aliases."""
    a, b = _x2dom_hosts()
    prior = empty_ledger()
    for host, ip, pid in (a, b):
        fp, item = _seed_29c4c3e_wazuh(host, ip, pid)
        prior["items"][fp] = item
    out = _apply_x2dom(prior, [("web01", "10.3.0.30")])
    open_items = [
        it for it in out["items"].values() if str(it.get("status") or "") != "closed"
    ]
    ids = {it["poam_id"] for it in open_items}
    aliases = {x for it in open_items for x in (it.get("aliased_poam_ids") or [])}
    stolen = [
        e for e in (out.get("events_this_run") or []) if e.get("kind") == "migrated_alias"
    ]
    assert a[2] in ids
    assert b[2] in ids
    assert len(ids) == 3
    web01_row = next(
        it for it in open_items if str(it.get("display_asset") or "") == "web01"
    )
    assert web01_row["poam_id"] not in {a[2], b[2]}
    assert not aliases
    assert stolen == []
