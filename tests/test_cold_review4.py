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
    # Same title, two URL shapes — do not mint a second row.
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
    assert weakness_key(easm_a) == weakness_key(easm_b)


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


def test_demo_fedramp_open_stays_126(tmp_path: Path, monkeypatch) -> None:
    from tests.test_poam_breakdown import _run_lab

    _run_lab(tmp_path, monkeypatch)
    fed = tmp_path / "poam" / "poam_fedramp.csv"
    assert fed.is_file()
    with fed.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 126, f"DEMO FedRAMP Open={len(rows)} expected 126"


def test_farm_fedramp_open_stays_172(tmp_path: Path) -> None:
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
    fed = work / "out" / "poam" / "poam_fedramp.csv"
    assert fed.is_file()
    with fed.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 172, f"farm FedRAMP Open={len(rows)} expected 172"


def test_master_demo_ledger_upgrade_stays_126_zero_ghosts(
    tmp_path: Path, monkeypatch
) -> None:
    """Upgrade a 932cf7c DEMO ledger: FedRAMP Open stays 126, 0 new, 0 ghosts."""
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
    reseen_ids = {it["poam_id"] for it in open_items}
    ghosts = prior_ids - reseen_ids
    assert created == [], [e.get("poam_id") for e in created]
    assert ghosts == set(), f"ghosts {sorted(ghosts)}"
    assert len(open_items) == 126
    assert len(fed_rows) == 126
    assert reseen_ids == prior_ids
    assert summary.get("demo") is True
