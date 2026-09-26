"""Parsers against real-shaped public samples (fixtures/samples). SAMPLE ≠ client."""

from __future__ import annotations

import json
from pathlib import Path

from collectors import cloud_prowler, host_wazuh, identity_ad, saas_idp, vuln_scan

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"


def test_cloud_custodian_resources_json_uses_policy_dir() -> None:
    recs = cloud_prowler.parse_file(SAMPLES / "cloud" / "s3-encryption-missing" / "resources.json")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("c7n-unencrypted" in a for a in assets)
    assert any("c7n-public-logs" in a for a in assets)
    assert "check" not in assets
    assert findings
    assert all(r["extra"].get("check_id") == "s3-encryption-missing" for r in findings)
    assert all("c7n-" in str(r.get("assets")) for r in findings)


def test_powerpipe_alarm_only_and_steampipe_query_not_fail() -> None:
    recs = cloud_prowler.parse_file(SAMPLES / "cloud" / "powerpipe-benchmark.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert findings[0]["extra"].get("check_id") == "cis_v300_1_5"
    assert "111122223333" in str(findings[0].get("assets"))
    query = cloud_prowler.parse_file(SAMPLES / "cloud" / "steampipe-query.json")
    assert not any(r["kind"] == "finding" for r in query)


def test_scoutsuite_danger_is_high() -> None:
    recs = cloud_prowler.parse_file(ROOT / "fixtures" / "demo" / "cloud" / "scoutsuite.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all(r["severity"] == "high" for r in findings)


def test_intune_v1_azure_ad_registered_is_not_enrollment() -> None:
    recs = host_wazuh.parse_file(SAMPLES / "mdm" / "intune-manageddevices-v1.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    names = [r["name"] for r in findings]
    assert any(r["kind"] == "asset" and r["name"] == "LAPTOP-GRAPH-01" for r in recs)
    assert not any("MDM enrollment" in n for n in names)
    assert not any("Missing EDR" in n for n in names)
    assert any("Disk encryption" in n and "LAPTOP-GRAPH-02" in n for n in names)
    assert any("encryption compliance" in n for n in names)


def test_jamf_pro_results_camelcase() -> None:
    recs = host_wazuh.parse_file(SAMPLES / "mdm" / "jamf-computers-inventory.json")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    assert "mac-jamf-01" in assets
    assert "mac-jamf-02" in assets
    assert any("Disk encryption" in r["name"] and "mac-jamf-02" in r["name"] for r in findings)
    assert not any("mac-jamf-01" in r["name"] and r["kind"] == "finding" and "Disk encryption" in r["name"] for r in recs)
    assert not any("Missing EDR" in r["name"] for r in findings)


def test_entra_isadmin_is_not_standing_ga() -> None:
    recs = saas_idp.parse_file(SAMPLES / "saas" / "entra-userregistrationdetails.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    names = [r["name"] for r in findings]
    assert any(r["kind"] == "asset" and r["name"] == "AdeleV@contoso.com" for r in recs)
    assert "Standing Global Administrator" not in names
    assert any(n == "Privileged role (unspecified)" for n in names)
    assert all(r["severity"] == "high" for r in findings if r["name"] == "Privileged role (unspecified)")


def test_okta_api_list_assets_only() -> None:
    recs = saas_idp.parse_file(SAMPLES / "saas" / "okta-users-api.json")
    assert recs
    assert any(r["kind"] == "asset" and r["name"] == "isaac.brock@example.com" for r in recs)
    assert not any(r["kind"] == "finding" for r in recs)


def test_google_console_csv_detected_by_header() -> None:
    recs = saas_idp.parse_file(SAMPLES / "saas" / "google-admin-users.csv")
    findings = [r for r in recs if r["kind"] == "finding"]
    names = [r["name"] for r in findings]
    assert any(r["kind"] == "asset" and r["name"] == "admin@example.com" for r in recs)
    assert "Standing Global Administrator" not in names
    assert any("MFA" in n or "Privileged" in n for n in names)
    assert not any("user@example.com" in (r.get("assets") or []) and r["kind"] == "finding" for r in recs)


def test_maester_missing_severity_defaults_medium() -> None:
    recs = saas_idp.parse_file(SAMPLES / "saas" / "maester-no-severity.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "MT.1035" in findings[0]["name"]
    assert findings[0]["severity"] == "medium"
    assert findings[0]["extra"].get("severity_source") == "default"


def test_bloodhound_ce_v6_skips_computer_spn_and_default_aces() -> None:
    users = identity_ad.parse_file(SAMPLES / "bloodhound" / "bhce_v6_users.json")
    computers = identity_ad.parse_file(SAMPLES / "bloodhound" / "bhce_v6_computers.json")
    domains = identity_ad.parse_file(SAMPLES / "bloodhound" / "bhce_v6_domains.json")
    ufind = [r for r in users if r["kind"] == "finding"]
    cfind = [r for r in computers if r["kind"] == "finding"]
    dfind = [r for r in domains if r["kind"] == "finding"]
    assert any(r["kind"] == "asset" and "KRBTGT@" in r["name"] for r in users)
    assert not any(r["name"] == "Roastable SPN" for r in ufind)
    assert not any(r["name"] == "Roastable SPN" for r in cfind)
    assert not any(r["severity"] in {"critical", "high"} and "GenericAll" in r["name"] for r in ufind + cfind + dfind)
    assert not any(r["name"] == "BloodHound DCSync" for r in dfind)


def test_bloodhound_true_dcsync_from_getchanges_pair() -> None:
    recs = identity_ad.parse_file(SAMPLES / "bloodhound" / "bhce_v6_real_exposure.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    names = [r["name"] for r in findings]
    assert "BloodHound DCSync" in names
    assert any("VICTIM@ESC1.LOCAL" in str(r.get("assets")) for r in findings if r["name"] == "BloodHound DCSync")
    assert not any(r["name"] == "BloodHound GenericAll" for r in findings)


def test_trivy_secrets_and_misconfig_only() -> None:
    secrets = vuln_scan.parse_file(SAMPLES / "trivy" / "secrets.json")
    sfind = [r for r in secrets if r["kind"] == "finding"]
    assert sfind
    assert any("aws-access-key-id" in (r.get("description") or r["name"]).lower() or "AWS Access Key" in r["name"] for r in sfind)
    assert all("[REDACTED]" in str(secrets) or "AKIA" not in str(secrets) for _ in [0])
    assert all(r["extra"].get("rule") and r["extra"].get("check_id") for r in sfind)
    assert any(r["extra"].get("check_id") == "aws-access-key-id" for r in sfind)
    mis = vuln_scan.parse_file(SAMPLES / "trivy" / "dockerfile.json")
    mfind = [r for r in mis if r["kind"] == "finding"]
    assert any(r["extra"].get("cve") == "" and "DS-0002" in r["ref_id"] or "DS-0002" in r["name"] or r["name"].startswith("Image user") for r in mfind)
    assert any(r["extra"].get("check_id") == "DS-0002" or r["extra"].get("rule") == "DS-0002" for r in mfind)


def test_trivy_two_secrets_on_one_file_stay_distinct(tmp_path: Path) -> None:
    payload = {
        "SchemaVersion": 2,
        "ArtifactName": "testdata/fixtures/repo/secrets",
        "ArtifactType": "repository",
        "Results": [
            {
                "Target": "deploy.sh",
                "Class": "secret",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Category": "AWS",
                        "Severity": "CRITICAL",
                        "Title": "AWS Access Key ID",
                        "Match": "export AWS_ACCESS_KEY_ID=[REDACTED]",
                    },
                    {
                        "RuleID": "generic-secret",
                        "Category": "General",
                        "Severity": "HIGH",
                        "Title": "My Secret",
                        "Match": "export MY_SECRET=[REDACTED]",
                    },
                ],
            }
        ],
    }
    dest = tmp_path / "two-secrets.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    recs = vuln_scan.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 2
    ids = {r["extra"].get("check_id") for r in findings}
    assert ids == {"aws-access-key-id", "generic-secret"}
    from shared.poam_ledger import fp_v1, weakness_key

    keys = {weakness_key(r) for r in findings}
    fps = {fp_v1(r) for r in findings}
    assert len(keys) == 2
    assert len(fps) == 2
    assert "unkeyed" not in "".join(keys)
    assert all(r["extra"].get("rule") == r["extra"].get("check_id") for r in findings)


def test_osquery_hostidentifier_and_check_snapshot() -> None:
    inv = host_wazuh.parse_file(SAMPLES / "osquery" / "docs-process-snapshot.json")
    assert any(r["kind"] == "asset" and r["name"] == "hostname.local" for r in inv)
    assert not any(r["kind"] == "finding" for r in inv)
    check = host_wazuh.parse_file(SAMPLES / "osquery" / "snapshot-disk-encryption.jsonl")
    findings = [r for r in check if r["kind"] == "finding"]
    assert findings
    assert any("disk encryption" in r["name"].lower() or "disk_encryption" in r["name"] for r in findings)
    assert all("hostname.local" in (r.get("assets") or []) for r in findings)


def test_osquery_it_compliance_pack_compliant_host_zero_findings() -> None:
    recs = host_wazuh.parse_file(SAMPLES / "osquery" / "it-compliance-pack.json")
    pack = json.loads((SAMPLES / "osquery" / "it-compliance-pack.json").read_text(encoding="utf-8"))
    assert len(pack["queries"]) == 32
    assert any(r["kind"] == "asset" and r["name"] == "compliant-mac.local" for r in recs)
    assert not any(r["kind"] == "finding" for r in recs)


def test_custodian_rejects_steampipe_list_and_defaults_medium(tmp_path: Path) -> None:
    steampipe = tmp_path / "steampipe-list.json"
    steampipe.write_text(
        json.dumps(
            [
                {
                    "arn": "arn:aws:s3:::query-bucket",
                    "name": "query-bucket",
                    "id": "query-bucket",
                }
            ]
        ),
        encoding="utf-8",
    )
    recs = cloud_prowler.parse_file(steampipe)
    assert not any(r["kind"] == "finding" for r in recs)

    dest = tmp_path / "ebs-unencrypted"
    dest.mkdir()
    (dest / "metadata.json").write_text(
        json.dumps({"policy": {"name": "ebs-unencrypted", "resource": "aws.ebs"}}),
        encoding="utf-8",
    )
    (dest / "resources.json").write_text(
        json.dumps(
            [
                {
                    "VolumeId": "vol-abc",
                    "Arn": "arn:aws:ec2:us-east-1:111122223333:volume/vol-abc",
                }
            ]
        ),
        encoding="utf-8",
    )
    recs = cloud_prowler.parse_file(dest / "resources.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all(r["severity"] == "medium" for r in findings)
    assert all(r["extra"].get("severity_source") == "default" for r in findings)


def test_scoutsuite_js_assignment_prefix() -> None:
    recs = cloud_prowler.parse_file(SAMPLES / "cloud" / "scoutsuite-results.js")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert any("demo-scout-js-public" in str(r.get("assets")) for r in findings)
    assert all(r["severity"] == "high" for r in findings)


def test_trivy_k8s_resources_results(tmp_path: Path) -> None:
    recs = vuln_scan.parse_file(SAMPLES / "trivy" / "k8s-cluster.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert any(r["extra"].get("cve") == "CVE-2019-14697" for r in findings)
    assert any("nginx" in str(r.get("assets")) for r in findings)
    empty = {"ClusterName": "kind-kind", "Resources": []}
    assert vuln_scan._is_trivy(empty)
    assert vuln_scan._is_trivy_k8s(empty)
    assert vuln_scan._trivy_rows(empty) == []
    dest = tmp_path / "empty-k8s.json"
    dest.write_text(json.dumps(empty), encoding="utf-8")
    assert vuln_scan.parse_file(dest) == []


def test_intune_owner_unknown_is_not_unenrolled() -> None:
    recs = host_wazuh.parse_file(SAMPLES / "mdm" / "intune-manageddevices-v1.json")
    assert any(r["kind"] == "asset" and r["name"] == "LAPTOP-GRAPH-03" for r in recs)
    enroll = [r for r in recs if r["kind"] == "finding" and "MDM enrollment" in r["name"]]
    assert not enroll
    assert not any("LAPTOP-GRAPH-03" in r["name"] and "enrollment" in r["name"].lower() for r in recs if r["kind"] == "finding")


def test_bloodhound_hassession_rolls_up_per_privileged_principal() -> None:
    recs = identity_ad.parse_file(SAMPLES / "bloodhound" / "bhce_v6_sessions.json")
    sessions = [r for r in recs if r["kind"] == "finding" and r["name"] == "BloodHound HasSession"]
    assert len(sessions) == 1
    finding = sessions[0]
    assert finding["extra"].get("session_count") == 3
    assert "ADMIN@LAB.LOCAL" in (finding.get("assets") or [])
    assert not any("BOB@LAB.LOCAL" == r["extra"].get("start") for r in sessions)


def test_jamf_filevault2_states_and_general_coverage_gap() -> None:
    recs = host_wazuh.parse_file(SAMPLES / "mdm" / "jamf-computers-inventory.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    names = [r["name"] for r in findings]
    assert any("Disk encryption" in n and "mac-jamf-02" in n for n in names)
    assert any("Disk encryption" in n and "mac-jamf-some" in n for n in names)
    assert not any("Disk encryption" in n and "mac-jamf-01" in n for n in names)
    assert not any("Disk encryption" in n and "mac-jamf-boot" in n for n in names)
    assert any("encryption not collected" in n and "mac-jamf-general" in n for n in names)
    fixture = (SAMPLES / "mdm" / "jamf-computers-inventory.json").read_text(encoding="utf-8")
    assert "ALL_ENCRYPTED" in fixture
    assert "BOOT_ENCRYPTED" in fixture
    assert "SOME_ENCRYPTED" in fixture
    assert "NOT_ENCRYPTED" in fixture
    assert "AllPartitionsEncrypted" not in fixture
    assert "NotEncrypted" not in fixture


def test_osquery_results_log_is_not_lynis() -> None:
    """*.log osqueryd results are detected by content, not sent to Lynis."""
    recs = host_wazuh.parse_file(SAMPLES / "osquery" / "osqueryd.results.sample.log")
    assert recs
    assert not any("lynis" in (r.get("labels") or []) for r in recs)
    assert any(r["kind"] == "asset" and r["name"] == "ubuntu-xenial" for r in recs)


def test_osquery_it_compliance_predicates_on_filebeat_and_msticpy() -> None:
    ubuntu = host_wazuh.parse_file(SAMPLES / "osquery" / "osqueryd.results.sample.log")
    ufind = [r for r in ubuntu if r["kind"] == "finding"]
    assert len(ufind) == 1
    assert "Disk encryption is disabled" in ufind[0]["name"]
    assert "ubuntu-xenial" in (ufind[0].get("assets") or [])

    mac = host_wazuh.parse_file(SAMPLES / "osquery" / "osqueryd.results.darwin.log")
    mfind = [r for r in mac if r["kind"] == "finding"]
    assert len(mfind) == 1
    assert "Application firewall is disabled" in mfind[0]["name"]
    assert not any("disk_encryption" in r["name"] or "disk encryption" in r["name"].lower() for r in mfind)

    mstic = host_wazuh.parse_file(SAMPLES / "osquery" / "msticpy.osqueryd.results.log")
    assert not any(r["kind"] == "finding" for r in mstic)
    assert all((r.get("extra") or {}).get("exclude_reason") == "unmapped" for r in mstic if r.get("kind") == "excluded")
    excluded = [r for r in mstic if r.get("kind") == "excluded"]
    assert len(excluded) == 11
    assert len({r["ref_id"] for r in excluded}) == 11
    assert {r.get("name") for r in mstic if r.get("kind") == "asset"} == {"jumpvm"}
    assert all("jumpvm" in (r.get("assets") or []) for r in excluded)
    assert "osquery-host" not in {r.get("name") for r in mstic}
    assert not any(str(r.get("name") or "").startswith("pack_") for r in mstic)
    assert not any("pack_" in str(r.get("name") or "") for r in ubuntu + mac)

    snaps = host_wazuh.parse_file(SAMPLES / "osquery" / "msticpy.osqueryd.snapshots.log")
    assert not any(r["kind"] == "finding" for r in snaps)
    sexcl = [r for r in snaps if r.get("kind") == "excluded"]
    assert len(sexcl) == 3
    assert len({r["ref_id"] for r in sexcl}) == 3
    assert {r.get("name") for r in snaps if r.get("kind") == "asset"} == {"jumpvm"}
    assert all((r.get("extra") or {}).get("exclude_reason") == "unmapped" for r in sexcl)


def test_real_corpus_four_poam_rows() -> None:
    """Metis §15: four per-asset weakness rows on the public corpus; msticpy is exclude-only."""
    rows = []
    for recs in (
        host_wazuh.parse_file(SAMPLES / "osquery" / "osqueryd.results.sample.log"),
        host_wazuh.parse_file(SAMPLES / "osquery" / "osqueryd.results.darwin.log"),
        cloud_prowler.parse_file(SAMPLES / "cloud" / "security-context-pods" / "resources.json"),
        cloud_prowler.parse_file(SAMPLES / "cloud" / "check-ebs-snapshot-public" / "resources.json"),
    ):
        rows.extend(r for r in recs if r["kind"] == "finding")
    assert len(rows) == 4
    assets = {tuple(r.get("assets") or []) for r in rows}
    assert any("ubuntu-xenial" in a for a in assets)
    assert any(any("snap-084bf49b944409f37" == x for x in a) for a in assets)
    assert any(any(x in {"test/test-pod-1", "default/web"} for x in a) for a in assets)
    names = " ".join(r["name"] for r in rows)
    assert "Disk encryption is disabled" in names
    assert "Application firewall is disabled" in names
    assert "pack_" not in names


def test_osquery_pack_config_is_not_results() -> None:
    from shared.io_util import UnrecognizedShape

    path = SAMPLES / "osquery" / "it-compliance.conf"
    try:
        recs = host_wazuh.parse_file(path)
    except UnrecognizedShape as exc:
        assert "pack config" in exc.reason
        return
    assert recs == []
    assert not any(r.get("name") == "osquery-host" for r in recs)


def test_make_ref_keeps_full_azure_vm_identity() -> None:
    """8 real Azure ARM ids must not collapse to one 48-char ref."""
    from shared.schema import make_ref

    recs = cloud_prowler.parse_file(SAMPLES / "cloud" / "stop-underutilized-azure-vms" / "resources.json")
    assets = [r for r in recs if r["kind"] == "asset"]
    assert len(assets) == 8
    assert all("/subscriptions/" in a["name"] for a in assets)
    refs = [r["ref_id"] for r in recs if r.get("kind") in {"finding", "excluded"}]
    assert len(refs) == 8
    assert len(set(refs)) == 8
    rows = json.loads((SAMPLES / "cloud" / "stop-underutilized-azure-vms" / "resources.json").read_text())
    arms = [str(r["id"]) for r in rows]
    assert len(arms) == 8
    ident_refs = [make_ref("cloud-prowler", f"stop-underutilized-azure-vms-{arm}") for arm in arms]
    assert len(set(ident_refs)) == 8
    for arm, ref in zip(arms, ident_refs, strict=True):
        tail = arm.rsplit("/", 1)[-1].lower()
        assert ref.endswith(tail)
        assert "subscriptions-8a4e83d9" in ref


def test_custodian_ebs_snapshot_and_aws_cost_on_real_runs() -> None:
    ebs = cloud_prowler.parse_file(SAMPLES / "cloud" / "check-ebs-snapshot-public" / "resources.json")
    efind = [r for r in ebs if r["kind"] == "finding"]
    assert len(efind) == 1
    assert efind[0]["severity"] in {"medium", "high"}
    assert "snap-084bf49b944409f37" in (efind[0].get("assets") or [])
    assert efind[0]["extra"].get("check_id") == "check-ebs-snapshot-public"

    aws = cloud_prowler.parse_file(SAMPLES / "cloud" / "stop-underutilized-aws-instances" / "resources.json")
    assert not any(r["kind"] == "finding" for r in aws)
    excluded = [r for r in aws if (r.get("extra") or {}).get("exclude_reason") == "NOT_A_WEAKNESS"]
    assert len(excluded) == 6


def test_custodian_annotations_without_sibling_metadata(tmp_path: Path) -> None:
    src = SAMPLES / "cloud" / "check-ebs-snapshot-public" / "resources.json"
    dest = tmp_path / "check-ebs-snapshot-public" / "resources.json"
    dest.parent.mkdir()
    dest.write_bytes(src.read_bytes())
    recs = cloud_prowler.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "snap-084bf49b944409f37" in (findings[0].get("assets") or [])


def test_custodian_unparseable_resources_json_is_unrecognized_shape(
    tmp_path: Path, monkeypatch
) -> None:
    from shared.io_util import UNRECOGNIZED_STATUS, load_sensor_coverage, run_collector

    dest_in = tmp_path / "in" / "cloud"
    dest_out = tmp_path / "out"
    dest_in.mkdir(parents=True)
    dest_out.mkdir(parents=True)
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("OUT_DIR", str(dest_out))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    (dest_in / "resources.json").write_text('{"not": "a-c7n-run"}', encoding="utf-8")
    run_collector("cloud-prowler", (".json", ".js", ".csv"), cloud_prowler.parse_file)
    rows = {row["source"]: row for row in load_sensor_coverage(dest_out)}
    cov = rows["cloud-prowler"]
    assert cov["status"] == UNRECOGNIZED_STATUS
    assert cov["records"] == 0
    issue = cov["issues"][0]
    assert issue["status"] == UNRECOGNIZED_STATUS
    assert issue["file"] == "resources.json"
    assert "unrecognized" in issue["reason"]


def test_custodian_security_vs_cost_on_real_runs() -> None:
    pod = cloud_prowler.parse_file(SAMPLES / "cloud" / "security-context-pods" / "resources.json")
    pfind = [r for r in pod if r["kind"] == "finding"]
    assert len(pfind) == 1
    assert pfind[0]["severity"] == "medium"
    assert pfind[0]["extra"].get("severity_source") == "default"
    assert "test/test-pod-1" in (pfind[0].get("assets") or [])
    assert pfind[0]["extra"].get("check_id") == "security-context-pods"
    assert not any(r["name"] == "security-context-pods" and r["kind"] == "asset" for r in pod)

    vms = cloud_prowler.parse_file(SAMPLES / "cloud" / "stop-underutilized-azure-vms" / "resources.json")
    assert not any(r["kind"] == "finding" for r in vms)
    excluded = [r for r in vms if (r.get("extra") or {}).get("exclude_reason") == "NOT_A_WEAKNESS"]
    assert len(excluded) == 8


def test_samples_are_not_client_keep() -> None:
    text = (SAMPLES / "SOURCES.md").read_text(encoding="utf-8")
    assert "SAMPLE" in text
    assert "not a client" in text.lower()
    assert "client KEEP" in text
    assert "/api/risks" in text
    assert "RiskReady" in text
