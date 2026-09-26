"""Metis §13.4.3–4 Custodian gating on real staged samples (sha256 in SOURCES.md).

SAMPLE fixtures under fixtures/samples/cloud/ — not dest_in, not client KEEP.
Hand-shaped trees are not labelled real.
"""

from __future__ import annotations

import json
from pathlib import Path

from collectors import cloud_prowler, inventory_nmap
from shared.control_map import POAM_EXCLUDE_REASONS, map_finding, poam_decision
from shared.io_util import (
    UNRECOGNIZED_STATUS,
    SidecarSkip,
    UnrecognizedShape,
    load_sensor_coverage,
    run_collector,
)
from shared.schema import make_ref

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
CLOUD = SAMPLES / "cloud"
DEMO = ROOT / "fixtures" / "demo"


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r["kind"] == "finding"]


def test_samples_sources_credits_real_custodian_sha256() -> None:
    text = (SAMPLES / "SOURCES.md").read_text(encoding="utf-8")
    assert "security-context-pods" in text
    assert "stop-underutilized-azure-vms" in text
    assert "15281f94a960469390ebc59aac4e64abaa8d65c7cefa0b3a2a8a21b9ab2db343" in text
    assert "305c698c5552350f681fc9a52a7edd010792dbba49c822b164f5f716eb60b4f2" in text
    assert "SAMPLE" in text
    assert "client KEEP" in text
    assert "/api/risks" in text
    assert "RiskReady" in text
    assert not (SAMPLES / "custodian").exists()


def test_t18a_security_context_pods_is_finding() -> None:
    recs = cloud_prowler.parse_file(CLOUD / "security-context-pods" / "resources.json")
    findings = _findings(recs)
    assert len(findings) == 1
    hit = findings[0]
    assert "test/test-pod-1" in hit["assets"]
    assert hit["extra"].get("check_id") == "security-context-pods"
    assert hit["severity"] == "medium"
    assert hit["extra"].get("exclude_reason") != "NOT_A_WEAKNESS"
    assert poam_decision(hit)["include"] is True
    assert not any(r["name"] == "security-context-pods" for r in recs if r["kind"] == "asset")


def test_t18b_empty_storage_encryption_no_finding(tmp_path: Path) -> None:
    dest = tmp_path / "enforce-storage-encryption"
    dest.mkdir()
    (dest / "metadata.json").write_text(
        json.dumps(
            {
                "policy": {
                    "name": "enforce-storage-encryption",
                    "resource": "azure.storageaccount",
                    "description": "Storage accounts without encryption at rest",
                    "filters": [{"type": "value", "key": "encryption", "value": False}],
                }
            }
        ),
        encoding="utf-8",
    )
    (dest / "resources.json").write_text("[]", encoding="utf-8")
    recs = cloud_prowler.parse_file(dest / "resources.json")
    assert _findings(recs) == []
    assert not any(r["kind"] == "asset" for r in recs)


def test_t18c_azure_vm_cpu_underutilized_not_a_weakness() -> None:
    recs = cloud_prowler.parse_file(CLOUD / "stop-underutilized-azure-vms" / "resources.json")
    findings = _findings(recs)
    excluded = [r for r in recs if (r.get("extra") or {}).get("exclude_reason") == "NOT_A_WEAKNESS"]
    assert findings == []
    assert len(excluded) == 8
    refs = [r["ref_id"] for r in excluded]
    assert len(set(refs)) == 8
    assert all("/subscriptions/" in (r.get("assets") or [""])[0] for r in excluded)
    hit = excluded[0]
    decision = poam_decision(hit)
    assert decision["include"] is False
    assert decision["reason"] == "NOT_A_WEAKNESS"
    assert decision["reason"] in POAM_EXCLUDE_REASONS
    mapped = map_finding(hit)
    assert mapped["include_poam"] is False
    assert "Cost or operations" in mapped["control_name"]


def test_metadata_does_not_reemit_sibling_resources(
    tmp_path: Path, monkeypatch
) -> None:
    dest_in = tmp_path / "in" / "cloud" / "security-context-pods"
    dest_out = tmp_path / "out"
    dest_in.mkdir(parents=True)
    dest_out.mkdir(parents=True)
    src = CLOUD / "security-context-pods"
    (dest_in / "metadata.json").write_bytes((src / "metadata.json").read_bytes())
    (dest_in / "resources.json").write_bytes((src / "resources.json").read_bytes())
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("OUT_DIR", str(dest_out))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    recs = run_collector("cloud-prowler", (".json", ".js", ".csv"), cloud_prowler.parse_file)
    findings = _findings(recs)
    assert len(findings) == 1
    rows = {row["source"]: row for row in load_sensor_coverage(dest_out)}
    cov = rows["cloud-prowler"]
    issues = cov.get("issues") or []
    assert not any(i.get("file") == "metadata.json" for i in issues)
    assert not any(i.get("status") == "no_records" for i in issues)


def test_lone_metadata_json_is_unrecognized_shape(tmp_path: Path, monkeypatch) -> None:
    dest_in = tmp_path / "in" / "cloud"
    dest_out = tmp_path / "out"
    dest_in.mkdir(parents=True)
    dest_out.mkdir(parents=True)
    (dest_in / "metadata.json").write_text(
        json.dumps({"policy": {"name": "orphan-policy", "resource": "aws.s3"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("OUT_DIR", str(dest_out))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    run_collector("cloud-prowler", (".json", ".js", ".csv"), cloud_prowler.parse_file)
    rows = {row["source"]: row for row in load_sensor_coverage(dest_out)}
    cov = rows["cloud-prowler"]
    assert cov["status"] == UNRECOGNIZED_STATUS
    issue = cov["issues"][0]
    assert issue["status"] == UNRECOGNIZED_STATUS
    assert issue["file"] == "metadata.json"
    assert "unrecognized" in issue["reason"]
    try:
        cloud_prowler.parse_file(dest_in / "metadata.json")
    except UnrecognizedShape as exc:
        assert "without resources.json" in exc.reason
    else:
        raise AssertionError("lone metadata.json must raise UnrecognizedShape")


def test_sidecar_metadata_parse_skips() -> None:
    path = CLOUD / "security-context-pods" / "metadata.json"
    try:
        cloud_prowler.parse_file(path)
    except SidecarSkip:
        return
    raise AssertionError("sidecar metadata.json must raise SidecarSkip")


def test_whole_token_gate_does_not_substring_match() -> None:
    assert cloud_prowler._custodian_is_security(
        "s3-public-acl", {"description": "public ACL", "resource": "aws.s3", "filters": []}
    )
    assert not cloud_prowler._custodian_is_security(
        "premium-storage",
        {"description": "right-size premium disks", "resource": "azure.disk", "filters": []},
    )
    assert cloud_prowler._custodian_classify(
        "stage-only",
        {"description": "tagged later", "resource": "aws.ec2", "filters": []},
    ) == "unknown"
    assert not cloud_prowler._custodian_is_security(
        "stage-only",
        {"description": "tagged later", "resource": "aws.ec2", "filters": []},
    )
    assert cloud_prowler._custodian_is_security(
        "azure-vm-cpu-underutilized",
        {"description": "cpu", "resource": "azure.vm", "filters": []},
    ) is False
    assert not cloud_prowler._custodian_is_security(
        "publication-digest",
        {"description": "tlsomething diameter", "resource": "aws.ec2", "filters": []},
    )


def test_cost_policy_tag_public_filter_is_not_a_weakness() -> None:
    """Gate name/description/resource only — tag:Exposure=public must not flip cost."""
    pol = {
        "description": "Stop EC2 instances with low CPU",
        "resource": "aws.ec2",
        "filters": [{"tag:Exposure": "public"}, {"type": "metrics", "name": "CPUUtilization"}],
    }
    assert cloud_prowler._custodian_is_security("ec2-underutilized-cpu", pol) is False
    recs = cloud_prowler._custodian_findings(
        {
            "name": "ec2-underutilized-cpu",
            **pol,
            "resources": [{"InstanceId": "i-aaa111", "tag:Exposure": "public"}],
        }
    )
    assert recs
    assert all(r.get("ExcludeReason") == "NOT_A_WEAKNESS" for r in recs)
    assert recs[0]["ResourceId"] == "i-aaa111"


def test_stop_idle_admin_workstations_is_not_a_weakness() -> None:
    """Operator cost map is authority — A4 stays NOT_A_WEAKNESS."""
    pol = {
        "description": "Stop idle admin workstations after hours",
        "resource": "aws.ec2",
        "filters": [],
    }
    assert cloud_prowler._custodian_is_security("stop-idle-admin-workstations", pol) is False
    recs = cloud_prowler._custodian_findings(
        {
            "name": "stop-idle-admin-workstations",
            **pol,
            "resources": [{"InstanceId": "i-admin01"}],
        }
    )
    assert recs
    assert recs[0].get("ExcludeReason") == "NOT_A_WEAKNESS"
    assert recs[0]["Status"] == "EXCLUDED"


def test_e1_stop_public_ssh_instances_stays_finding() -> None:
    """Keyword conflict: stop + public/ssh — security wins. Not in operator maps."""
    pol = {
        "description": "SSH open to 0.0.0.0/0",
        "resource": "aws.ec2",
        "filters": [{"type": "ingress", "CidrIp": "0.0.0.0/0", "FromPort": 22}],
    }
    assert "stop-public-ssh-instances" not in cloud_prowler._C7N_SECURITY_NAMES
    assert "stop-public-ssh-instances" not in cloud_prowler._C7N_COST_NAMES
    assert cloud_prowler._custodian_is_security("stop-public-ssh-instances", pol) is True
    recs = cloud_prowler._custodian_findings(
        {
            "name": "stop-public-ssh-instances",
            **pol,
            "resources": [{"InstanceId": "i-ssh01"}],
        }
    )
    assert recs
    assert recs[0].get("ExcludeReason") != "NOT_A_WEAKNESS"
    assert recs[0]["Status"] == "FAIL"
    assert recs[0]["ResourceId"] == "i-ssh01"
    assert poam_decision(
        {
            "kind": "finding",
            "source": "cloud-prowler",
            "name": recs[0]["CheckTitle"],
            "severity": "medium",
            "assets": [recs[0]["ResourceId"]],
            "extra": {"exclude_reason": recs[0].get("ExcludeReason")},
        }
    )["include"] is True


def test_e2_iam_unused_access_keys_stays_finding() -> None:
    """Keyword conflict: unused + iam/cis — security wins. Not in operator maps."""
    pol = {
        "description": "CIS unused credentials — IAM access keys not rotated",
        "resource": "aws.iam-user",
        "filters": [{"type": "access-key", "key": "Status", "value": "Active"}],
    }
    assert "iam-unused-access-keys" not in cloud_prowler._C7N_SECURITY_NAMES
    assert "iam-unused-access-keys" not in cloud_prowler._C7N_COST_NAMES
    assert cloud_prowler._custodian_is_security("iam-unused-access-keys", pol) is True
    recs = cloud_prowler._custodian_findings(
        {
            "name": "iam-unused-access-keys",
            **pol,
            "resources": [
                {
                    "UserName": "alice",
                    "Arn": "arn:aws:iam::111122223333:user/alice",
                }
            ],
        }
    )
    assert recs
    assert recs[0].get("ExcludeReason") != "NOT_A_WEAKNESS"
    assert recs[0]["Status"] == "FAIL"
    assert recs[0]["ResourceId"] == "arn:aws:iam::111122223333:user/alice"


def test_iam_user_prefers_arn_over_username() -> None:
    recs = cloud_prowler._custodian_findings(
        {
            "name": "iam-unused-access-keys",
            "resource": "aws.iam-user",
            "description": "CIS unused credentials",
            "filters": [],
            "resources": [
                {"UserName": "alice", "Arn": "arn:aws:iam::111122223333:user/alice"},
                {"UserName": "alice", "Arn": "arn:aws:iam::444455556666:user/alice"},
            ],
        }
    )
    ids = [r["ResourceId"] for r in recs]
    assert ids == [
        "arn:aws:iam::111122223333:user/alice",
        "arn:aws:iam::444455556666:user/alice",
    ]
    assert len(set(ids)) == 2


def test_n_security_groups_give_n_distinct_refs() -> None:
    recs = cloud_prowler._custodian_findings(
        {
            "name": "sg-public-ingress",
            "resource": "aws.security-group",
            "description": "security groups with public ingress",
            "filters": [],
            "resources": [
                {"GroupId": "sg-0eee", "VpcId": "vpc-aaa", "OwnerId": "111122223333"},
                {"GroupId": "sg-0fff", "VpcId": "vpc-aaa", "OwnerId": "111122223333"},
            ],
        }
    )
    assert [r["ResourceId"] for r in recs] == ["sg-0eee", "sg-0fff"]
    refs = [make_ref("cloud-prowler", f"sg-public-ingress-{r['ResourceId']}") for r in recs]
    assert len(set(refs)) == 2
    assert all(r["ResourceId"] != "sg-public-ingress" for r in recs)


def test_n_lambdas_give_n_distinct_refs() -> None:
    recs = cloud_prowler._custodian_findings(
        {
            "name": "lambda-public-access",
            "resource": "aws.lambda",
            "description": "lambdas with public access",
            "filters": [],
            "resources": [
                {
                    "FunctionArn": "arn:aws:lambda:us-east-1:1:function:alpha",
                    "FunctionName": "alpha",
                    "Role": "arn:aws:iam::1:role/lambda",
                },
                {
                    "FunctionArn": "arn:aws:lambda:us-east-1:1:function:beta",
                    "FunctionName": "beta",
                    "Role": "arn:aws:iam::1:role/lambda",
                },
            ],
        }
    )
    assert [r["ResourceId"] for r in recs] == [
        "arn:aws:lambda:us-east-1:1:function:alpha",
        "arn:aws:lambda:us-east-1:1:function:beta",
    ]
    refs = [make_ref("cloud-prowler", f"lambda-public-access-{r['ResourceId']}") for r in recs]
    assert len(set(refs)) == 2


def test_ami_image_id_is_primary() -> None:
    assert (
        cloud_prowler._custodian_resource_id(
            {"ImageId": "ami-0abc", "OwnerId": "111122223333"}, "aws.ami"
        )
        == "ami-0abc"
    )


def test_multi_resource_never_falls_back_to_policy_name() -> None:
    recs = cloud_prowler._custodian_findings(
        {
            "name": "mystery-policy",
            "resource": "aws.something",
            "description": "security check",
            "filters": [],
            "resources": [
                {"KmsKeyId": "arn:aws:kms:us-east-1:1:key/aaa", "OwnerId": "1"},
                {"KmsKeyId": "arn:aws:kms:us-east-1:1:key/bbb", "OwnerId": "1"},
            ],
        }
    )
    ids = [r["ResourceId"] for r in recs]
    assert ids == ["mystery-policy-1", "mystery-policy-2"]
    assert len(set(ids)) == 2


def test_asset_key_is_not_first_star_id() -> None:
    res = {
        "KmsKeyId": "arn:aws:kms:us-east-1:1:key/kms-should-not-win",
        "OwnerId": "owner-should-not-win",
        "SnapshotId": "snap-084bf49b944409f37",
        "c7n:CrossAccountViolations": ["123"],
    }
    assert (
        cloud_prowler._custodian_resource_id(res, "aws.ebs-snapshot")
        == "snap-084bf49b944409f37"
    )
    no_primary = {
        "KmsKeyId": "arn:aws:kms:us-east-1:1:key/kms-should-not-win",
        "OwnerId": "owner-should-not-win",
    }
    assert cloud_prowler._custodian_resource_id(no_primary, "aws.ebs-snapshot") == ""


def test_eight_azure_refs_are_distinct() -> None:
    recs = cloud_prowler.parse_file(CLOUD / "stop-underutilized-azure-vms" / "resources.json")
    refs = [r["ref_id"] for r in recs if r.get("kind") in {"finding", "excluded"}]
    assert len(refs) == 8
    assert len(set(refs)) == 8
    rows = json.loads((CLOUD / "stop-underutilized-azure-vms" / "resources.json").read_text())
    arms = [str(r["id"]) for r in rows]
    ident = [make_ref("cloud-prowler", f"stop-underutilized-azure-vms-{arm}") for arm in arms]
    assert len(set(ident)) == 8


def test_c7n_annotations_still_detect_resources() -> None:
    ebs = json.loads((CLOUD / "check-ebs-snapshot-public" / "resources.json").read_text())
    assert any("c7n:CrossAccountViolations" in row for row in ebs)
    aws = json.loads((CLOUD / "stop-underutilized-aws-instances" / "resources.json").read_text())
    assert any("c7n.metrics" in row for row in aws)
    recs = cloud_prowler.parse_file(CLOUD / "check-ebs-snapshot-public" / "resources.json")
    assert _findings(recs)
    assert "snap-084bf49b944409f37" in (_findings(recs)[0].get("assets") or [])


def test_nmap_excluded_rows_are_unchanged() -> None:
    dest = SAMPLES / "udpConnect_10.11.1.0-254.xml"
    recs = inventory_nmap.parse_file(dest)
    excluded = [
        r
        for r in recs
        if r["kind"] == "finding" and (r.get("extra") or {}).get("not_a_weakness")
    ]
    assert excluded
    for rec in excluded:
        decision = poam_decision(rec)
        assert decision["include"] is False
        assert decision["reason"] == "not_a_weakness"
        mapped = map_finding(rec)
        blob = f"{mapped.get('control_name')} {mapped.get('recommended_fix')} {mapped.get('weakness_name')}"
        assert "Cost or operations" not in blob
        assert "Cloud Custodian" not in blob
        assert "unmapped Custodian" not in blob


def test_demo_custodian_encrypt_still_a_finding() -> None:
    recs = cloud_prowler.parse_file(DEMO / "cloud" / "custodian.json")
    findings = _findings(recs)
    assert findings
    assert any("demo-unencrypted-tmp" in str(r.get("assets")) for r in findings)
    assert findings[0]["extra"].get("exclude_reason") != "NOT_A_WEAKNESS"
    assert poam_decision(findings[0])["include"] is True


def test_unknown_custodian_policy_is_needs_review_never_dropped() -> None:
    """Fail-closed: no known class → POA&M needs-review, not a silent drop."""
    for name, resource, desc in (
        ("rds-publicly-accessible", "aws.rds", "RDS instances that are publicly accessible"),
        ("cloudtrail-not-enabled", "aws.cloudtrail", "CloudTrail is not enabled"),
        ("guardduty-disabled", "aws.guardduty", "GuardDuty detector is disabled"),
    ):
        assert cloud_prowler._custodian_classify(
            name, {"description": desc, "resource": resource, "filters": []}
        ) == "unknown"
        recs = cloud_prowler._custodian_findings(
            {
                "name": name,
                "resource": resource,
                "description": desc,
                "filters": [],
                "resources": [{"id": f"{name}-res-1"}],
            }
        )
        assert recs
        assert recs[0].get("NeedsReview") is True
        assert recs[0].get("ExcludeReason") != "NOT_A_WEAKNESS"
        assert recs[0]["Status"] == "FAIL"


def test_synthetic_eleven_security_policies_never_drop_unknown() -> None:
    """8 of 11 named security policies used to vanish; unknown now needs-review."""
    known = {
        "s3-encryption-missing": "aws.s3",
        "security-context-pods": "k8s.pod",
        "check-ebs-snapshot-public": "aws.ebs-snapshot",
    }
    unknown = {
        "rds-publicly-accessible": "aws.rds",
        "cloudtrail-not-enabled": "aws.cloudtrail",
        "guardduty-disabled": "aws.guardduty",
        "vpc-flow-logs-disabled": "aws.vpc",
        "s3-versioning-disabled": "aws.s3",
        "lambda-env-plaintext": "aws.lambda",
        "ebs-snapshot-retention": "aws.ebs-snapshot",
        "config-recorder-off": "aws.config",
    }
    assert len(known) + len(unknown) == 11
    on_plan = []
    dropped = []
    for name, resource in {**known, **unknown}.items():
        recs = cloud_prowler._custodian_findings(
            {
                "name": name,
                "resource": resource,
                "description": name.replace("-", " "),
                "filters": [],
                "resources": [{"id": f"{name}-1"}],
            }
        )
        if not recs or recs[0].get("ExcludeReason") == "NOT_A_WEAKNESS":
            dropped.append(name)
            continue
        on_plan.append(name)
        if name in unknown:
            assert recs[0].get("NeedsReview") is True
        else:
            assert recs[0].get("NeedsReview") in (None, False)
    assert dropped == []
    assert len(on_plan) == 11


def test_unknown_needs_review_rolls_up_per_policy() -> None:
    """Two unknown policies × many resources → two rollup items, not N."""
    recs = cloud_prowler._custodian_findings(
        {
            "policies": [
                {
                    "name": "require-owner-tag",
                    "resource": "aws.ec2",
                    "description": "stage label",
                    "filters": [],
                    "resources": [
                        {"InstanceId": f"i-aaa{i:03d}", "AccountId": "111122223333"}
                        for i in range(20)
                    ],
                },
                {
                    "name": "snapshot-age-days",
                    "resource": "aws.ec2",
                    "description": "age window",
                    "filters": [],
                    "resources": [
                        {"InstanceId": f"i-bbb{i:03d}", "AccountId": "111122223333"}
                        for i in range(20)
                    ],
                },
            ]
        }
    )
    assert len(recs) == 2
    assert {r["CheckID"] for r in recs} == {"require-owner-tag", "snapshot-age-days"}
    for item in recs:
        assert item.get("NeedsReview") is True
        assert item.get("Rollup") is True
        assert item["AffectedCount"] == 20
        assert item["ResourceId"] == "account:111122223333"
        assert item["AffectedResources"] == sorted(item["AffectedResources"])
