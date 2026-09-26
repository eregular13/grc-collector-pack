"""CR6-4: Custodian security-policy / security-context → honest 800-53.

security-context-pods is a Moderate finding (real c7n has no severity).
Unmapped Custodian security (including High GuardDuty / KMS rotation)
stays on the POA&M — never excluded as unmapped. Open RDP joins the
public-SSH internet-facing SG class. SAMPLE ≠ client KEEP.
No POST /api/risks. Does not rewrite FedRAMP export or pack_drop.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from collectors import cloud_prowler
from shared.control_map import map_finding, poam_decision
from shared.finding_types import finding_type
from shared.framework_class_map import is_internet_facing
from shared.poam_fields import poam_fields
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]
CLOUD = ROOT / "fixtures" / "samples" / "cloud"


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r["kind"] == "finding"]


def _custodian_finding(
    *,
    name: str = "Cloud Custodian mystery-policy",
    description: str = "unclassified policy",
    severity: str = "medium",
    extra: dict | None = None,
    assets: list[str] | None = None,
) -> dict:
    payload = dict(extra or {})
    payload.setdefault("check_id", "mystery-policy")
    payload.setdefault("status", "FAIL")
    return make_record(
        kind="finding",
        source="cloud-prowler",
        ref_id="CLD-c7n-test",
        name=name,
        description=description,
        severity=severity,
        category="cloud-misconfiguration",
        assets=assets or ["res-1"],
        extra=payload,
    )


def test_security_context_pods_stamps_ac6_cm6_cm7() -> None:
    recs = cloud_prowler.parse_file(CLOUD / "security-context-pods" / "resources.json")
    hit = _findings(recs)[0]
    assert finding_type(hit) == "k8s_security_context"
    mapped = map_finding(hit)
    assert mapped.get("generic") is False
    assert mapped["control_name"] == "Require a Kubernetes container securityContext"
    assert {"AC-6", "CM-6", "CM-7"} <= set(mapped.get("nist_800_53") or [])
    blob = mapped["recommended_fix"].lower()
    compact = blob.replace(" ", "").replace("_", "").replace("-", "")
    assert "securitycontext" in compact
    assert "not a privileged=true admission finding" in blob
    fields = poam_fields(hit, mapped, date(2026, 9, 26))
    assert fields["controls"]
    assert "AC-6" in fields["controls"]
    decision = poam_decision(hit)
    assert decision["include"] is True
    assert decision["reason"] in {"key_medium", "severity_medium"}


def test_security_context_class_maps_from_policy_name() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian require-sec-con-on-pods",
        description="Pods missing container securityContext",
        extra={"check_id": "require-sec-con-on-pods", "classification": "security"},
    )
    assert finding_type(rec) == "k8s_security_context"
    mapped = map_finding(rec)
    assert {"AC-6", "CM-6", "CM-7"} <= set(mapped.get("nist_800_53") or [])
    assert poam_decision(rec)["include"] is True


def test_high_custodian_security_context_keeps_controls() -> None:
    recs = cloud_prowler.parse_file(CLOUD / "security-context-pods" / "resources.json")
    hit = dict(_findings(recs)[0])
    hit["severity"] = "high"
    mapped = map_finding(hit)
    assert mapped.get("nist_800_53")
    assert poam_fields(hit, mapped, date(2026, 9, 26))["controls"]
    decision = poam_decision(hit)
    assert decision["include"] is True
    assert decision["severity"] == "high"


def test_high_guardduty_disabled_stays_on_poam() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian guardduty-disabled-high",
        description="GuardDuty detector is disabled",
        severity="high",
        extra={
            "check_id": "guardduty-disabled-high",
            "needs_review": True,
            "classification": "needs-review",
        },
    )
    decision = poam_decision(rec)
    assert decision["include"] is True
    assert decision["reason"] == "needs_review"
    assert decision["severity"] == "high"


def test_high_kms_rotation_stays_on_poam() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian kms-secret-no-rotation",
        description="KMS key rotation is disabled",
        severity="high",
        extra={
            "check_id": "kms-secret-no-rotation",
            "classification": "security",
        },
    )
    decision = poam_decision(rec)
    assert decision["include"] is True
    assert decision["reason"] == "severity_high_critical"
    assert decision["severity"] == "high"


def test_high_classified_security_without_mapping_stays_on_poam() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian iam-admin-policy-attached",
        description="IAM admin policy is attached",
        severity="high",
        extra={"check_id": "iam-admin-policy-attached", "classification": "security"},
    )
    mapped = map_finding(rec)
    decision = poam_decision(rec)
    assert decision["include"] is True
    assert decision["reason"] == "severity_high_critical"
    assert mapped.get("include_poam") is not False or mapped.get("nist_800_53")


def test_moderate_needs_review_blank_controls_is_intentional() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian require-owner-tag",
        description="stage label",
        severity="medium",
        extra={
            "check_id": "require-owner-tag",
            "needs_review": True,
            "classification": "needs-review",
        },
    )
    mapped = map_finding(rec)
    assert mapped["finding_type"] == "needs_review"
    assert not (mapped.get("nist_800_53") or [])
    fields = poam_fields(rec, mapped, date(2026, 9, 26))
    assert fields["controls"] == ""
    decision = poam_decision(rec)
    assert decision["include"] is True
    assert decision["reason"] == "needs_review"


def test_public_ssh_custodian_stays_on_plan_with_controls() -> None:
    recs = cloud_prowler._custodian_findings(
        {
            "name": "stop-public-ssh-instances",
            "resource": "aws.ec2",
            "description": "SSH open to 0.0.0.0/0",
            "filters": [{"type": "ingress", "CidrIp": "0.0.0.0/0", "FromPort": 22}],
            "resources": [{"InstanceId": "i-ssh01"}],
        }
    )
    rec = make_record(
        kind="finding",
        source="cloud-prowler",
        ref_id="CLD-ssh",
        name=recs[0]["CheckTitle"],
        description=recs[0]["Description"],
        severity="medium",
        category="cloud-misconfiguration",
        assets=[recs[0]["ResourceId"]],
        extra={"check_id": recs[0]["CheckID"], "classification": "security"},
    )
    assert finding_type(rec) == "sg_ingress_open"
    mapped = map_finding(rec)
    assert mapped.get("nist_800_53")
    assert poam_decision(rec)["include"] is True
    assert is_internet_facing(rec, mapped) is True


def test_open_rdp_custodian_is_internet_facing_sg_ingress() -> None:
    recs = cloud_prowler._custodian_findings(
        {
            "name": "sg-open-rdp",
            "resource": "aws.security-group",
            "description": "RDP 3389 open to 0.0.0.0/0",
            "filters": [{"type": "ingress", "CidrIp": "0.0.0.0/0", "FromPort": 3389}],
            "resources": [{"GroupId": "sg-rdp01"}],
        }
    )
    rec = make_record(
        kind="finding",
        source="cloud-prowler",
        ref_id="CLD-rdp",
        name=recs[0]["CheckTitle"],
        description=recs[0]["Description"],
        severity="medium",
        category="cloud-misconfiguration",
        assets=[recs[0]["ResourceId"]],
        extra={"check_id": recs[0]["CheckID"], "classification": "security"},
    )
    assert finding_type(rec) == "sg_ingress_open"
    mapped = map_finding(rec)
    assert "SC-7" in set(mapped.get("nist_800_53") or [])
    assert poam_decision(rec)["include"] is True
    assert is_internet_facing(rec, mapped) is True


def test_prowler_non_custodian_high_is_not_forced_unmapped() -> None:
    rec = make_record(
        kind="finding",
        source="cloud-prowler",
        ref_id="CLD-s3-enc",
        name="S3 bucket server-side encryption",
        description="ASFF export: encryption not enforced.",
        severity="high",
        category="cloud-misconfiguration",
        assets=["arn:aws:s3:::demo-public-assets"],
        extra={"check_id": "s3_bucket_server_side_encryption_enabled", "service": "s3"},
    )
    assert finding_type(rec) == "s3_encryption"
    decision = poam_decision(rec)
    assert decision["include"] is True
    assert map_finding(rec).get("nist_800_53")
