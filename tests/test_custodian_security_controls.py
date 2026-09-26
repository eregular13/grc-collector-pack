"""CR6-4: Custodian security-policy / security-context → honest 800-53.

security-context-pods is a Moderate finding (real c7n has no severity).
High/Critical never ship blank Controls. Moderate blanks are the
tested needs-review path, not a silent gap. SAMPLE ≠ client KEEP.
No POST /api/risks. Does not rewrite FedRAMP export or pack_drop.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from collectors import cloud_prowler
from shared.control_map import map_finding, poam_decision
from shared.finding_types import finding_type
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


def test_high_unmapped_custodian_security_is_excluded() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian lambda-env-plaintext",
        description="Lambda environment variables in plaintext",
        severity="high",
        extra={"check_id": "lambda-env-plaintext", "classification": "security"},
    )
    mapped = map_finding(rec)
    assert not (mapped.get("nist_800_53") or [])
    assert mapped.get("include_poam") is False
    assert mapped["control_name"] == "Unmapped Custodian security policy"
    assert "unmapped" in mapped["recommended_fix"].lower()
    decision = poam_decision(rec)
    assert decision["include"] is False
    assert decision["reason"] == "unmapped"
    assert decision["severity"] == "high"
    assert poam_fields(rec, mapped, date(2026, 9, 26))["controls"] == ""


def test_critical_unmapped_custodian_security_is_excluded() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian lambda-env-plaintext",
        description="Lambda environment variables in plaintext",
        severity="critical",
        extra={"check_id": "lambda-env-plaintext", "classification": "security"},
    )
    decision = poam_decision(rec)
    assert decision["include"] is False
    assert decision["reason"] == "unmapped"
    assert decision["severity"] == "critical"
    assert not (map_finding(rec).get("nist_800_53") or [])


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


def test_high_needs_review_blank_controls_is_excluded() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian require-owner-tag",
        description="stage label",
        severity="high",
        extra={
            "check_id": "require-owner-tag",
            "needs_review": True,
            "classification": "needs-review",
        },
    )
    mapped = map_finding(rec)
    assert not (mapped.get("nist_800_53") or [])
    decision = poam_decision(rec)
    assert decision["include"] is False
    assert decision["reason"] == "unmapped"
    assert poam_fields(rec, mapped, date(2026, 9, 26))["controls"] == ""


def test_moderate_unmapped_classified_security_is_excluded() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian lambda-env-plaintext",
        description="Lambda environment variables in plaintext",
        severity="medium",
        extra={"check_id": "lambda-env-plaintext", "classification": "security"},
    )
    mapped = map_finding(rec)
    assert not (mapped.get("nist_800_53") or [])
    assert mapped["control_name"] == "Unmapped Custodian security policy"
    decision = poam_decision(rec)
    assert decision["include"] is False
    assert decision["reason"] == "unmapped"


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
