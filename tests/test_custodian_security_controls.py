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


SG_INGRESS_FIX = "Remove 0.0.0.0/0 ingress"


def _custodian_finding(
    *,
    name: str = "Cloud Custodian mystery-policy",
    description: str = "unclassified policy",
    severity: str = "medium",
    extra: dict | None = None,
    assets: list[str] | None = None,
    labels: list[str] | None = None,
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
        labels=labels,
        extra=payload,
    )


def _from_c7n_policy(pol: dict) -> dict:
    """Canonical-shaped row from a Custodian policy payload (real description)."""
    items = cloud_prowler._custodian_findings(pol)
    assert items, pol.get("name")
    item = items[0]
    extra = {
        "check_id": item["CheckID"],
        "classification": item.get("Classification") or "security",
        "service": item.get("ServiceName"),
        "resource_type": item.get("ResourceType"),
        "arn": item.get("ResourceArn"),
    }
    return make_record(
        kind="finding",
        source="cloud-prowler",
        ref_id="CLD-c7n-probe",
        name=item["CheckTitle"],
        description=item["Description"],
        severity="medium",
        category="cloud-misconfiguration",
        assets=[item["ResourceId"]],
        labels=["cloud", str(item.get("ServiceName") or "")],
        extra=extra,
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


def test_wordpress_public_is_not_sg_ingress_open() -> None:
    """'rdp' is a substring of 'wordpress' — must not steal the SG-ingress class."""
    for name in ("lightsail-wordpress-public", "wordpress-public-bucket"):
        rec = _custodian_finding(
            name=f"Cloud Custodian {name}",
            description="WordPress site published on a public endpoint",
            extra={"check_id": name, "classification": "security"},
        )
        assert finding_type(rec) != "sg_ingress_open", name
        assert SG_INGRESS_FIX not in map_finding(rec)["recommended_fix"], name


def test_s3_public_read_security_blurb_is_not_sg_ingress_open() -> None:
    rec = _from_c7n_policy(
        {
            "name": "s3-public-read",
            "resource": "aws.s3",
            "description": "Security: S3 bucket allows public read",
            "resources": [{"Name": "public-read-bucket"}],
        }
    )
    assert finding_type(rec) == "s3_public_access"
    mapped = map_finding(rec)
    assert SG_INGRESS_FIX not in mapped["recommended_fix"]
    assert "public ACL" in mapped["recommended_fix"] or "public ACLs" in mapped["recommended_fix"]


def test_ebs_public_snapshot_security_paren_is_not_sg_ingress_open() -> None:
    rec = _from_c7n_policy(
        {
            "name": "ebs-snapshot-public",
            "resource": "aws.ebs",
            "description": "Public EBS snapshot (security)",
            "resources": [{"SnapshotId": "snap-abc01"}],
        }
    )
    assert finding_type(rec) == "ebs_snapshot_public"
    mapped = map_finding(rec)
    assert SG_INGRESS_FIX not in mapped["recommended_fix"]
    assert "EBS snapshot private" in mapped["recommended_fix"]


def test_bucket_named_security_logs_is_not_sg_ingress_open() -> None:
    rec = _from_c7n_policy(
        {
            "name": "s3-bucket-public",
            "resource": "aws.s3",
            "resources": [{"Name": "acme-security-logs"}],
        }
    )
    assert rec["description"].startswith("Policy ")
    assert "acme-security-logs" in rec["description"]
    assert rec["assets"] == ["acme-security-logs"]
    assert finding_type(rec) != "sg_ingress_open"
    assert SG_INGRESS_FIX not in map_finding(rec)["recommended_fix"]


def test_wordpress_security_review_is_not_sg_ingress_open() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian lightsail-wordpress-public",
        description="Security review: public WordPress instance",
        extra={"check_id": "lightsail-wordpress-public", "classification": "security"},
        assets=["i-wordpress01"],
    )
    assert finding_type(rec) != "sg_ingress_open"
    assert SG_INGRESS_FIX not in map_finding(rec)["recommended_fix"]


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


def test_rdp_token_in_policy_name_is_sg_ingress_open() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian sg-open-rdp-ingress",
        description="Security group allows inbound RDP from the internet",
        extra={"check_id": "sg-open-rdp-ingress", "classification": "security"},
    )
    assert finding_type(rec) == "sg_ingress_open"


def test_camelcase_and_digit_admin_ports_are_sg_ingress_open() -> None:
    cases = (
        "OpenRdpPort",
        "sgOpenSSH",
        "rdp3389",
        "ssh22-open",
        "sg-open-rdp",
    )
    for check_id in cases:
        rec = _custodian_finding(
            name=f"Cloud Custodian {check_id}",
            description="internet-facing admin port",
            extra={"check_id": check_id, "classification": "security"},
        )
        assert finding_type(rec) == "sg_ingress_open", check_id
        assert SG_INGRESS_FIX in map_finding(rec)["recommended_fix"], check_id


def test_sshd_and_33890_are_not_sg_ingress_open() -> None:
    cases = (
        ("sshd-public", "sshd config allows open root login"),
        ("port-33890-open", "port 33890 open"),
    )
    for check_id, description in cases:
        rec = _custodian_finding(
            name=f"Cloud Custodian {check_id}",
            description=description,
            extra={"check_id": check_id, "classification": "security"},
        )
        assert finding_type(rec) != "sg_ingress_open", check_id
        assert SG_INGRESS_FIX not in map_finding(rec)["recommended_fix"], check_id


def test_sg_token_in_description_only_is_not_sg_ingress() -> None:
    """Bare 'sg' is accepted from check_id/name, never from free text."""
    rec = _custodian_finding(
        name="Cloud Custodian lambda-ingress",
        description="Lambda ingress restricted to sg members",
        extra={"check_id": "lambda-ingress", "classification": "security"},
    )
    assert finding_type(rec) != "sg_ingress_open"
    assert SG_INGRESS_FIX not in map_finding(rec)["recommended_fix"]
    alb = _custodian_finding(
        name="Cloud Custodian alb-public-ingress",
        description="ALB ingress rules; see SG docs",
        extra={"check_id": "alb-public-ingress", "classification": "security"},
    )
    assert finding_type(alb) != "sg_ingress_open"


def test_nonadjacent_security_and_group_is_not_sg_ingress() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian review-group-security",
        description="security review for the finance group; ingress logs retained",
        extra={"check_id": "review-group-security", "classification": "security"},
    )
    assert finding_type(rec) != "sg_ingress_open"
    assert SG_INGRESS_FIX not in map_finding(rec)["recommended_fix"]


def test_adjacent_security_group_phrase_is_sg_ingress() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian web-ingress-open",
        description="Security group allows ingress from 0.0.0.0/0 on 8080",
        extra={"check_id": "web-ingress-open", "classification": "security"},
    )
    assert finding_type(rec) == "sg_ingress_open"
    assert SG_INGRESS_FIX in map_finding(rec)["recommended_fix"]


def test_azure_nsg_open_ingress_is_sg_ingress() -> None:
    rec = _from_c7n_policy(
        {
            "name": "azure-nsg-open-ingress",
            "resource": "azure.networksecuritygroup",
            "description": "Network security group allows inbound from the internet",
            "filters": [{"type": "ingress", "Cidr": "0.0.0.0/0"}],
            "resources": [{"id": "/nsg/web-in"}],
        }
    )
    assert finding_type(rec) == "sg_ingress_open"
    mapped = map_finding(rec)
    assert SG_INGRESS_FIX in mapped["recommended_fix"]
    assert "SC-7" in set(mapped.get("nist_800_53") or [])
    named = _custodian_finding(
        name="Cloud Custodian azure-nsg-open-ingress",
        description="NSG ingress from 0.0.0.0/0",
        extra={"check_id": "azure-nsg-open-ingress", "classification": "security"},
    )
    assert finding_type(named) == "sg_ingress_open"


def test_rdp_gateway_public_is_rd_gateway_exposed() -> None:
    """RD Gateway is an intended internet broker — typed, not open-3389 SG."""
    want = {
        "AC-17",
        "AC-17(3)",
        "IA-2(1)",
        "IA-2(2)",
        "AC-7",
        "SI-2",
        "SC-7",
    }
    for check_id in ("RDPGatewayPublic", "OpenRDPGateway"):
        rec = _custodian_finding(
            name=f"Cloud Custodian {check_id}",
            description="RD Gateway published on the internet",
            extra={"check_id": check_id, "classification": "security"},
        )
        assert finding_type(rec) == "rd_gateway_exposed", check_id
        mapped = map_finding(rec)
        assert finding_type(rec) != "sg_ingress_open"
        assert SG_INGRESS_FIX not in mapped["recommended_fix"]
        assert mapped["control_name"] == "Harden the public Remote Desktop Gateway"
        assert want <= set(mapped.get("nist_800_53") or [])
        assert mapped["csf_subcategory"] == "PR.AA-03"
        assert "csf_PR_IR_01" in mapped["framework_refs"]
        assert "csf_PR_IR_01" in mapped["csf"]
        assert "csf 2.0" not in mapped["recommended_fix"].lower()
        assert "primary" not in mapped["recommended_fix"].lower()
        assert "secondary" not in mapped["recommended_fix"].lower()
        assert "mfa" in mapped["recommended_fix"].lower()
        assert "aa20-014a" in mapped["recommended_fix"].lower()
    # Bare RDP on an SG stays the open-3389 class.
    rdp = _custodian_finding(
        name="Cloud Custodian PublicRDPAccess",
        description="RDP open to the internet",
        extra={"check_id": "PublicRDPAccess", "classification": "security"},
    )
    assert finding_type(rdp) == "sg_ingress_open"


def test_rdgatewaypublic_non_alias_is_rd_gateway_exposed() -> None:
    """Mutant-kill: RD Gateway branch, not only TYPE_ALIASES."""
    rec = _custodian_finding(
        name="Cloud Custodian RDGatewayPublic",
        description="published on the internet",
        extra={"check_id": "RDGatewayPublic", "classification": "security"},
    )
    assert finding_type(rec) == "rd_gateway_exposed"
    mapped = map_finding(rec)
    assert mapped["csf_subcategory"] == "PR.AA-03"
    assert "csf_PR_IR_01" in mapped["framework_refs"]
    assert "csf_PR_IR_01" in mapped["csf"]


def test_rd_gateway_without_exposure_is_not_typed() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian rd-gateway-internal",
        description="RD Gateway is configured on an internal listener",
        extra={"check_id": "rd-gateway-internal", "classification": "security"},
    )
    assert finding_type(rec) != "rd_gateway_exposed"
    assert finding_type(rec) != "sg_ingress_open"


def test_standard_dashboard_card_gateway_phrases_are_not_rd_gateway() -> None:
    cases = (
        (
            "ec2-rdp-public",
            "RDP open to 0.0.0.0/0 via the standard gateway",
            "sg_ingress_open",
        ),
        (
            "ec2-ssh-public",
            "SSH on the onboard gateway host is public",
            "sg_ingress_open",
        ),
        (
            "s3-bucket-open",
            "bucket served to the payment card gateway",
            "",
        ),
        (
            "elb-public",
            "ELB fronts the dashboard gateway",
            "",
        ),
    )
    for check_id, desc, want in cases:
        rec = _custodian_finding(
            name=f"Cloud Custodian {check_id}",
            description=desc,
            extra={"check_id": check_id, "classification": "security"},
        )
        got = finding_type(rec)
        assert got != "rd_gateway_exposed", (check_id, desc, got)
        if want:
            assert got == want, (check_id, desc, got)


def test_standard_dashboard_card_gateway_ids_are_not_rd_gateway() -> None:
    """Compact regex on concatenated id+name must not type rd+gateway substrings."""
    cases = (
        "vpc-standard-gateway-open",
        "dashboard-gateway-public",
        "payment-card-gateway-open",
        "onboard-gateway-rdp-open",
        "standard_gateway_open",
    )
    for check_id in cases:
        rec = _custodian_finding(
            name=f"Cloud Custodian {check_id}",
            description="published on the internet",
            extra={"check_id": check_id, "classification": "security"},
        )
        got = finding_type(rec)
        assert got != "rd_gateway_exposed", (check_id, got)


def test_rd_gateway_snake_and_name_phrase_are_rd_gateway_exposed() -> None:
    snake = _custodian_finding(
        name="Cloud Custodian rd_gateway_public",
        description="published on the internet",
        extra={"check_id": "rd_gateway_public", "classification": "security"},
    )
    assert finding_type(snake) == "rd_gateway_exposed"
    named = _custodian_finding(
        name="RD Gateway",
        description="published on the internet",
        extra={"check_id": "cloud-policy-public", "classification": "security"},
    )
    assert finding_type(named) == "rd_gateway_exposed"
    compact = _custodian_finding(
        name="Cloud Custodian rdgateway-open",
        description="published on the internet",
        extra={"check_id": "rdgateway-open", "classification": "security"},
    )
    assert finding_type(compact) == "rd_gateway_exposed"


def test_nat_gateway_in_description_does_not_untype_public_rdp() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian ec2-rdp-public",
        description="Instances behind a NAT gateway allow RDP from 0.0.0.0/0",
        extra={"check_id": "ec2-rdp-public", "classification": "security"},
    )
    assert finding_type(rec) == "sg_ingress_open"
    assert SG_INGRESS_FIX in map_finding(rec)["recommended_fix"]
    igw = _custodian_finding(
        name="Cloud Custodian ec2-rdp-public",
        description="Security group behind an internet gateway allows RDP",
        extra={"check_id": "ec2-rdp-public", "classification": "security"},
    )
    assert finding_type(igw) == "sg_ingress_open"


def test_azure_arm_networksecuritygroups_resource_is_sg_ingress() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian azure-nsg-open-ingress",
        description="ingress from 0.0.0.0/0",
        extra={
            "check_id": "azure-nsg-open-ingress",
            "classification": "security",
            "resource_type": "microsoft.network/networksecuritygroups",
        },
    )
    assert finding_type(rec) == "sg_ingress_open"
    assert SG_INGRESS_FIX in map_finding(rec)["recommended_fix"]


def test_plural_security_groups_prose_is_not_sg_ingress() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian rds-ingress-logging",
        description="RDS ingress logging is enabled; see security groups doc",
        extra={"check_id": "rds-ingress-logging", "classification": "security"},
    )
    assert finding_type(rec) != "sg_ingress_open"
    assert SG_INGRESS_FIX not in map_finding(rec)["recommended_fix"]


def test_plural_network_security_groups_prose_is_not_sg_ingress() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian rds-ingress-logging",
        description="RDS ingress logging is enabled; see network security groups doc",
        extra={"check_id": "rds-ingress-logging", "classification": "security"},
    )
    assert finding_type(rec) != "sg_ingress_open"


def test_azure_application_security_group_is_not_sg_ingress() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian asg-ingress",
        description="application security group ingress from the internet",
        extra={
            "check_id": "asg-ingress",
            "classification": "security",
            "resource_type": "microsoft.network/applicationsecuritygroups",
        },
    )
    assert finding_type(rec) != "sg_ingress_open"
    compact = _custodian_finding(
        name="Cloud Custodian asg-ingress",
        description="applicationsecuritygroup ingress from the internet",
        extra={"check_id": "asg-ingress", "classification": "security"},
    )
    assert finding_type(compact) != "sg_ingress_open"


def test_checkov_ckv_aws_24_and_260_are_sg_ingress() -> None:
    for cid in ("CKV_AWS_24", "CKV_AWS_260"):
        rec = make_record(
            kind="finding",
            source="code-secrets",
            ref_id=f"CODE-{cid}",
            name=f"Checkov {cid}",
            description="Security groups allow ingress from 0.0.0.0/0",
            severity="high",
            category="misconfiguration",
            assets=["sg-1"],
            extra={"check_id": cid},
        )
        assert finding_type(rec) == "sg_ingress_open", cid


def test_plural_security_groups_check_id_is_sg_ingress() -> None:
    rec = _custodian_finding(
        name="Cloud Custodian ec2-security-groups-ingress-open",
        description="inbound from the internet",
        extra={
            "check_id": "ec2-security-groups-ingress-open",
            "classification": "security",
        },
    )
    assert finding_type(rec) == "sg_ingress_open"


def test_nested_arm_nsg_securityrules_is_sg_ingress() -> None:
    """resource_type kind split only — check_id/name stay off nsg/sg tokens."""
    rec = _custodian_finding(
        name="Cloud Custodian open-ingress",
        description="ingress from the internet",
        extra={
            "check_id": "open-ingress",
            "classification": "security",
            "resource_type": "microsoft.network/networksecuritygroups/securityrules",
        },
    )
    assert finding_type(rec) == "sg_ingress_open"


def test_description_only_network_security_group_is_sg_ingress() -> None:
    """Mutant-kill m110: description phrase alone types SG ingress."""
    rec = _custodian_finding(
        name="Cloud Custodian policy-open",
        description="Network security group allows ingress",
        extra={"check_id": "policy-open", "classification": "security"},
    )
    assert finding_type(rec) == "sg_ingress_open"


def test_ad_feed_security_group_is_not_sg_ingress() -> None:
    rec = make_record(
        kind="finding",
        source="identity-ad",
        ref_id="ID-da",
        name="Domain Admins security group listed",
        description="Domain Admins is a privileged security group; ingress N/A",
        severity="high",
        category="identity-gap",
        assets=["CORP\\Domain Admins"],
        extra={"check_id": "domain-admins", "edge": "DomainAdmins"},
    )
    assert finding_type(rec) != "sg_ingress_open"
    assert finding_type(rec) != "rd_gateway_exposed"


def test_identity_ad_security_group_cidr_is_not_sg_ingress() -> None:
    """Mutant-kill: dropping the identity-ad heuristic exclusion."""
    rec = make_record(
        kind="finding",
        source="identity-ad",
        ref_id="ID-corp-sg",
        name="Corp Users security group listed",
        description="security group members noted; 0.0.0.0/0 is not a CIDR filter",
        severity="high",
        category="identity-gap",
        assets=["CORP\\Users"],
        extra={"check_id": "corp-users"},
    )
    assert finding_type(rec) != "sg_ingress_open"


def test_sg_ingress_requires_ingress_token() -> None:
    """Mutant-kill: dropping the ingress requirement types non-ingress SG rows."""
    rec = _custodian_finding(
        name="Cloud Custodian sg-default-restrict",
        description="Default security group has no extra rules",
        extra={
            "check_id": "sg-default-restrict",
            "classification": "security",
            "resource_type": "aws.security-group",
        },
    )
    assert finding_type(rec) != "sg_ingress_open"


def test_ingress_without_sg_signal_is_not_sg_ingress() -> None:
    """Mutant-kill: dropping the security-group phrase types any ingress row."""
    rec = _custodian_finding(
        name="Cloud Custodian lambda-public-ingress",
        description="Lambda function ingress from the internet",
        extra={"check_id": "lambda-public-ingress", "classification": "security"},
    )
    assert finding_type(rec) != "sg_ingress_open"


def test_compound_securitygroup_check_id_is_sg_ingress() -> None:
    """Mutant-kill: removing the no-separator securitygroup match."""
    rec = _custodian_finding(
        name="Cloud Custodian SecurityGroupIngressOpen",
        description="inbound from the internet",
        extra={"check_id": "SecurityGroupIngressOpen", "classification": "security"},
    )
    assert finding_type(rec) == "sg_ingress_open"


def test_azure_nsg_resource_kind_alone_is_sg_ingress() -> None:
    """Mutant-kill: removing NSG kind checks leaves Azure resource-only untyped."""
    rec = _custodian_finding(
        name="Cloud Custodian open-ingress",
        description="ingress from the internet",
        extra={
            "check_id": "open-ingress",
            "classification": "security",
            "resource_type": "azure.networksecuritygroup",
        },
    )
    assert finding_type(rec) == "sg_ingress_open"


def test_demo_custodian_s3_encryption_stays_off_sg_ingress() -> None:
    """Host-lab DEMO poam.csv is byte-identical to master aside from intended rows."""
    recs = cloud_prowler.parse_file(ROOT / "fixtures" / "demo" / "cloud" / "custodian.json")
    hit = _findings(recs)[0]
    assert finding_type(hit) == "s3_encryption"
    mapped = map_finding(hit)
    assert SG_INGRESS_FIX not in mapped["recommended_fix"]
    assert "encryption" in mapped["recommended_fix"].lower()


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
