"""Same-issue-same-asset findings collapse; different assets stay separate."""

from __future__ import annotations

from shared.finding_types import dedupe_key, dedupe_weaknesses, finding_type, normalize_asset_id
from shared.schema import make_record


def _finding(**kwargs):
    defaults = dict(
        kind="finding",
        source="cloud-prowler",
        ref_id="CLD-a",
        name="S3 bucket server-side encryption",
        description="encryption not enforced",
        severity="high",
        category="cloud-misconfiguration",
        assets=["demo-public-assets"],
        extra={"check_id": "s3_bucket_default_encryption", "service": "s3"},
    )
    defaults.update(kwargs)
    return make_record(**defaults)


def test_normalize_asset_id_strips_arn_and_upn() -> None:
    assert normalize_asset_id("arn:aws:s3:::demo-public-assets") == "demo-public-assets"
    assert normalize_asset_id("SVC-SQL@CORP.LOCAL") == "svc-sql"
    assert normalize_asset_id("DEMO-PUBLIC-ASSETS") == "demo-public-assets"


def test_duplicate_same_issue_same_asset_merges_evidence() -> None:
    first = _finding(
        ref_id="CLD-s3-enc-prowler",
        assets=["demo-public-assets"],
        extra={"check_id": "s3_bucket_default_encryption", "service": "s3"},
        labels=["cloud", "prowler"],
    )
    second = _finding(
        ref_id="CLD-s3-enc-asff",
        source="cloud-prowler",
        name="S3 bucket server-side encryption",
        description="ASFF export: encryption not enforced on demo-public-assets.",
        assets=["arn:aws:s3:::demo-public-assets"],
        extra={
            "check_id": "s3_bucket_server_side_encryption_enabled",
            "arn": "arn:aws:s3:::demo-public-assets",
            "service": "s3",
        },
        labels=["cloud", "asff"],
    )
    assert finding_type(first) == finding_type(second) == "s3_encryption"
    assert dedupe_key(first) == dedupe_key(second)
    merged = dedupe_weaknesses([first, second])
    findings = [r for r in merged if r.get("kind") == "finding"]
    assert len(findings) == 1
    kept = findings[0]
    extra = kept["extra"]
    assert "CLD-s3-enc-asff" in (extra.get("also_ids") or [])
    assert set(extra.get("sources") or []) >= {"cloud-prowler"}
    assert any(p.get("ref_id") == "CLD-s3-enc-asff" for p in (extra.get("provenance") or []))
    assert "asff" in (kept.get("labels") or [])
    assert kept.get("ref_id") == "CLD-s3-enc-prowler"


def test_same_issue_different_assets_stay_separate() -> None:
    a = _finding(ref_id="CLD-enc-a", assets=["bucket-a"])
    b = _finding(ref_id="CLD-enc-b", assets=["bucket-b"])
    merged = [r for r in dedupe_weaknesses([a, b]) if r.get("kind") == "finding"]
    assert len(merged) == 2
    assert {dedupe_key(r) for r in merged} == {
        ("bucket-a", "s3_encryption"),
        ("bucket-b", "s3_encryption"),
    }


def test_different_types_same_asset_stay_separate() -> None:
    enc = _finding(
        ref_id="CLD-enc",
        assets=["demo-public-assets"],
        extra={"check_id": "s3_bucket_default_encryption"},
    )
    pub = _finding(
        ref_id="CLD-pub",
        name="S3 bucket prohibits public access",
        description="Bucket ACL and policy allow public List/Get.",
        assets=["demo-public-assets"],
        extra={"check_id": "s3_bucket_public_access"},
    )
    merged = [r for r in dedupe_weaknesses([enc, pub]) if r.get("kind") == "finding"]
    assert len(merged) == 2
    assert {finding_type(r) for r in merged} == {"s3_encryption", "s3_public_access"}


def test_dcsync_same_principal_merges() -> None:
    a = make_record(
        kind="finding",
        source="identity-ad",
        ref_id="ID-dcsync-1",
        name="BloodHound DCSync",
        description="Principal can replicate directory secrets. SVC-SQL -> CORP.",
        severity="critical",
        category="identity-gap",
        assets=["SVC-SQL@CORP.LOCAL", "CORP.LOCAL"],
        extra={"edge": "DCSync"},
        labels=["identity", "bloodhound"],
    )
    b = make_record(
        kind="finding",
        source="identity-ad",
        ref_id="ID-dcsync-2",
        name="BloodHound DCSync",
        description="DS-Replication-Get-Changes on SVC-SQL",
        severity="critical",
        category="identity-gap",
        assets=["svc-sql@corp.local"],
        extra={"edge": "DCSync"},
        labels=["identity", "ace"],
    )
    merged = [r for r in dedupe_weaknesses([a, b]) if r.get("kind") == "finding"]
    assert len(merged) == 1
    assert "ID-dcsync-2" in (merged[0]["extra"].get("also_ids") or [])
    assert "ace" in (merged[0].get("labels") or [])


def test_non_findings_pass_through() -> None:
    asset = make_record(
        kind="asset",
        source="cloud-prowler",
        ref_id="CLD-asset",
        name="demo-public-assets",
        category="cloud-resource",
    )
    finding = _finding()
    out = dedupe_weaknesses([asset, finding, finding])
    assert [r["kind"] for r in out] == ["asset", "finding"]
