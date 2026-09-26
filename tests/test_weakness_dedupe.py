"""Same-issue-same-asset findings collapse; different assets stay separate."""

from __future__ import annotations

from collectors.grc_loader import _dedupe, load
from shared.finding_types import (
    dedupe_key,
    dedupe_weaknesses,
    finding_identity,
    finding_type,
    normalize_asset_id,
)
from shared.io_util import write_canonical
from shared.schema import make_record, make_ref, slug


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


def test_sarif_same_rule_two_hosts_stay_two_weaknesses() -> None:
    """SARIF ref_id is the rule slug only — second host must not be dropped."""
    rule = "python.lang.security.audit.sql-injection"
    a = make_record(
        kind="finding",
        source="code-secrets",
        ref_id=make_ref("code-secrets", rule),
        name="Possible SQL injection via string format",
        description="SARIF rule on payments/query.py",
        severity="high",
        category="sast",
        assets=["services/payments/query.py"],
        extra={"rule": rule},
        labels=["sarif"],
    )
    b = make_record(
        kind="finding",
        source="code-secrets",
        ref_id=make_ref("code-secrets", rule),
        name="Possible SQL injection via string format",
        description="SARIF rule on auth/login.py",
        severity="high",
        category="sast",
        assets=["services/auth/login.py"],
        extra={"rule": rule},
        labels=["sarif"],
    )
    assert a["ref_id"] == b["ref_id"]
    kept = [r for r in _dedupe([a, b]) if r.get("kind") == "finding"]
    assert len(kept) == 2
    merged = [r for r in dedupe_weaknesses(_dedupe([a, b])) if r.get("kind") == "finding"]
    assert len(merged) == 2
    assert {normalize_asset_id(r["assets"][0]) for r in merged} == {
        "services/payments/query.py",
        "services/auth/login.py",
    }


def test_trivy_same_cve_two_images_stay_two_weaknesses() -> None:
    cve = "CVE-2023-44270"
    alpine = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id=make_ref("vuln-scan", cve),
        name="postcss line return parsing",
        description="Affected alpine image.",
        severity="medium",
        category="vulnerability",
        assets=["alpine:3.19"],
        extra={"cve": cve, "pkg": "postcss"},
        labels=["trivy"],
    )
    debian = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id=make_ref("vuln-scan", cve),
        name="postcss line return parsing",
        description="Affected debian image.",
        severity="medium",
        category="vulnerability",
        assets=["debian:12"],
        extra={"cve": cve, "pkg": "postcss"},
        labels=["trivy"],
    )
    assert alpine["ref_id"] == debian["ref_id"]
    kept = [r for r in _dedupe([alpine, debian]) if r.get("kind") == "finding"]
    assert len(kept) == 2
    merged = [r for r in dedupe_weaknesses(_dedupe([alpine, debian])) if r.get("kind") == "finding"]
    assert len(merged) == 2
    assert {normalize_asset_id(r["assets"][0]) for r in merged} == {"alpine:3.19", "debian:12"}


def test_long_ids_sharing_first_48_chars_do_not_collide() -> None:
    prefix = "python.lang.security.audit.sql-injection-via-string-format-extra"
    id_a = f"{prefix}-suffix-alpha"
    id_b = f"{prefix}-suffix-bravo"
    assert slug(id_a) == slug(id_b)
    assert make_ref("code-secrets", id_a) != make_ref("code-secrets", id_b)
    assert finding_identity({"extra": {"rule": id_a}}) != finding_identity({"extra": {"rule": id_b}})
    a = make_record(
        kind="finding",
        source="code-secrets",
        ref_id=make_ref("code-secrets", id_a),
        name="SQL injection A",
        severity="high",
        category="sast",
        assets=["repo/a.py"],
        extra={"rule": id_a},
    )
    b = make_record(
        kind="finding",
        source="code-secrets",
        ref_id=make_ref("code-secrets", id_b),
        name="SQL injection B",
        severity="high",
        category="sast",
        assets=["repo/a.py"],
        extra={"rule": id_b},
    )
    assert a["ref_id"] != b["ref_id"]
    kept = [r for r in _dedupe([a, b]) if r.get("kind") == "finding"]
    assert len(kept) == 2
    merged = [r for r in dedupe_weaknesses(_dedupe([a, b])) if r.get("kind") == "finding"]
    assert len(merged) == 2


def test_true_duplicate_same_id_same_asset_collapses() -> None:
    rule = "python.lang.security.audit.sql-injection"
    first = make_record(
        kind="finding",
        source="code-secrets",
        ref_id=make_ref("code-secrets", rule),
        name="Possible SQL injection",
        severity="high",
        category="sast",
        assets=["services/payments/query.py"],
        extra={"rule": rule},
        labels=["sarif"],
    )
    second = make_record(
        kind="finding",
        source="code-secrets",
        ref_id=make_ref("code-secrets", rule),
        name="Possible SQL injection",
        severity="high",
        category="sast",
        assets=["services/payments/query.py"],
        extra={"rule": rule},
        labels=["sarif", "retry"],
    )
    kept = [r for r in _dedupe([first, second]) if r.get("kind") == "finding"]
    assert len(kept) == 1
    merged = [r for r in dedupe_weaknesses(_dedupe([first, second])) if r.get("kind") == "finding"]
    assert len(merged) == 1


def test_loader_sarif_two_hosts_and_trivy_two_images_count(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    rule = "python.lang.security.audit.sql-injection"
    cve = "CVE-2023-44270"
    write_canonical(
        "code-secrets",
        [
            make_record(
                kind="finding",
                source="code-secrets",
                ref_id=make_ref("code-secrets", rule),
                name="Possible SQL injection",
                severity="high",
                category="sast",
                assets=["services/payments/query.py"],
                extra={"rule": rule},
            ),
            make_record(
                kind="finding",
                source="code-secrets",
                ref_id=make_ref("code-secrets", rule),
                name="Possible SQL injection",
                severity="high",
                category="sast",
                assets=["services/auth/login.py"],
                extra={"rule": rule},
            ),
        ],
    )
    write_canonical(
        "vuln-scan",
        [
            make_record(
                kind="finding",
                source="vuln-scan",
                ref_id=make_ref("vuln-scan", cve),
                name="postcss",
                severity="high",
                category="vulnerability",
                assets=["alpine:3.19"],
                extra={"cve": cve},
            ),
            make_record(
                kind="finding",
                source="vuln-scan",
                ref_id=make_ref("vuln-scan", cve),
                name="postcss",
                severity="high",
                category="vulnerability",
                assets=["debian:12"],
                extra={"cve": cve},
            ),
        ],
    )
    summary = load()
    assert summary["weaknesses"] == 4
    assert summary["vulnerabilities"] == 4
    assert summary["findings"] == 0
    assert summary["risk_scenarios"] == 4


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
