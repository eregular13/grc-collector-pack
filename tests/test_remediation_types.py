"""Table-driven remediations for every emitted cloud / identity / k8s type.

S3 encryption must mention SSE/KMS and not ACL/public access.
DCSync must mention replication rights / DS-Replication-Get-Changes, not
secret-rotation-only. Distinct types do not share identical fix text unless
allowlisted.
"""

from __future__ import annotations

from pathlib import Path

from collectors.cloud_prowler import parse_file as parse_cloud
from collectors.identity_ad import parse_file as parse_identity
from collectors.k8s_kubescape import parse_file as parse_k8s
from shared.control_map import map_finding
from shared.finding_types import (
    GENERIC_FLAG,
    SHARED_REMEDIATION_ALLOWLIST,
    TYPE_REMEDIATIONS,
    finding_type,
)
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"

# Per-type must / must-not tokens on recommended_fix (lowercase).
TYPE_ASSERTIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "s3_encryption": {
        "must": ("encryption", "sse"),
        "must_any": ("kms", "sse-s3", "sse-kms"),
        "must_not": ("acl", "public access", "allusers"),
    },
    "s3_public_access": {
        "must": ("acl", "public"),
        "must_not": ("sse-s3", "sse-kms", "default encryption"),
    },
    "ebs_encryption": {
        "must": ("ebs", "encrypt"),
        "must_not": ("acl", "public access", "sse-s3"),
    },
    "iam_admin_access": {
        "must": ("administratoraccess",),
        "must_not": ("acl", "dcsync"),
    },
    "iam_root_mfa": {
        "must": ("mfa", "root"),
        "must_not": ("dcsync", "acl"),
    },
    "iam_user_mfa": {
        "must": ("mfa", "iam"),
        "must_not": ("root account", "dcsync"),
    },
    "sg_ingress_open": {
        "must": ("0.0.0.0/0", "ingress"),
        "must_not": ("sse", "dcsync"),
    },
    "cloudtrail_logging": {
        "must": ("cloudtrail", "trail"),
        "must_not": ("acl", "sse-s3"),
    },
    "rds_public": {
        "must": ("rds", "public"),
        "must_not": ("sse-s3", "dcsync"),
    },
    "ad_dcsync": {
        "must": ("replication", "ds-replication-get-changes"),
        "must_not": ("rotate the secret", "remove it from the repo"),
    },
    "ad_genericall": {
        "must": ("genericall",),
        "must_not": ("rotate the secret",),
    },
    "ad_adminto": {
        "must": ("admin",),
        "must_not": ("rotate the secret", "sse"),
    },
    "ad_backup_operators": {
        "must": ("backup operators",),
        "must_not": ("rotate the secret",),
    },
    "ad_kerberoast": {
        "must": ("spn",),
        "must_not": ("remove it from the repo", "acl"),
    },
    "ad_asrep": {
        "must": ("preauthentication",),
        "must_not": ("rotate the secret",),
    },
    "ad_domain_admins": {
        "must": ("domain admins",),
        "must_not": ("rotate the secret",),
    },
    "ad_unconstrained_delegation": {
        "must": ("delegation",),
        "must_not": ("rotate the secret",),
    },
    "entra_ga_pim": {
        "must": ("pim", "global administrator"),
        "must_not": ("rotate the secret",),
    },
    "ad_smb_null_session": {
        "must": ("null",),
        "must_not": ("rotate the secret",),
    },
    "hk_password_history": {
        "must": ("password history",),
        "must_not": ("rotate the secret",),
    },
    "hk_lm_hash": {
        "must": ("lm",),
        "must_not": ("rotate the secret",),
    },
    "k8s_privileged": {
        "must": ("privileged",),
        "must_not": ("rotate the secret", "acl"),
    },
    "k8s_anonymous_auth": {
        "must": ("anonymous",),
        "must_not": ("rotate the secret",),
    },
    "k8s_privilege_escalation": {
        "must": ("privilegeescalation", "allowprivilegeescalation"),
        "must_any": ("allowprivilegeescalation", "privilege escalation"),
        "must_not": ("rotate the secret",),
    },
    "k8s_hostnetwork": {
        "must": ("hostnetwork",),
        "must_not": ("rotate the secret",),
    },
    "k8s_write_binary_dir": {
        "must": ("binary",),
        "must_not": ("rotate the secret", "acl"),
    },
    "tls_breach": {
        "must": ("compress", "breach"),
        "must_not": ("lucky13", "cbc", "rotate the secret"),
    },
    "tls_lucky13": {
        "must": ("cbc", "lucky13"),
        "must_not": ("gzip", "breach", "rotate the secret"),
    },
    "tls_cert_expiration": {
        "must": ("certificate", "expir"),
        "must_not": ("gzip", "lucky13", "cbc"),
    },
    "tls_heartbleed": {
        "must": ("heartbleed",),
        "must_not": ("gzip", "lucky13"),
    },
    "tls_1_0": {
        "must": ("tls 1.0",),
        "must_not": ("gzip", "lucky13"),
    },
    "tls_1_1": {
        "must": ("tls 1.1",),
        "must_not": ("gzip", "lucky13"),
    },
    "tls_sslv3": {
        "must": ("sslv3",),
        "must_not": ("gzip", "lucky13"),
    },
    "tls_sslv2": {
        "must": ("sslv2",),
        "must_not": ("gzip", "lucky13"),
    },
    "web_admin_path": {
        "must": ("admin", "nikto"),
        "must_not": ("easm", "gzip", "rotate the secret"),
    },
    "web_dir_listing": {
        "must": ("directory listing", "nikto"),
        "must_not": ("gzip", "rotate the secret"),
    },
    "web_sensitive_file": {
        "must": (".git", "nikto"),
        "must_not": ("gzip", "rotate the secret"),
    },
    "web_http_methods": {
        "must": ("put", "nikto"),
        "must_not": ("gzip", "rotate the secret"),
    },
    "web_default_creds": {
        "must": ("default", "nikto"),
        "must_not": ("gzip", "rotate the secret"),
    },
    "pc_min_pwd_len": {
        "must": ("password", "a-minpwdlen"),
        "must_not": ("rotate the secret", "gzip"),
    },
    "pc_krbtgt": {
        "must": ("krbtgt",),
        "must_not": ("gzip", "rotate the secret"),
    },
}


def _emitted_findings() -> list[dict]:
    rows: list[dict] = []
    for path in sorted((DEMO / "cloud").glob("*")):
        rows.extend(r for r in parse_cloud(path) if r.get("kind") == "finding")
    for path in sorted((DEMO / "identity").glob("*")):
        try:
            recs = parse_identity(path)
        except Exception:
            continue
        rows.extend(r for r in recs if r.get("kind") == "finding")
    for path in sorted((DEMO / "k8s").glob("*")):
        rows.extend(r for r in parse_k8s(path) if r.get("kind") == "finding")
    return rows


def test_every_emitted_cloud_identity_k8s_type_has_specific_remediation() -> None:
    emitted = _emitted_findings()
    assert emitted, "demo fixtures must emit cloud/identity/k8s findings"
    types = sorted({finding_type(r) for r in emitted if finding_type(r) and finding_type(r) != "unknown"})
    missing = [t for t in types if t not in TYPE_REMEDIATIONS]
    assert not missing, f"emitted types missing remediations: {missing}"
    uncatalogued = [t for t in types if t not in TYPE_ASSERTIONS]
    assert not uncatalogued, f"emitted types missing test assertions: {uncatalogued}"
    for rec in emitted:
        ftype = finding_type(rec)
        mapped = map_finding(rec)
        if ftype == "unknown":
            assert mapped.get("generic") is True, rec.get("name")
            assert "review and remediate per control" in mapped["recommended_fix"].lower()
            assert GENERIC_FLAG in mapped["recommended_fix"].lower()
            continue
        if not ftype:
            continue
        spec = TYPE_ASSERTIONS[ftype]
        fix = mapped["recommended_fix"].lower()
        name = mapped["control_name"].lower()
        blob = f"{name} {fix}"
        for token in spec.get("must", ()):
            assert token in blob, (ftype, rec.get("name"), token, mapped["recommended_fix"])
        any_tokens = spec.get("must_any") or ()
        if any_tokens:
            assert any(tok in blob for tok in any_tokens), (ftype, rec.get("name"), any_tokens)
        for token in spec.get("must_not", ()):
            assert token not in blob, (ftype, rec.get("name"), token, mapped["recommended_fix"])
        assert mapped.get("generic") is False, ftype


def test_s3_encryption_not_public_acl_and_dcsync_not_secret_rotation() -> None:
    enc = make_record(
        kind="finding",
        source="cloud-prowler",
        ref_id="CLD-s3-enc",
        name="S3 bucket server-side encryption",
        description="ASFF export: encryption not enforced on demo-public-assets.",
        severity="high",
        category="cloud-misconfiguration",
        assets=["arn:aws:s3:::demo-public-assets"],
        extra={
            "check_id": "s3_bucket_server_side_encryption_enabled",
            "arn": "arn:aws:s3:::demo-public-assets",
            "service": "s3",
        },
    )
    mapped = map_finding(enc)
    fix = mapped["recommended_fix"].lower()
    assert "encrypt" in fix and ("sse" in fix or "kms" in fix)
    assert "acl" not in fix and "public access" not in fix
    assert mapped.get("finding_type") == "s3_encryption"

    dcsync = make_record(
        kind="finding",
        source="identity-ad",
        ref_id="ID-dcsync",
        name="BloodHound DCSync",
        description="Principal can replicate directory secrets. SVC-SQL@CORP.LOCAL -> CORP.LOCAL",
        severity="critical",
        category="identity-gap",
        assets=["SVC-SQL@CORP.LOCAL", "CORP.LOCAL"],
        extra={"edge": "DCSync", "start": "SVC-SQL@CORP.LOCAL", "end": "CORP.LOCAL"},
    )
    mapped = map_finding(dcsync)
    fix = mapped["recommended_fix"].lower()
    assert "ds-replication-get-changes" in fix or "replication" in fix
    assert "rotate the secret" not in fix
    assert "remove it from the repo" not in fix
    assert mapped.get("finding_type") == "ad_dcsync"


def test_distinct_types_do_not_share_identical_remediation() -> None:
    by_fix: dict[str, list[str]] = {}
    for ftype, meta in TYPE_REMEDIATIONS.items():
        by_fix.setdefault(meta["recommended_fix"], []).append(ftype)
    collisions = {fix: types for fix, types in by_fix.items() if len(types) > 1}
    for _fix, types in collisions.items():
        pair_ok = True
        for i, left in enumerate(types):
            for right in types[i + 1 :]:
                key = tuple(sorted((left, right)))
                if key not in SHARED_REMEDIATION_ALLOWLIST:
                    pair_ok = False
        assert pair_ok, f"shared remediations without allowlist: {collisions}"


def test_unknown_typed_finding_is_generic_not_borrowed() -> None:
    rec = make_record(
        kind="finding",
        source="cloud-prowler",
        ref_id="CLD-unknown-xyz",
        name="Some novel cloud check",
        description="A check the catalog does not know.",
        severity="high",
        category="cloud-misconfiguration",
        assets=["res-1"],
        extra={"check_id": "novel_unmapped_control_xyz", "service": "lambda"},
    )
    mapped = map_finding(rec)
    assert mapped.get("generic") is True
    assert "review and remediate per control" in mapped["recommended_fix"].lower()
    assert GENERIC_FLAG in mapped["recommended_fix"].lower()
    assert "acl" not in mapped["recommended_fix"].lower()
    assert "rotate the secret" not in mapped["recommended_fix"].lower()
