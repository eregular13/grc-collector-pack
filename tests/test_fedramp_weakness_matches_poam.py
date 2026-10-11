"""BEHAVIOR: FedRAMP twin Weakness Name equals poam.csv weakness (failure wording)."""
from __future__ import annotations

import csv
from pathlib import Path

from shared.poam_fedramp import plan_by_poam_id, write_fedramp_poam


def test_fedramp_weakness_name_matches_poam_plan_not_check_title(tmp_path: Path) -> None:
    """Synthetic corpus: ledger name is pass-style check title; poam weakness is failure.

    Fail-before on tip: item_to_row uses item['name'] → AssertionError.
    Pass-after pr-o-fedramp-weakness: plan weakness overlays Weakness Name.
    """
    # Operator plan (poam.csv) — failure wording
    poam_header = [
        "weakness",
        "asset",
        "severity",
        "framework_refs",
        "recommended_fix",
        "owner",
        "due",
        "status",
        "estate",
        "poam_id",
        "controls",
        "weakness_description",
        "original_risk_rating",
    ]
    poam_rows = [
        [
            "S3 bucket allows public access",
            "bucket-a",
            "critical",
            "nist80053_AC-3",
            "Block public ACLs",
            "",
            "",
            "open",
            "SYNTH",
            "EGP-SYN-S3",
            "AC-3",
            "Bucket ACL allows public List/Get.",
            "Critical",
        ],
        [
            "Root account has no MFA",
            "root",
            "high",
            "nist80053_IA-2",
            "Enable MFA on root",
            "",
            "",
            "open",
            "SYNTH",
            "EGP-SYN-MFA",
            "IA-2",
            "Root user has no MFA device.",
            "High",
        ],
    ]
    # Ledger items keep raw check titles (what tip wrongly exports)
    ledger = {
        "items": {
            "fp-s3": {
                "poam_id": "EGP-SYN-S3",
                "status": "open",
                "name": "S3 bucket prohibits public access",
                "description": "Bucket ACL allows public List/Get.",
                "source_family": "cloud-prowler",
                "weakness_key": "prowler:s3_bucket_public_access",
                "display_asset": "bucket-a",
                "original_detection_date": "2026-01-01",
                "status_date": "2026-01-02",
                "original_risk_rating": "Critical",
                "controls": "AC-3",
                "remediation_plan": "Block public ACLs",
                "framework_refs": "nist80053_AC-3",
            },
            "fp-mfa": {
                "poam_id": "EGP-SYN-MFA",
                "status": "open",
                "name": "Root account MFA enabled",
                "description": "Root user has no MFA device.",
                "source_family": "cloud-prowler",
                "weakness_key": "prowler:iam_root_mfa_enabled",
                "display_asset": "root",
                "original_detection_date": "2026-01-01",
                "status_date": "2026-01-02",
                "original_risk_rating": "High",
                "controls": "IA-2",
                "remediation_plan": "Enable MFA on root",
                "framework_refs": "nist80053_IA-2",
            },
        },
        "closed": [],
    }
    plan = plan_by_poam_id(poam_header, poam_rows)
    out = tmp_path / "poam"
    write_fedramp_poam(out, ledger, plan_by_id=plan)
    fed_path = out / "poam_fedramp.csv"
    assert fed_path.is_file(), "poam_fedramp.csv missing"
    fed = list(csv.DictReader(fed_path.open(encoding="utf-8", newline="")))
    by_id = {r["POAM ID"]: r for r in fed}
    assert "EGP-SYN-S3" in by_id and "EGP-SYN-MFA" in by_id
    assert by_id["EGP-SYN-S3"]["Weakness Name"] == "S3 bucket allows public access"
    assert by_id["EGP-SYN-MFA"]["Weakness Name"] == "Root account has no MFA"
    # Must NOT keep pass-style check titles on the twin
    assert by_id["EGP-SYN-S3"]["Weakness Name"] != "S3 bucket prohibits public access"
    assert by_id["EGP-SYN-MFA"]["Weakness Name"] != "Root account MFA enabled"
