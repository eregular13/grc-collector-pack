"""Argus cold review 7 issue 3: #177 bh-high-value must keep the group playbook.

Administrators / Enterprise Admins / Schema Admins rows stamp
extra.check_id=bh-high-value (identity_ad._BH_NODE_CHECK). That unknown
typed key must not send them to the generic fallback. POA&M IDs stay on
bh-high-value so the ledger carry still matches. SAMPLE/DEMO != client KEEP.
No POST /api/risks.
"""

from __future__ import annotations

from pathlib import Path

from collectors import cloud_prowler, host_wazuh, identity_ad, saas_idp
from shared.control_map import map_finding
from shared.finding_types import finding_identity
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"

# Pre-#177 generic count on this sample walk (sensor dirs + BH/PingCastle).
# The three high-value group rows are the #177 regression (5 → 8).
PRE_177_SAMPLE_GENERIC = 5

_HIGH_VALUE_GROUPS = (
    ("Administrators", ("administrators", "domain admins")),
    ("Enterprise Admins", ("enterprise admin",)),
    ("Schema Admins", ("schema update",)),
)


def _sample_findings() -> list[dict]:
    rows: list[dict] = []
    for sub, parse in (
        ("cloud", cloud_prowler.parse_file),
        ("wazuh", host_wazuh.parse_file),
        ("saas", saas_idp.parse_file),
        ("bloodhound", identity_ad.parse_file),
        ("pingcastle", identity_ad.parse_file),
    ):
        root = SAMPLES / sub
        if not root.exists():
            continue
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            try:
                recs = parse(path)
            except Exception:
                continue
            rows.extend(r for r in recs if r.get("kind") == "finding")
    return rows


def test_high_value_group_rows_keep_playbook_and_ac2_ac6() -> None:
    recs = [
        r
        for r in identity_ad.parse_file(SAMPLES / "pingcastle" / "synthetic_group_membership.xml")
        if r.get("kind") == "finding" and r.get("name") == "High-value identity"
    ]
    by_asset = {str((r.get("assets") or [""])[0]): r for r in recs}
    for group, tokens in _HIGH_VALUE_GROUPS:
        rec = by_asset[group]
        extra = rec.get("extra") or {}
        assert extra.get("check_id") == "bh-high-value", group
        assert finding_identity(rec) == "bh-high-value", group
        mapped = map_finding(rec)
        assert mapped.get("generic") is False, group
        assert mapped["control_name"] == "Review high-value directory group membership"
        assert {"AC-2", "AC-6"} <= set(mapped.get("nist_800_53") or []), group
        blob = mapped["recommended_fix"].lower()
        assert "generic fallback" not in blob, group
        assert all(tok in blob for tok in tokens), (group, blob)


def test_sample_generic_count_returns_to_pre_177() -> None:
    rows = _sample_findings()
    assert rows, "fixtures/samples walk must emit findings"
    generic = [r for r in rows if map_finding(r).get("generic")]
    assert len(generic) == PRE_177_SAMPLE_GENERIC, [
        (r.get("name"), r.get("assets"), (r.get("extra") or {}).get("check_id"))
        for r in generic
    ]


def test_typed_generic_falls_through_to_title_playbook() -> None:
    rec = make_record(
        kind="finding",
        source="identity-ad",
        ref_id="ID-hv-schema",
        name="High-value identity",
        description="SCHEMA ADMINS@CORP.LOCAL is marked high-value.",
        severity="medium",
        category="identity-gap",
        assets=["SCHEMA ADMINS@CORP.LOCAL"],
        extra={"kind": "Group", "check_id": "novel_unmapped_hv_xyz"},
    )
    mapped = map_finding(rec)
    assert mapped.get("generic") is False
    assert mapped["control_name"] == "Review high-value directory group membership"
    assert "schema update" in mapped["recommended_fix"].lower()
    assert "generic fallback" not in mapped["recommended_fix"].lower()
