"""FedRAMP export honesty (cold-review-5 B2).

Open rows are the operator plan (poam.csv), not every ledger item.
Controls and Overall Remediation Plan come from the mapped POA&M row.
Critical is written as Critical; the High-fold is the template col M note.
SAMPLE/DEMO/LAB only. No POST /api/risks. RiskReady stay-out.
"""

from __future__ import annotations

import csv
from pathlib import Path

from shared.poam_fedramp import (
    CRITICAL_COMMENT,
    CRITICAL_R_NOTE,
    PLAN_ONLY_NOTE,
    item_to_row,
    kev_md_footer,
    plan_by_poam_id,
    write_fedramp_poam,
)
from shared.kev import KevCatalog


def _item(
    pid: str,
    *,
    status: str = "open",
    name: str = "Redis without auth",
    rating: str = "High",
    scanner_critical: bool = False,
    vendor_dependency: str = "No",
) -> dict:
    return {
        "poam_id": pid,
        "fp": f"fp-{pid}",
        "name": name,
        "description": f"{name} description",
        "source_family": "vuln-scan",
        "weakness_key": "nuclei:exposed-redis",
        "asset_key": "redis-a.lab.internal",
        "display_asset": "redis-a.lab.internal",
        "original_risk_rating": rating,
        "current_scanner_rating": "critical" if scanner_critical else "high",
        "scanner_critical": scanner_critical,
        "status": status,
        "status_date": "2026-09-26",
        "original_detection_date": "2026-09-01",
        "vendor_dependency": vendor_dependency,
        "framework_refs": "",
        "remediation_plan": "",
        "cves": [],
        "kev_comments": [],
        "vd_comments": [],
        "vd_flags": [],
    }


def test_plan_by_poam_id_indexes_controls_fix_and_rating() -> None:
    header = [
        "weakness",
        "recommended_fix",
        "poam_id",
        "controls",
        "original_risk_rating",
        "framework_refs",
    ]
    rows = [
        ["Redis without auth", "Enable Redis ACL", "EGP-1", "IA-2, AC-3", "Critical", "csf_PR_AA_01"],
        ["", "", "", "", "", ""],
    ]
    got = plan_by_poam_id(header, rows)
    assert set(got) == {"EGP-1"}
    assert got["EGP-1"]["controls"] == "IA-2, AC-3"
    assert got["EGP-1"]["recommended_fix"] == "Enable Redis ACL"
    assert got["EGP-1"]["original_risk_rating"] == "Critical"


def test_open_export_drops_ledger_items_not_on_plan(tmp_path: Path) -> None:
    on_plan = _item("EGP-ON")
    off_plan = _item("EGP-OFF", name="Excluded info")
    write_fedramp_poam(
        tmp_path,
        {"items": {"a": on_plan, "b": off_plan}, "closed": []},
        plan_by_id={"EGP-ON": {"controls": "IA-2", "recommended_fix": "Require auth", "original_risk_rating": "High"}},
    )
    with (tmp_path / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    ids = [r["POAM ID"] for r in rows]
    assert ids == ["EGP-ON"]
    assert "EGP-OFF" not in ids


def test_closed_tab_keeps_closed_items_not_on_current_plan(tmp_path: Path) -> None:
    closed = _item("EGP-OLD", status="closed", name="Closed flap")
    write_fedramp_poam(
        tmp_path,
        {"items": {}, "closed": [closed]},
        plan_by_id={"EGP-NEW": {"controls": "", "recommended_fix": "", "original_risk_rating": "High"}},
    )
    with (tmp_path / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        open_rows = list(csv.DictReader(fh))
    with (tmp_path / "poam_fedramp_closed.csv").open(encoding="utf-8", newline="") as fh:
        closed_rows = list(csv.DictReader(fh))
    assert open_rows == []
    assert [r["POAM ID"] for r in closed_rows] == ["EGP-OLD"]


def test_item_to_row_fills_controls_remediation_and_critical() -> None:
    item = _item("EGP-C", rating="High", scanner_critical=True)
    plan = {
        "controls": "IA-2, AC-3",
        "recommended_fix": "Enable Redis ACL users or requirepass.",
        "original_risk_rating": "Critical",
        "framework_refs": "csf_PR_AA_01",
    }
    row = item_to_row(item, plan)
    assert row[0] == "EGP-C"
    assert row[1] == "IA-2, AC-3"
    assert row[9] == "Enable Redis ACL users or requirepass."
    assert row[16] == "Critical"
    assert CRITICAL_COMMENT in row[23]
    assert row[27] == "csf_PR_AA_01"


def test_item_to_row_writes_critical_from_scanner_when_plan_absent() -> None:
    item = _item("EGP-C", rating="High", scanner_critical=True)
    row = item_to_row(item)
    assert row[16] == "Critical"
    assert row[1] == ""
    assert row[9] == ""


def test_footer_states_plan_only_and_critical_r_honesty() -> None:
    catalog = KevCatalog(kev_evaluated=False)
    md = kev_md_footer(catalog, {"warnings": []})
    assert PLAN_ONLY_NOTE in md
    assert CRITICAL_R_NOTE in md
    assert "does not fold col R" in md
