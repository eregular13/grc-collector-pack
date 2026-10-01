"""Argus cold-review-3 B7: DEMO/lab exclusion path is visible and honest.

Lab collectors must run honeypot so fixtures/demo/honeypot* land in
poam/excluded.csv. severity_info rows keep severity=info (not low).
Farm identity still holds. SAMPLE/DEMO/LAB != client KEEP.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from tests.test_pack_drop_scan_density import (
    MIN_FARM_EXCLUDED,
    MIN_FARM_FINDINGS,
    MIN_FARM_POAM,
)
from tests.test_poam_breakdown import COLLECTORS, _run_lab

ROOT = Path(__file__).resolve().parents[1]
LAB_COLLECTOR_PATHS = (
    ROOT / "Makefile",
    ROOT / "scripts" / "lab.sh",
    ROOT / "scripts" / "lab.ps1",
    ROOT / ".github" / "workflows" / "lab.yml",
)


def test_lab_collector_lists_include_honeypot() -> None:
    for path in LAB_COLLECTOR_PATHS:
        blob = path.read_text(encoding="utf-8")
        assert "honeypot" in blob, path
        assert "honeypot.py" in blob or "collectors.honeypot" in blob or "honeypot " in blob
    assert "collectors.honeypot" in COLLECTORS
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "honeypot" not in compose


def test_lab_path_excluded_csv_has_honeypot_or_severity_info(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    summary = _run_lab(tmp_path, monkeypatch)
    excluded_path = tmp_path / "poam" / "excluded.csv"
    assert excluded_path.is_file()
    with excluded_path.open(encoding="utf-8", newline="") as fh:
        excluded = list(csv.DictReader(fh))
    assert excluded, "DEMO/lab excluded.csv must not be header-only"
    reasons = {str(row.get("excluded_reason") or "") for row in excluded}
    assert reasons & {"honeypot", "severity_info"}, reasons
    assert "honeypot" in reasons
    info_rows = [row for row in excluded if row.get("excluded_reason") == "severity_info"]
    assert all(row.get("severity") == "info" for row in info_rows)
    assert all(row.get("severity") != "low" for row in info_rows)
    assert int(summary["excluded"]) == len(excluded)
    assert int(summary["weaknesses_total"]) == int(summary["poam_included"]) + int(
        summary["excluded"]
    )


def test_farm_identity_floors_still_hold() -> None:
    """Farm_drop floors are unchanged; density test locks measured identity."""
    assert MIN_FARM_FINDINGS == 110
    assert MIN_FARM_POAM == 70
    assert MIN_FARM_EXCLUDED == 20
