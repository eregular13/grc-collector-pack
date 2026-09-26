"""Original detection date from artifact scan time, never the pack run date."""

from __future__ import annotations

import csv
import importlib
import json
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from shared.poam_fields import NOT_RECORDED, PENDING_DUE, _to_date, poam_fields
from shared.poam_ledger import apply_ledger
from shared.scan_time import calendar_date, format_detection_date, merge_detection
from shared.kev import KevCatalog

ROOT = Path(__file__).resolve().parents[1]


def _mapped() -> dict:
    return {
        "nist_800_53": ["SI-2"],
        "control_name": "Patch",
        "include_poam": True,
        "framework_refs": "csf_PR",
        "recommended_fix": "patch",
    }


def _rec(**kw) -> dict:
    extra = kw.pop("extra", {"id": "p1", "tool": "nessus", "port": "443"})
    rec = {
        "kind": "finding",
        "source": "vuln-scan",
        "ref_id": kw.pop("ref_id", "VULN-1"),
        "name": kw.pop("name", "OpenSSL heartbeat"),
        "description": "fixture",
        "severity": kw.pop("severity", "high"),
        "category": "vulnerability",
        "assets": ["10.0.0.5"],
        "labels": ["nessus"],
        "collected_at": kw.pop("collected_at", "2026-09-26T06:00:00Z"),
        "extra": extra,
    }
    rec.update(kw)
    return rec


def test_scan_time_taken_from_artifact() -> None:
    rec = _rec(extra={"id": "p1", "tool": "nessus", "scan_time": "2026-09-01T12:00:00Z"})
    fields = poam_fields(rec, _mapped(), date(2026, 9, 26))
    assert fields["original_detection_date"] == "2026-09-01"
    assert fields["scheduled_completion_date"] == "2026-10-01"


def test_missing_scan_time_is_not_recorded_no_scheduled() -> None:
    rec = _rec(collected_at="2026-09-26T06:00:00Z", extra={"id": "p1", "tool": "nessus"})
    fields = poam_fields(rec, _mapped(), date(2026, 9, 26))
    assert fields["original_detection_date"] == NOT_RECORDED
    assert fields["scheduled_completion_date"] == PENDING_DUE
    assert fields["milestones"] == PENDING_DUE
    assert fields["original_detection_date"] != date.today().isoformat()
    assert fields["original_detection_date"] != "2026-09-26"


def test_pt_2300_keeps_labeled_calendar_day() -> None:
    """23:00 PT (06:00Z next day) stays 2026-09-25, not the next UTC day."""
    pt = "2026-09-25T23:00:00-07:00"
    utc_next = "2026-09-26T06:00:00Z"
    assert format_detection_date(pt) == "2026-09-25"
    assert calendar_date(pt) == date(2026, 9, 25)
    assert _to_date(pt) == date(2026, 9, 25)
    assert _to_date(utc_next) == date(2026, 9, 26)
    rec = _rec(extra={"id": "p1", "tool": "nessus", "scan_time": pt})
    fields = poam_fields(rec, _mapped(), date(2026, 9, 26))
    assert fields["original_detection_date"] == "2026-09-25"
    assert fields["scheduled_completion_date"] == "2026-10-25"


def test_ledger_keeps_original_date_across_later_scan() -> None:
    rec1 = _rec(extra={"id": "p1", "tool": "nessus", "port": "443", "scan_time": "2026-09-01T00:00:00Z"})
    first = apply_ledger(
        [rec1],
        catalog=KevCatalog(kev_evaluated=False, reason="snapshot_missing"),
        run_at=datetime(2026, 9, 10, tzinfo=timezone.utc),
        prior_existed=True,
    )
    item = next(iter(first["items"].values()))
    assert item["original_detection_date"] == "2026-09-01"
    rec2 = _rec(extra={"id": "p1", "tool": "nessus", "port": "443", "scan_time": "2026-09-20T00:00:00Z"})
    second = apply_ledger(
        [rec2],
        catalog=KevCatalog(kev_evaluated=False, reason="snapshot_missing"),
        run_at=datetime(2026, 9, 21, tzinfo=timezone.utc),
        ledger_in=first,
        prior_existed=True,
    )
    item2 = next(iter(second["items"].values()))
    assert item2["original_detection_date"] == "2026-09-01"
    assert item2["poam_id"] == item["poam_id"]


def test_ledger_real_scan_time_wins_over_not_recorded() -> None:
    rec1 = _rec(extra={"id": "p1", "tool": "nessus", "port": "443"})
    first = apply_ledger(
        [rec1],
        catalog=KevCatalog(kev_evaluated=False, reason="snapshot_missing"),
        run_at=datetime(2026, 9, 10, tzinfo=timezone.utc),
        prior_existed=True,
    )
    assert next(iter(first["items"].values()))["original_detection_date"] == NOT_RECORDED
    rec2 = _rec(extra={"id": "p1", "tool": "nessus", "port": "443", "scan_time": "2026-09-01T00:00:00Z"})
    second = apply_ledger(
        [rec2],
        catalog=KevCatalog(kev_evaluated=False, reason="snapshot_missing"),
        run_at=datetime(2026, 9, 12, tzinfo=timezone.utc),
        ledger_in=first,
        prior_existed=True,
    )
    assert next(iter(second["items"].values()))["original_detection_date"] == "2026-09-01"


def test_merge_detection_never_moves_later() -> None:
    assert merge_detection("2026-09-01", "2026-09-20") == "2026-09-01"
    assert merge_detection("not recorded", "2026-09-01") == "2026-09-01"
    assert merge_detection("2026-09-01", None) == "2026-09-01"
    assert merge_detection("not recorded", None) == "not recorded"
    assert merge_detection("2026-09-10", "2026-09-01") == "2026-09-01"


def test_poam_csv_missing_scan_time_via_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    rec = _rec(ref_id="VULN-MISSING", extra={"id": "p1", "tool": "nessus", "port": "443"})
    with (out / "canonical" / "x.jsonl").open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    (tmp_path / "in").mkdir(exist_ok=True)
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    with (out / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        row = list(csv.DictReader(fh))[0]
    assert row["original_detection_date"] == NOT_RECORDED
    assert row["scheduled_completion_date"] == PENDING_DUE
    md = (out / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "UTC" in md
    assert "not recorded" in md.lower()
