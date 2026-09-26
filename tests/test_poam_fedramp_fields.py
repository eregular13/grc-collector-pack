"""POAM_FEDRAMP_FIELDS: POA&M export carries FedRAMP R3.0-style fields from data we already have.

Benchmark: FedRAMP POA&M Template R3.0 (POAM ID, Controls, Weakness Description,
Detector Source, Source Identifier, Original Detection Date, Scheduled Completion
Date (30/90/180 by risk), Status Date, milestones, Original Risk Rating, CVE).
Existing columns stay in place; owner / point_of_contact stay blank for a human.
"""

from __future__ import annotations

import csv
import importlib
import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from shared.ciso_shape import POAM_HEADER, assert_risk_register_and_poam

LEGACY = "weakness,asset,severity,framework_refs,recommended_fix,owner,due,status,estate"
NEW = (
    "poam_id", "finding_ref_id", "controls", "weakness_description", "detector_source",
    "weakness_source_id", "original_detection_date", "scheduled_completion_date",
    "status_date", "milestones", "original_risk_rating", "point_of_contact", "cve",
)
ROOT = Path(__file__).resolve().parents[1]


def _rec(ref: str, sev: str, **kw) -> dict:
    base = {
        "kind": "finding", "source": "inventory-nmap", "ref_id": ref,
        "name": kw.pop("name", f"Anonymous FTP login allowed {ref}"),
        "description": kw.pop("description", f"{ref} accepts anonymous FTP login (nmap ftp-anon)."),
        "severity": sev, "category": kw.pop("category", "misconfiguration"),
        "assets": ["10.0.0.5"], "labels": ["nmap"], "collected_at": "2026-09-20T10:00:00Z",
        "extra": kw.pop("extra", {"port": "21", "ip": "10.0.0.5", "check_id": "nse-ftp-anon",
                                   "nse_script": "ftp-anon", "tool": "nmap",
                                   "scan_time": "2026-09-01T12:00:00Z"}),
    }
    base.update(kw)
    return base


def _load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, records: list[dict]) -> list[dict[str, str]]:
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    asset = {"kind": "asset", "source": "inventory-nmap", "ref_id": "asset-10-0-0-5", "name": "10.0.0.5",
             "description": "Host 10.0.0.5", "severity": "info", "category": "host", "assets": ["10.0.0.5"],
             "labels": ["nmap"], "extra": {"asset_type": "PR", "ip": "10.0.0.5"}}
    with (out / "canonical" / "x.jsonl").open("w", encoding="utf-8") as fh:
        for rec in [asset, *records]:
            fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    from shared.ciso_shape import csv_rows

    assert_risk_register_and_poam(out)
    return csv_rows(out / "poam" / "poam.csv")


def test_header_keeps_legacy_prefix_and_appends_fedramp_fields() -> None:
    assert POAM_HEADER.startswith(LEGACY + ",")
    assert tuple(POAM_HEADER.split(",")[len(LEGACY.split(",")):]) == NEW


def test_row_fields_from_existing_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _load(tmp_path, monkeypatch, [_rec("NMAP-10-0-0-5-21-nse-ftp-anon", "high")])
    row = rows[0]
    assert row["poam_id"] == "POAM-NMAP-10-0-0-5-21-nse-ftp-anon"
    assert row["finding_ref_id"] == "NMAP-10-0-0-5-21-nse-ftp-anon"
    assert {"AC-3", "CM-7"} <= {c.strip() for c in row["controls"].split(",")}
    assert row["weakness_description"].startswith("NMAP-10-0-0-5-21-nse-ftp-anon accepts anonymous FTP")
    assert row["detector_source"] == "inventory-nmap (nmap NSE ftp-anon)"
    assert row["weakness_source_id"] == "nse-ftp-anon"
    # first-seen absent -> scan time
    assert row["original_detection_date"] == "2026-09-01"
    assert row["scheduled_completion_date"] == "2026-10-01"  # high = 30 days
    assert row["status_date"] == date.today().isoformat() or len(row["status_date"]) == 10
    assert row["original_risk_rating"] == "High"
    assert row["owner"] == "" and row["point_of_contact"] == "" and row["due"] == ""
    assert row["status"] == "open" and row["estate"] == "LAB: TEST ENVIRONMENT"
    ms = [m.strip() for m in row["milestones"].split(";") if m.strip()]
    assert len(ms) >= 3
    assert "validate" in ms[0].lower() and "2026-09-08" in ms[0]
    assert "Disable anonymous FTP access" in ms[1]
    assert "rescan" in ms[-1].lower() and "2026-10-01" in ms[-1]


@pytest.mark.parametrize(
    ("sev", "days", "rating"),
    [("critical", 30, "Critical"), ("high", 30, "High"), ("medium", 90, "Moderate"), ("low", 180, "Low")],
)
def test_scheduled_completion_defaults_by_risk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sev: str, days: int, rating: str
) -> None:
    rows = _load(tmp_path, monkeypatch, [_rec("R1", sev)])  # misconfig rules always POA&M
    row = rows[0]
    assert row["original_risk_rating"] == rating
    start = date.fromisoformat(row["original_detection_date"])
    assert date.fromisoformat(row["scheduled_completion_date"]) == start + timedelta(days=days)


def test_first_seen_wins_over_scan_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extra = {"port": "21", "check_id": "nse-ftp-anon", "scan_time": "2026-09-01T00:00:00Z", "first_seen": "2026-07-04"}
    rows = _load(tmp_path, monkeypatch, [_rec("R1", "high", extra=extra)])
    assert rows[0]["original_detection_date"] == "2026-07-04"
    assert rows[0]["scheduled_completion_date"] == "2026-08-03"


def test_collected_at_when_no_first_seen_or_scan_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _load(tmp_path, monkeypatch, [_rec("R1", "high", extra={"port": "21", "check_id": "nse-ftp-anon"})])
    assert rows[0]["original_detection_date"] == "not recorded"
    assert rows[0]["scheduled_completion_date"] == "pending due date"


def test_cve_where_known(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recs = [
        _rec("H1", "critical", name="Heartbleed on TLS", description="OpenSSL heartbeat leak", category="tls",
             extra={"port": "443"}),
        _rec("C1", "high", name="Apache vuln", description="Affected by CVE-2021-41773 path traversal",
             category="vuln", extra={"port": "80"}),
        _rec("X1", "critical", name="Explicit", description="x", category="vuln", extra={"cve": "CVE-2023-4966"}),
    ]
    rows = {r["finding_ref_id"]: r for r in _load(tmp_path, monkeypatch, recs)}
    assert rows["H1"]["cve"] == "CVE-2014-0160"
    assert rows["C1"]["cve"] == "CVE-2021-41773"
    assert rows["X1"]["cve"] == "CVE-2023-4966"


def test_unmapped_controls_stay_blank_not_invented(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _rec("U1", "high", name="Something odd", description="odd thing", category="other",
               extra={"port": ""})
    rows = _load(tmp_path, monkeypatch, [rec])
    assert rows[0]["controls"] == ""
    assert rows[0]["cve"] == ""


def test_poam_md_says_dates_are_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _load(tmp_path, monkeypatch, [_rec("R1", "medium")])
    md = (tmp_path / "out" / "poam" / "poam.md").read_text(encoding="utf-8")
    low = md.lower()
    assert "default" in low and "30" in md and "90" in md and "180" in md
    assert "point of contact" in low and "blank" in low
    assert "Moderate" in md
    assert "POAM-R1" in md


def test_lab_misconfig_fixture_end_to_end(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    fix = ROOT / "fixtures" / "lab-misconfig"
    work = tmp_path / "w"
    (work / "in" / "nmap").mkdir(parents=True)
    (work / "in" / "LAB.txt").write_text((fix / "LAB.txt").read_text(encoding="utf-8"), encoding="utf-8")
    (work / "in" / "nmap" / "misconfig-nse.xml").write_bytes((fix / "nmap" / "misconfig-nse.xml").read_bytes())
    env = {**os.environ, "PYTHONPATH": str(ROOT), "DRY_RUN": "1", "CISO_PUSH": "0", "RISKREADY_PUSH": "0"}
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "prove_ciso.py"), "--work", str(work), "--use-existing-in"],
                          cwd=str(ROOT), env=env, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout[-600:] + proc.stderr[-600:]
    from shared.ciso_shape import csv_rows

    rows = csv_rows(work / "out" / "poam" / "poam.csv")
    anon = next(r for r in rows if r["weakness"] == "Anonymous FTP login allowed")
    assert anon["original_detection_date"] == "2026-09-25"  # nmap host starttime (UTC)
    assert anon["scheduled_completion_date"] == "2026-10-25"
    assert anon["estate"] == "LAB: TEST ENVIRONMENT"
    assert all(r["poam_id"].startswith("POAM-") for r in rows)
    assert all(len([m for m in r["milestones"].split(";") if m.strip()]) >= 2 for r in rows)
