"""IG1 coverage report: mapped vs real-scan-backed vs sample-only, never clean on unknown."""
from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from shared import cis_ig1

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = ("1.2", "2.1", "2.2", "4.2", "4.4", "5.1", "5.3", "6.1", "8.1", "9.1", "9.2", "12.1")


def _poam(path: Path, rows: list[tuple[str, str]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["weakness", "framework_refs", "estate"])
        for refs, estate in rows:
            w.writerow(["synthetic", refs, estate])
    return path


def _by_id(rows):
    return {r["safeguard"]: r for r in rows}


def test_ig1_has_56_safeguards() -> None:
    assert len(cis_ig1.SAFEGUARDS) == 56 == len(set(cis_ig1.SAFEGUARDS))


def test_scan_candidates_mapped_or_reasoned() -> None:
    mapped = cis_ig1.mapped_safeguards()
    for sg in CANDIDATES:
        assert sg in mapped or cis_ig1.UNMAPPED_REASONS.get(sg), sg
    assert mapped.get("4.4") == "refs" and mapped.get("5.3") == "refs"


def test_real_vs_sample_vs_no_evidence(tmp_path: Path) -> None:
    lab = _poam(tmp_path / "lab" / "poam" / "poam.csv", [("cpg_x,cis_4_4", "LAB: TEST ENVIRONMENT")])
    demo = _poam(
        tmp_path / "demo" / "poam" / "poam.csv",
        [("cis_5_3", "DEMO: NOT A CLIENT"), ("cis_4_4", "SAMPLE DATA: NOT A CLIENT"), ("cis_7_3", "")],
    )
    rows = _by_id(cis_ig1.coverage([lab, demo]))
    assert rows["4.4"]["status"] == "REAL" and rows["4.4"]["real_rows"] == 1
    assert rows["5.3"]["status"] == "SAMPLE-ONLY"
    assert rows["7.3"]["status"] == "SAMPLE-ONLY", "blank estate must never count as real"
    assert rows["4.1"]["status"] == "MAPPED-NO-EVIDENCE"
    assert rows["14.1"]["status"] == "UNMAPPED" and rows["14.1"]["note"]


def test_no_row_claims_clean(tmp_path: Path) -> None:
    rows = cis_ig1.coverage([_poam(tmp_path / "o" / "poam" / "poam.csv", [])])
    allowed = {"REAL", "SAMPLE-ONLY", "MAPPED-NO-EVIDENCE", "MAPPED-INTERNAL", "UNMAPPED"}
    assert {r["status"] for r in rows} <= allowed
    for r in rows:
        if r["status"] != "REAL":
            assert r["note"], r
    assert not any(r["status"] == "REAL" for r in rows)


def test_script_renders_csv_and_markdown(tmp_path: Path) -> None:
    out = tmp_path / "out"
    _poam(out / "poam" / "poam.csv", [("cis_4_4,cis_5_3", "LAB: TEST ENVIRONMENT")])
    rep = tmp_path / "rep"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "ig1_coverage.py"), str(rep), str(out)],
        capture_output=True, text=True, check=True,
    )
    summ = json.loads(proc.stdout)
    assert summ["safeguards"] == 56 and summ["REAL"] == 2
    assert summ["mapped"] == 56 - summ["UNMAPPED"]
    md = (rep / "ig1-coverage.md").read_text(encoding="utf-8")
    assert "| 4.4 | REAL |" in md and "| 1.2 | UNMAPPED |" in md
    assert len(list(csv.DictReader((rep / "ig1-coverage.csv").open(encoding="utf-8")))) == 56
