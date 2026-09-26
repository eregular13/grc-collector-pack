"""Exec page counts must reconcile with poam.csv / excluded.csv / register.

Argus cold-review 7 issue 2: headline open == poam.csv; kind-excluded is
named so weaknesses + kind-excluded = register and
POA&M + excluded + kind-excluded = register. Ledger-open including
excluded is secondary only. FedRAMP Open == poam (#179). Register 1:1
(#181). SAMPLE/DEMO/LAB is never client KEEP. No POST /api/risks.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from shared.ciso_shape import assert_count_consistency, csv_rows
from shared.estate_pages import (
    EstateStamp,
    PageContext,
    _reconcile,
    build_executive_summary,
)
from shared.poam_fedramp import FEDRAMP_CSV_NAME
from tests.test_poam_breakdown import _run_lab

ROOT = Path(__file__).resolve().parents[1]

RECONCILE_RE = re.compile(
    r"(?P<weaknesses>\d+) weaknesses, (?P<poam>\d+) POA&M, "
    r"(?P<excluded>\d+) excluded, (?P<kind_excluded>\d+) kind-excluded, "
    r"(?P<register>\d+) register "
    r"\((?P<p>\d+) \+ (?P<e>\d+) \+ (?P<k>\d+) = (?P<r1>\d+); "
    r"(?P<w>\d+) \+ (?P<k2>\d+) = (?P<r2>\d+)\)\."
)
OPEN_RE = re.compile(r"^Changed since last run: open=(\d+) ", re.M)
LEDGER_OPEN_RE = re.compile(r"^Ledger open including excluded: (\d+)\.\s*$", re.M)
KIND_LINE_RE = re.compile(
    r"^(\d+) kind-excluded records stay on the register as accept "
    r"and are not POA&M rows\.\s*$",
    re.M,
)


def _stamp() -> EstateStamp:
    return EstateStamp(
        kind="LAB",
        label="LAB: TEST ENVIRONMENT",
        sentence="From scans of an Evergreen-controlled test environment.",
    )


def _parse_exec_counts(text: str) -> dict[str, int]:
    open_m = OPEN_RE.search(text)
    assert open_m, text
    out: dict[str, int] = {"open": int(open_m.group(1))}
    ledger_m = LEDGER_OPEN_RE.search(text)
    if ledger_m:
        out["ledger_open"] = int(ledger_m.group(1))
    recon_m = RECONCILE_RE.search(text)
    if recon_m:
        out.update(
            {
                "weaknesses": int(recon_m.group("weaknesses")),
                "poam": int(recon_m.group("poam")),
                "excluded": int(recon_m.group("excluded")),
                "kind_excluded": int(recon_m.group("kind_excluded")),
                "register": int(recon_m.group("register")),
            }
        )
        assert int(recon_m.group("p")) == out["poam"]
        assert int(recon_m.group("e")) == out["excluded"]
        assert int(recon_m.group("k")) == out["kind_excluded"]
        assert int(recon_m.group("r1")) == out["register"]
        assert int(recon_m.group("w")) == out["weaknesses"]
        assert int(recon_m.group("k2")) == out["kind_excluded"]
        assert int(recon_m.group("r2")) == out["register"]
    kind_m = KIND_LINE_RE.search(text)
    if kind_m:
        out["kind_excluded_line"] = int(kind_m.group(1))
    assert "were not included in the POA&M" not in text
    return out


def _assert_exec_matches_csvs(out: Path) -> dict[str, int]:
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    poam = csv_rows(out / "poam" / "poam.csv")
    excluded = csv_rows(out / "poam" / "excluded.csv")
    register = csv_rows(out / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    findings = csv_rows(out / "ciso-assistant" / "findings.csv")
    vulns = csv_rows(out / "ciso-assistant" / "vulnerabilities.csv")
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    parsed = _parse_exec_counts(exec_text)
    kind_excluded = int(summary.get("kind_excluded") or 0)
    weaknesses = len(findings) + len(vulns)

    assert parsed["open"] == len(poam) == int(summary["poam"])
    assert parsed.get("poam", parsed["open"]) == len(poam)
    assert parsed.get("register", len(register)) == len(register)
    assert parsed.get("kind_excluded", kind_excluded) == kind_excluded
    if "excluded" in parsed:
        assert parsed["excluded"] + parsed["kind_excluded"] == len(excluded)
        assert parsed["weaknesses"] == weaknesses
        assert parsed["weaknesses"] + parsed["kind_excluded"] == parsed["register"]
        assert (
            parsed["poam"] + parsed["excluded"] + parsed["kind_excluded"]
            == parsed["register"]
        )
    if kind_excluded:
        assert parsed.get("kind_excluded_line") == kind_excluded
        assert "kind-excluded records stay on the register as accept" in exec_text
    ledger_open = parsed.get("ledger_open")
    if ledger_open is not None:
        assert ledger_open != parsed["open"]
        assert ledger_open >= parsed["open"]

    consistent = assert_count_consistency(out, summary)
    assert consistent["poam"] == len(poam)
    assert consistent["risk_scenarios"] == len(register)
    assert consistent["kind_excluded"] == kind_excluded

    fed = out / "poam" / FEDRAMP_CSV_NAME
    if fed.is_file():
        fed_rows = csv_rows(fed)
        plan_ids = {r.get("poam_id") or "" for r in poam if r.get("poam_id")}
        fed_ids = {r.get("POAM ID") or "" for r in fed_rows if r.get("POAM ID")}
        assert fed_ids == plan_ids
    return parsed


def test_reconcile_names_kind_excluded_and_adds_up() -> None:
    text = _reconcile(301, 154, 336, excluded_poam=147, kind_excluded=35)
    assert text is not None
    parsed = _parse_exec_counts(
        "Changed since last run: open=154 new=0 pending verification=0 reopened=0 closed=0.\n"
        + text
        + "\n"
    )
    assert parsed["weaknesses"] == 301
    assert parsed["poam"] == 154
    assert parsed["excluded"] == 147
    assert parsed["kind_excluded"] == 35
    assert parsed["register"] == 336
    assert parsed["kind_excluded_line"] == 35
    assert 154 + 147 + 35 == 336
    assert 301 + 35 == 336


def test_reconcile_silent_when_counts_already_match() -> None:
    assert _reconcile(4, 4, 4) is None


def test_exec_headline_open_is_poam_not_ledger_open() -> None:
    ctx = PageContext(
        stamp=_stamp(),
        findings=[
            {"severity": "high", "name": "a", "ref_id": "a", "assets": ["h"]},
            {"severity": "info", "name": "b", "ref_id": "b", "assets": ["h"]},
        ],
        poam_rows=[{"severity": "high", "weakness": "a", "asset": "h", "ref_id": "a"}],
        poam_n=1,
        risk_n=3,
        excluded_poam=1,
        kind_excluded=1,
        run_delta={
            "open": 1,
            "ledger_open": 2,
            "new": 2,
            "pending_verification": 0,
            "reopened": 0,
            "closed": 0,
        },
    )
    text = build_executive_summary(ctx)
    parsed = _parse_exec_counts(text)
    assert parsed["open"] == 1
    assert parsed["ledger_open"] == 2
    assert parsed["kind_excluded"] == 1
    assert parsed["register"] == 3
    assert "Ledger open including excluded: 2." in text


def test_exec_counts_match_demo_csvs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run_lab(tmp_path, monkeypatch)
    parsed = _assert_exec_matches_csvs(tmp_path)
    assert parsed["open"] >= 1


def test_exec_counts_match_sample_csvs(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "sample_to_sor.sh"
    if not script.is_file():
        pytest.skip("sample_to_sor.sh absent")
    work = tmp_path / "sample-work"
    subprocess.run(
        ["bash", str(script), "--work", str(work)],
        check=True,
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "DRY_RUN": "1",
            "GRC_LIVE_SCAN": "0",
            "CISO_PUSH": "0",
            "RISKREADY_PUSH": "0",
        },
    )
    parsed = _assert_exec_matches_csvs(work / "out")
    assert parsed["open"] >= 1


def test_exec_counts_match_farm_csvs(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "farm_drop_to_sor.sh"
    if not script.is_file():
        pytest.skip("farm_drop_to_sor.sh absent")
    work = tmp_path / "farm-work"
    subprocess.run(
        ["bash", str(script), "--work", str(work)],
        check=True,
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "DRY_RUN": "1",
            "GRC_LIVE_SCAN": "0",
            "CISO_PUSH": "0",
            "RISKREADY_PUSH": "0",
            "DROPBOX_LIVE": "0",
        },
    )
    parsed = _assert_exec_matches_csvs(work / "out")
    assert parsed["open"] >= 1
