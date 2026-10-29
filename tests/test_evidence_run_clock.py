"""Fail-before/pass-after: evidences.csv uses the run clock, not wall clock.

Without SOURCE_DATE_EPOCH, grc_loader.load(run_at=T) stamped the ledger with T
but evidences.csv with a second wall-clock read, so two runs of the same input
at the same run_at differed. Synthetic DEMO fixtures only.
"""
from __future__ import annotations

import csv
import importlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from collectors import grc_loader
from shared.io_util import run_collector
from tests.test_fixture_scan_times import COLLECTORS

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"
RUN_AT = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str) -> list[str]:
    dest_in = tmp_path / name / "in"
    dest_out = tmp_path / name / "out"
    dest_in.mkdir(parents=True)
    dest_out.mkdir(parents=True)
    for k, v in {
        "IN_DIR": str(dest_in), "OUT_DIR": str(dest_out), "FIXTURES_DIR": str(DEMO),
        "GRC_ESTATE_LABEL": "DEMO", "DRY_RUN": "1", "GRC_LIVE_SCAN": "0",
        "CISO_PUSH": "0", "RISKREADY_PUSH": "0",
    }.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    monkeypatch.delenv("GRC_RUN_TS", raising=False)
    for source, suffixes, parse, finalize in COLLECTORS:
        run_collector(source, suffixes, parse, finalize=finalize)
    importlib.reload(grc_loader)
    monkeypatch.setattr(grc_loader, "iso_now", lambda: "2099-12-31T23:59:59Z")
    grc_loader.load(run_at=RUN_AT)
    with (dest_out / "ciso-assistant" / "evidences.csv").open(encoding="utf-8") as fh:
        return [r["description"] for r in csv.DictReader(fh)]


def test_evidences_use_run_at_not_wall_clock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    descs = _run(tmp_path, monkeypatch, "a")
    import re

    stamped = [d for d in descs if re.search(r" at \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", d)]
    assert stamped
    assert all("2024-01-02T03:04:05Z" in d for d in stamped), stamped[:2]
    assert not any("2099-12-31" in d for d in descs)
