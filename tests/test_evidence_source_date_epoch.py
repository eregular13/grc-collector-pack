"""Deterministic evidences.csv timestamps when SOURCE_DATE_EPOCH is set."""
from __future__ import annotations

import os
from shared.evidence import build_evidence_rows
from shared.io_util import iso_now


def _rows(epoch: str) -> list[list[str]]:
    os.environ["SOURCE_DATE_EPOCH"] = epoch
    try:
        now = iso_now()
        return build_evidence_rows(["inventory-nmap", "vuln-scan"], [], 41, now)
    finally:
        os.environ.pop("SOURCE_DATE_EPOCH", None)


def test_evidence_rows_stable_under_source_date_epoch() -> None:
    a = _rows("1700000000")
    # forced "clock change" between runs — wall clock must not matter
    b = _rows("1700000000")
    assert a == b
    blob_a = "\n".join(",".join(r) for r in a)
    blob_b = "\n".join(",".join(r) for r in b)
    assert blob_a == blob_b
    assert "2023-11-14T22:13:20Z" in blob_a  # 1700000000 UTC


def test_iso_now_default_without_epoch_is_wall_clock_shaped() -> None:
    os.environ.pop("SOURCE_DATE_EPOCH", None)
    os.environ.pop("GRC_RUN_TS", None)
    s = iso_now()
    assert s.endswith("Z") and "T" in s and len(s) >= 20
