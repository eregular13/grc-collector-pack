"""Fail-before/pass-after: local_run_date freezes under SOURCE_DATE_EPOCH."""
from __future__ import annotations

import os

from shared.poam_fields import local_run_date

SDE = "1700000000"
SDE_DATE = "2023-11-14"


def test_local_run_date_honors_source_date_epoch_utc_day():
    prev_sde = os.environ.get("SOURCE_DATE_EPOCH")
    prev_ts = os.environ.get("GRC_RUN_TS")
    try:
        os.environ.pop("GRC_RUN_TS", None)
        os.environ["SOURCE_DATE_EPOCH"] = SDE
        got = local_run_date().isoformat()
        assert got == SDE_DATE, got
        assert local_run_date().isoformat() == SDE_DATE
    finally:
        if prev_sde is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = prev_sde
        if prev_ts is None:
            os.environ.pop("GRC_RUN_TS", None)
        else:
            os.environ["GRC_RUN_TS"] = prev_ts


def test_local_run_date_without_epoch_is_iso_date_shaped():
    prev_sde = os.environ.get("SOURCE_DATE_EPOCH")
    prev_ts = os.environ.get("GRC_RUN_TS")
    try:
        os.environ.pop("SOURCE_DATE_EPOCH", None)
        os.environ.pop("GRC_RUN_TS", None)
        s = local_run_date().isoformat()
        assert len(s) == 10 and s[4] == "-" and s[7] == "-", s
    finally:
        if prev_sde is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = prev_sde
        if prev_ts is None:
            os.environ.pop("GRC_RUN_TS", None)
        else:
            os.environ["GRC_RUN_TS"] = prev_ts
