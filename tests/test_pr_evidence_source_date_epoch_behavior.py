"""Fail-before/pass-after: iso_now freezes under SOURCE_DATE_EPOCH."""
from __future__ import annotations

import os

from shared.io_util import iso_now

SDE = "1700000000"
SDE_ISO = "2023-11-14T22:13:20Z"


def test_iso_now_honors_source_date_epoch_utc():
    prev_sde = os.environ.get("SOURCE_DATE_EPOCH")
    prev_ts = os.environ.get("GRC_RUN_TS")
    try:
        os.environ.pop("GRC_RUN_TS", None)
        os.environ["SOURCE_DATE_EPOCH"] = SDE
        got = iso_now()
        assert got == SDE_ISO, got
        # second call must stay frozen (not wall clock drift)
        assert iso_now() == SDE_ISO
    finally:
        if prev_sde is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = prev_sde
        if prev_ts is None:
            os.environ.pop("GRC_RUN_TS", None)
        else:
            os.environ["GRC_RUN_TS"] = prev_ts


def test_iso_now_without_epoch_is_zulu_shaped():
    prev_sde = os.environ.get("SOURCE_DATE_EPOCH")
    prev_ts = os.environ.get("GRC_RUN_TS")
    try:
        os.environ.pop("SOURCE_DATE_EPOCH", None)
        os.environ.pop("GRC_RUN_TS", None)
        s = iso_now()
        assert s.endswith("Z") and "T" in s and len(s) >= 20, s
    finally:
        if prev_sde is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = prev_sde
        if prev_ts is None:
            os.environ.pop("GRC_RUN_TS", None)
        else:
            os.environ["GRC_RUN_TS"] = prev_ts
