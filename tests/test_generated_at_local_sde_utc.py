"""generated_at_local must freeze to UTC under SOURCE_DATE_EPOCH (job wall-clock residual)."""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

import pytest

from shared.estate_pages import generated_at_local
from shared.io_util import iso_now


def test_generated_at_local_sde_utc_across_extreme_tz(monkeypatch: pytest.MonkeyPatch) -> None:
    """Public stamp string must match under Etc/GMT+12 vs Pacific/Kiritimati when SDE set."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    monkeypatch.delenv("GRC_RUN_TS", raising=False)
    # force re-read
    iso = iso_now()
    assert iso.endswith("Z")

    def _stamp(tz: str) -> str:
        monkeypatch.setenv("TZ", tz)
        time.tzset()
        # both paths: explicit iso and bare now
        a = generated_at_local(iso)
        b = generated_at_local(None)
        assert a == b, f"iso path {a!r} != bare {b!r} under {tz}"
        return a

    s_gmt = _stamp("Etc/GMT+12")
    s_kiri = _stamp("Pacific/Kiritimati")
    assert s_gmt == s_kiri, (
        f"SDE stamp must be TZ-invariant UTC; got {s_gmt!r} vs {s_kiri!r}"
    )
    assert "UTC" in s_gmt or "+00" in s_gmt or s_gmt.endswith("Z") or " 22:13" in s_gmt
    # epoch 1700000000 = 2023-11-14 22:13:20 UTC
    assert s_gmt.startswith("2023-11-14"), s_gmt
