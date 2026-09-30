"""POA&M status_date is the host-local civil day (YYYY-MM-DD), not UTC.

Local = generating host timezone at generation (datetime.now().astimezone(),
honoring TZ / time.tzset). No pack-specific env var or CLI flag.

time.tzset is POSIX-only. Tests that pin a non-UTC zone skip cleanly where
tzset or the zoneinfo file is missing (Windows / slim images).
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest

from shared.control_map import map_finding
from shared.kev import KevCatalog
from shared.poam_fields import SLA_NOTE, local_run_date, poam_fields
from shared.poam_ledger import apply_ledger

ROOT = Path(__file__).resolve().parents[1]
ZONEINFO = Path("/usr/share/zoneinfo")

# Instant where UTC and each zone disagree on the calendar day.
# 2026-10-01 04:00 UTC = 2026-09-30 21:00 PDT (America/Los_Angeles, UTC-7).
# 2026-09-30 20:00 UTC = 2026-10-01 06:00 AEST (Australia/Sydney still UTC+10
# on 2026-09-30; AEDT starts the first Sunday of October).
_LA_MIDNIGHT = datetime(2026, 10, 1, 4, 0, tzinfo=timezone.utc)
_SYDNEY_MIDNIGHT = datetime(2026, 9, 30, 20, 0, tzinfo=timezone.utc)

_ZONES = (
    ("America/Los_Angeles", _LA_MIDNIGHT, "2026-10-01", "2026-09-30"),
    ("Australia/Sydney", _SYDNEY_MIDNIGHT, "2026-09-30", "2026-10-01"),
)


def _require_tzset() -> None:
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is POSIX-only")


def _require_zone(name: str) -> None:
    path = ZONEINFO / name
    if not path.exists():
        pytest.skip(f"tzdata missing {name}")


@contextmanager
def pinned_tz(name: str):
    """Set TZ + tzset; always restore so later tests keep the host zone."""
    _require_tzset()
    _require_zone(name)
    prev = os.environ.get("TZ")
    os.environ["TZ"] = name
    time.tzset()
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = prev
        time.tzset()


def _rec() -> dict:
    return {
        "kind": "finding",
        "source": "vuln-scan",
        "ref_id": "VULN-status-date-local",
        "name": "OpenSSL heartbeat",
        "description": "fixture",
        "severity": "high",
        "category": "vulnerability",
        "assets": ["10.0.0.5"],
        "labels": ["vuln", "nessus"],
        "collected_at": "2026-09-01T00:00:00Z",
        "extra": {
            "id": "plugin-1",
            "tool": "nessus",
            "port": "443",
            "protocol": "tcp",
            "scan_time": "2026-09-01T12:00:00Z",
        },
    }


def test_local_run_date_none_matches_host_wall_clock() -> None:
    assert local_run_date().isoformat() == datetime.now().astimezone().date().isoformat()
    assert len(local_run_date().isoformat()) == 10


def test_local_run_date_naive_is_already_local() -> None:
    naive = datetime(2026, 10, 1, 4, 0, 0)
    assert local_run_date(naive).isoformat() == "2026-10-01"


def test_docs_say_host_local_not_utc() -> None:
    assert "host-local" in SLA_NOTE
    assert "status_date is the UTC" not in SLA_NOTE
    schema = (ROOT / "schemas" / "ciso-assistant.md").read_text(encoding="utf-8")
    assert "host-local civil day" in schema
    assert "not UTC" in schema


@pytest.mark.parametrize("zone,clock,utc_day,local_day", _ZONES)
def test_local_run_date_crosses_utc_midnight(
    zone: str, clock: datetime, utc_day: str, local_day: str
) -> None:
    assert clock.astimezone(timezone.utc).date().isoformat() == utc_day
    with pinned_tz(zone):
        got = local_run_date(clock).isoformat()
        assert got == local_day
        assert got != utc_day
        assert len(got) == 10
        assert "+" not in got and "Z" not in got


@pytest.mark.parametrize("zone,clock,utc_day,local_day", _ZONES)
def test_poam_fields_status_date_is_local_civil_day(
    zone: str, clock: datetime, utc_day: str, local_day: str
) -> None:
    rec = _rec()
    with pinned_tz(zone):
        fields = poam_fields(rec, map_finding(rec), local_run_date(clock))
        assert fields["status_date"] == local_day
        assert fields["status_date"] != utc_day
        # Detection date stays the artifact calendar day (out of scope).
        assert fields["original_detection_date"] == "2026-09-01"


@pytest.mark.parametrize("zone,clock,utc_day,local_day", _ZONES)
def test_ledger_status_date_is_local_civil_day(
    zone: str, clock: datetime, utc_day: str, local_day: str
) -> None:
    rec = _rec()
    with pinned_tz(zone):
        ledger = apply_ledger(
            [rec],
            catalog=KevCatalog(kev_evaluated=False, reason="snapshot_missing"),
            run_at=clock,
            prior_existed=False,
        )
        item = next(iter(ledger["items"].values()))
        assert item["status_date"] == local_day
        assert item["status_date"] != utc_day
        # first_seen / last_seen stay UTC ISO (not this change).
        assert item["first_seen"].endswith("Z")
        assert item["last_seen"].endswith("Z")
        utc_iso = clock.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert item["first_seen"] == utc_iso
