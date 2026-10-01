"""POA&M status_date is the host-local civil day (YYYY-MM-DD), not UTC.

Local = generating host timezone at generation (datetime.now().astimezone(),
honoring TZ / time.tzset). No pack-specific env var or CLI flag.

time.tzset is POSIX-only. Tests that pin a non-UTC zone skip cleanly where
tzset or the zoneinfo file is missing (Windows / slim images).
"""

from __future__ import annotations

import csv
import importlib
import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from shared.control_map import map_finding
from shared.kev import KevCatalog
from shared.poam_fields import SLA_NOTE, local_run_date, poam_fields
from shared.poam_ledger import apply_ledger
from shared.vendor_dependency import VENDOR_CHECKIN_OVERDUE, VD_NOTE

ROOT = Path(__file__).resolve().parents[1]


def _zoneinfo_root() -> Path:
    raw = os.environ.get("TZDIR")
    if raw:
        return Path(raw)
    return Path("/usr/share/zoneinfo")

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
    path = _zoneinfo_root() / name
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
    # Capture around the call so a local-midnight straddle cannot flake.
    before = datetime.now().astimezone().date()
    got = local_run_date()
    after = datetime.now().astimezone().date()
    assert got in {before, after}
    assert len(got.isoformat()) == 10


def test_local_run_date_naive_is_already_local() -> None:
    """M08: naive is local wall time, not UTC-then-convert (dies under LA)."""
    naive = datetime(2026, 10, 1, 4, 0, 0)
    with pinned_tz("America/Los_Angeles"):
        assert local_run_date(naive).isoformat() == "2026-10-01"
        # UTC-then-convert would yield 2026-09-30 (04:00Z = 21:00 PDT prior day).
        as_utc = naive.replace(tzinfo=timezone.utc).astimezone().date().isoformat()
        assert as_utc == "2026-09-30"
        assert local_run_date(naive).isoformat() != as_utc


def test_docs_say_host_local_not_utc() -> None:
    assert "host-local" in SLA_NOTE
    assert "status_date is the UTC" not in SLA_NOTE
    assert "No extra env var" in SLA_NOTE
    assert "first_seen / last_seen stay UTC" in SLA_NOTE
    assert "can be a day off" in SLA_NOTE
    assert "on a first run" in SLA_NOTE
    assert "all four surfaces" in SLA_NOTE
    assert "VENDOR_CHECKIN_OVERDUE" in SLA_NOTE
    assert "scan_time.bind_run_clock treats naive as UTC" in SLA_NOTE
    assert "load(run_at=)" in SLA_NOTE
    assert "host-local run day" in VD_NOTE
    schema = (ROOT / "schemas" / "ciso-assistant.md").read_text(encoding="utf-8")
    assert "host-local civil day" in schema
    assert "not UTC" in schema
    assert "YYYY-MM-DD" in schema
    assert "no offset" in schema
    assert "simplerisk" in schema
    assert "first_seen" in schema and "last_seen" in schema and "stay UTC" in schema
    assert "on a first run" in schema
    assert "all four surfaces" in schema
    assert "load(run_at=)" in schema
    assert "bind_run_clock treats naive as UTC" in schema
    assert "UTC calendar day" not in schema
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "load(run_at=)" in changelog
    assert "ledger_sha" in changelog
    assert "America/Los_Angeles" in changelog
    yml = (ROOT / ".github" / "workflows" / "lab.yml").read_text(encoding="utf-8")
    assert "America/Los_Angeles" in yml
    assert "Pacific/Kiritimati" in yml
    assert "pytest-tz:" in yml
    assert "TZ: ${{ matrix.tz }}" in yml


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


def _catalog():
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _write_canonical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rec: dict) -> Path:
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    asset = {
        "kind": "asset",
        "source": "inventory-nmap",
        "ref_id": "asset-10-0-0-5",
        "name": "10.0.0.5",
        "description": "Host 10.0.0.5",
        "severity": "info",
        "category": "host",
        "assets": ["10.0.0.5"],
        "labels": ["nmap"],
        "extra": {"asset_type": "PR", "ip": "10.0.0.5"},
    }
    with (out / "canonical" / "x.jsonl").open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(asset) + "\n")
        fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    (tmp_path / "in").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    return out


def test_loader_status_date_is_local_not_utc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M01: loader today must stay local. UTC date would write 2026-10-01."""
    out = _write_canonical(tmp_path, monkeypatch, _rec())
    import collectors.grc_loader as loader

    importlib.reload(loader)
    with pinned_tz("America/Los_Angeles"):
        loader.load(run_at=_LA_MIDNIGHT)
    from shared.ciso_shape import csv_rows

    poam = csv_rows(out / "poam" / "poam.csv")
    assert poam
    assert {row["status_date"] for row in poam} == {"2026-09-30"}
    sr = csv_rows(out / "simplerisk" / "poam.csv")
    assert {row["status_date"] for row in sr} == {"2026-09-30"}
    with (out / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        fed = list(csv.DictReader(fh))
    assert {row["Status Date"] for row in fed} == {"2026-09-30"}
    ledger = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    item = next(iter(ledger["items"].values()))
    assert item["status_date"] == "2026-09-30"
    assert item["first_seen"] == "2026-10-01T04:00:00Z"


def test_first_seen_is_true_utc_for_aware_non_utc_clock() -> None:
    """M10: aware +09:00 must convert to UTC, not write local wall labelled Z."""
    tokyo = timezone(timedelta(hours=9))
    clock = datetime(2026, 10, 1, 4, 0, tzinfo=tokyo)
    rec = _rec()
    ledger = apply_ledger(
        [rec],
        catalog=_catalog(),
        run_at=clock,
        prior_existed=False,
    )
    item = next(iter(ledger["items"].values()))
    assert item["first_seen"] == "2026-09-30T19:00:00Z"
    assert item["last_seen"] == "2026-09-30T19:00:00Z"
    assert item["first_seen"] != "2026-10-01T04:00:00Z"


def test_naive_run_at_status_date_and_first_seen_under_la() -> None:
    naive = datetime(2026, 10, 1, 12, 0, 0)
    rec = _rec()
    with pinned_tz("America/Los_Angeles"):
        assert local_run_date(naive).isoformat() == "2026-10-01"
        ledger = apply_ledger(
            [rec],
            catalog=_catalog(),
            run_at=naive,
            prior_existed=False,
        )
        item = next(iter(ledger["items"].values()))
        assert item["status_date"] == "2026-10-01"
        # Naive is local wall; PDT is UTC-7 on 2026-10-01.
        assert item["first_seen"] == "2026-10-01T19:00:00Z"
        assert item["last_seen"] == "2026-10-01T19:00:00Z"


def test_vendor_checkin_overdue_uses_local_run_day() -> None:
    rec = _rec()
    first = apply_ledger(
        [rec],
        catalog=_catalog(),
        run_at=datetime(2026, 9, 1, 12, 0, 0),
        prior_existed=False,
    )
    pid = next(iter(first["items"].values()))["poam_id"]
    ov = {
        pid: {
            "vendor_dependency": "Yes",
            "last_vendor_checkin": "2026-09-01",
            "vendor_product": "Vendor – Product",
        }
    }
    utc_midnight = datetime(2026, 10, 3, 0, 0, tzinfo=timezone.utc)
    naive_noon = datetime(2026, 10, 3, 12, 0, 0)
    with pinned_tz("America/Los_Angeles"):
        west = apply_ledger(
            [rec], catalog=_catalog(), run_at=utc_midnight, ledger_in=first, overrides=ov
        )
        # 2026-10-03T00:00:00Z is still 2026-10-02 in PDT, so 31 days — not overdue.
        assert VENDOR_CHECKIN_OVERDUE not in next(iter(west["items"].values()))["vd_flags"]
        local = apply_ledger(
            [rec], catalog=_catalog(), run_at=naive_noon, ledger_in=first, overrides=ov
        )
        assert VENDOR_CHECKIN_OVERDUE in next(iter(local["items"].values()))["vd_flags"]


def test_local_run_date_none_is_host_local_not_utc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M05: None path must use host-local date, not UTC."""
    frozen_utc = datetime(2026, 10, 1, 4, 0, 0, tzinfo=timezone.utc)

    class _FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            if tz is None:
                return frozen_utc.astimezone()
            return frozen_utc.astimezone(tz)

    monkeypatch.setattr("shared.poam_fields.datetime", _FrozenDateTime)
    with pinned_tz("America/Los_Angeles"):
        got = local_run_date()
        assert got.isoformat() == "2026-09-30"
        assert frozen_utc.date().isoformat() == "2026-10-01"
        assert got.isoformat() != frozen_utc.date().isoformat()


def test_load_naive_run_at_is_local_including_scanner_cutoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """N06: load() treats naive run_at as local, not UTC (status_date + bind)."""
    out = _write_canonical(tmp_path, monkeypatch, _rec())
    import collectors.grc_loader as loader
    from shared.scan_time import bind_run_clock as real_bind

    importlib.reload(loader)
    captured: list[datetime] = []

    @contextmanager
    def _capture(clock):
        captured.append(clock)
        with real_bind(clock) as resolved:
            yield resolved

    monkeypatch.setattr(loader, "bind_run_clock", _capture)
    naive = datetime(2026, 10, 1, 4, 0, 0)
    with pinned_tz("America/Los_Angeles"):
        loader.load(run_at=naive)
    from shared.ciso_shape import csv_rows

    poam = csv_rows(out / "poam" / "poam.csv")
    assert {row["status_date"] for row in poam} == {"2026-10-01"}
    ledger = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    item = next(iter(ledger["items"].values()))
    assert item["status_date"] == "2026-10-01"
    # 04:00 PDT = 11:00Z. Treating naive as UTC would write 04:00Z / 09-30.
    assert item["first_seen"] == "2026-10-01T11:00:00Z"
    assert item["last_seen"] == "2026-10-01T11:00:00Z"
    assert captured
    bound = captured[0]
    if bound.tzinfo is None:
        bound = bound.replace(tzinfo=timezone.utc)
    assert bound.astimezone(timezone.utc) == datetime(2026, 10, 1, 11, 0, tzinfo=timezone.utc)


def test_load_bind_converts_local_aware_to_true_utc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """N11: bind must convert local wall to UTC, not label local as Z."""
    _write_canonical(tmp_path, monkeypatch, _rec())
    import collectors.grc_loader as loader
    from shared.scan_time import bind_run_clock as real_bind

    importlib.reload(loader)
    captured: list[datetime] = []

    @contextmanager
    def _capture(clock):
        captured.append(clock)
        with real_bind(clock) as resolved:
            yield resolved

    monkeypatch.setattr(loader, "bind_run_clock", _capture)
    try:
        from zoneinfo import ZoneInfo
    except ImportError:
        pytest.skip("zoneinfo missing")
    local = datetime(2026, 9, 30, 21, 0, 0, tzinfo=ZoneInfo("America/Los_Angeles"))
    with pinned_tz("America/Los_Angeles"):
        loader.load(run_at=local)
    assert captured
    bound = captured[0]
    if bound.tzinfo is None:
        bound = bound.replace(tzinfo=timezone.utc)
    assert bound.astimezone(timezone.utc) == datetime(
        2026, 10, 1, 4, 0, tzinfo=timezone.utc
    )
    labelled_local_as_utc = local.replace(tzinfo=timezone.utc)
    assert bound.astimezone(timezone.utc) != labelled_local_as_utc.astimezone(
        timezone.utc
    )


def test_missed_dates_use_local_day_not_utc() -> None:
    """N10: a covered miss records the local civil day, not the UTC day."""
    rec = _rec()
    cover = {
        "kind": "finding",
        "source": "vuln-scan",
        "ref_id": "VULN-status-date-cover",
        "name": "cover peer",
        "description": "same host so the miss is covered",
        "severity": "high",
        "category": "vulnerability",
        "assets": ["10.0.0.5"],
        "labels": ["vuln", "nessus"],
        "collected_at": "2026-09-01T00:00:00Z",
        "extra": {
            "id": "plugin-cover",
            "tool": "nessus",
            "port": "80",
            "protocol": "tcp",
            "scan_time": "2026-09-01T12:00:00Z",
        },
    }
    first = apply_ledger(
        [rec, cover],
        catalog=_catalog(),
        run_at=datetime(2026, 9, 1, 12, 0, 0),
        prior_existed=False,
    )
    fp_a = next(
        fp for fp, it in first["items"].items() if "plugin-1" in str(it.get("weakness_key") or "")
    )
    utc_midnight = datetime(2026, 10, 3, 0, 0, tzinfo=timezone.utc)
    with pinned_tz("America/Los_Angeles"):
        # 2026-10-03T00:00:00Z is still 2026-10-02 17:00 PDT.
        second = apply_ledger(
            [cover], catalog=_catalog(), run_at=utc_midnight, ledger_in=first
        )
        dates = second["items"][fp_a]["missed_dates"]
        assert "2026-10-02" in dates
        assert "2026-10-03" not in dates


def test_reobserved_unchanged_status_date_agrees_on_all_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Observed-but-unchanged rows keep the ledger last-change date everywhere."""
    rec = _rec()
    first = apply_ledger(
        [rec],
        catalog=_catalog(),
        run_at=datetime(2026, 10, 1, 12, 0, 0),
        prior_existed=False,
    )
    out = _write_canonical(tmp_path, monkeypatch, rec)
    incoming = Path(os.environ["IN_DIR"])
    (incoming / "poam").mkdir(parents=True, exist_ok=True)
    (incoming / "poam" / "poam-ledger.json").write_text(
        json.dumps(first) + "\n", encoding="utf-8"
    )
    import collectors.grc_loader as loader

    importlib.reload(loader)
    with pinned_tz("America/Los_Angeles"):
        loader.load(run_at=datetime(2026, 10, 3, 12, 0, 0))
    from shared.ciso_shape import csv_rows

    poam = csv_rows(out / "poam" / "poam.csv")
    sr = csv_rows(out / "simplerisk" / "poam.csv")
    with (out / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        fed = list(csv.DictReader(fh))
    ledger = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    item = next(iter(ledger["items"].values()))
    assert item["status_date"] == "2026-10-01"
    assert {row["status_date"] for row in poam} == {"2026-10-01"}
    assert {row["status_date"] for row in sr} == {"2026-10-01"}
    assert {row["Status Date"] for row in fed} == {"2026-10-01"}
