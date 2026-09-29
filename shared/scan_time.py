"""Artifact scan timestamps for original_detection_date.

Never use the pack run date. When the artifact records no scan time the
literal ``not recorded`` is written. Calendar dates keep the timestamp's
own zone (no silent UTC day-shift).

The future-epoch cutoff (tiny/1970 epochs and stamps past the run) is
tied to the pack run clock — the run start passed through the pipeline
— not wall-clock at the moment ``parse_scan_datetime`` happens to run.
Tests inject that clock; production binds it at loader start.
"""

from __future__ import annotations

import json
import re
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

NOT_RECORDED = "not recorded"
PENDING_DUE = "pending due date"

# Scanner / artifact keys that are real scan times (never collected_at / now).
# Argus B4: lookup is case-insensitive so Greenbone Timestamp / Scuba
# TimestampZulu / Scan_Time all feed #131 original_detection_date.
_SCAN_KEYS = (
    "first_seen",
    "firstSeen",
    "first_seen_at",
    "scan_time",
    "scan_start",
    "HOST_START",
    "HOST_END",
    "host_start",
    "host_end",
    "startTimeUtc",
    "start_time_utc",
    "CreatedAt",
    "created_at",
    "generated_at",
    "timestamp",
    "Timestamp",
    "TimestampZulu",
    "timestamp_zulu",
    "time",
    "time_dt",
    "created_time",
    "created_time_dt",
    "scanTime",
    "EventTime",
    "start",
    "finished",
    "starttime",
)

_NESSUS_HOST_START = (
    "%a %b %d %H:%M:%S %Y",
    "%a %b %d %H:%M:%S %Y %Z",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
)
_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}
_NESSUS_EN = re.compile(
    r"^[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})(?:\s+\S+)?$"
)

_TZ_NAME = re.compile(r"([+-])(\d{2}):?(\d{2})$")
# Cloud Custodian writes execution.start as time.time() (float). Digit-only
# strings were already epochs; float strings were not.
_EPOCH_NUM = re.compile(r"^-?\d+(?:\.\d+)?$")
_EPOCH_MIN_DATE = date(2000, 1, 1)
# Inclusive calendar-day grace past the run's UTC date. A stamp on
# run_date + 1 day is kept (clock-skew); run_date + 2 days is not.
FUTURE_EPOCH_GRACE_DAYS = 1

# Pack run start. Bound by the loader; tests inject it.
# Unbound → wall-clock, matching pre-inject behavior.
_RUN_CLOCK: ContextVar[datetime | None] = ContextVar("grc_run_clock", default=None)


def _aware_utc(clock: datetime) -> datetime:
    if clock.tzinfo is None:
        return clock.replace(tzinfo=timezone.utc)
    return clock.astimezone(timezone.utc)


def resolve_run_clock(now: datetime | date | None = None) -> datetime:
    """Run start used for the future-epoch cutoff.

    Preference: explicit ``now`` (tests / call site) → bound run clock →
    wall-clock. A bare ``date`` is treated as that UTC midnight.
    """
    if now is not None:
        if isinstance(now, datetime):
            return _aware_utc(now)
        return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    bound = _RUN_CLOCK.get()
    if bound is not None:
        return bound
    return datetime.now(timezone.utc)


def _set_run_clock(clock: datetime | date) -> Token:
    """Bind the pack run start. Pair with ``_reset_run_clock``."""
    return _RUN_CLOCK.set(resolve_run_clock(clock))


def _reset_run_clock(token: Token) -> None:
    _RUN_CLOCK.reset(token)


@contextmanager
def bind_run_clock(clock: datetime | date) -> Iterator[datetime]:
    """Bind the run start for the duration of a parse / load.

    Always restores the prior bind (or unbound) in ``finally``, including
    when the body raises and when binds are nested.
    """
    resolved = resolve_run_clock(clock)
    token = _set_run_clock(resolved)
    try:
        yield resolved
    finally:
        _reset_run_clock(token)


def epoch_cutoff_date(now: datetime | date | None = None) -> date:
    """Last UTC calendar day an epoch stamp may land on for this run."""
    run_day = resolve_run_clock(now).date()
    return run_day + timedelta(days=FUTURE_EPOCH_GRACE_DAYS)


def _plausible_epoch_date(d: date, now: datetime | date | None = None) -> bool:
    """Reject 1970-from-tiny-epoch and far-future noise vs the run clock."""
    return _EPOCH_MIN_DATE <= d <= epoch_cutoff_date(now)


def parse_scan_datetime(
    raw: Any,
    *,
    now: datetime | date | None = None,
) -> tuple[datetime, str] | None:
    """Parse an artifact timestamp.

    Returns ``(datetime, zone_label)``. The datetime's ``.date()`` is the
    calendar day in the recorded zone — it is not converted to UTC first.

    ``now`` is the pack run start (injectable). When omitted, the bound
    run clock is used; when nothing is bound, wall-clock.
    """
    if raw in (None, ""):
        return None
    if isinstance(raw, datetime):
        dt = raw
        if dt.tzinfo is None:
            return dt, "artifact-local"
        return dt, _zone_label(dt)
    if isinstance(raw, date) and not isinstance(raw, datetime):
        return datetime(raw.year, raw.month, raw.day), "artifact-local"
    if isinstance(raw, bool):
        return None
    epoch_raw: float | None = None
    if isinstance(raw, (int, float)):
        epoch_raw = float(raw)
    elif isinstance(raw, str) and _EPOCH_NUM.fullmatch(raw.strip()):
        try:
            epoch_raw = float(raw.strip())
        except ValueError:
            epoch_raw = None
    if epoch_raw is not None:
        try:
            epoch = epoch_raw
            if abs(epoch) >= 10**11:
                epoch /= 1000.0
            dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        if not _plausible_epoch_date(dt.date(), now):
            return None
        return dt, "UTC"
    text = str(raw).strip()
    if not text or text.lower() == NOT_RECORDED:
        return None
    if text.endswith("Z") or text.endswith("z"):
        try:
            dt = datetime.fromisoformat(text[:-1] + "+00:00")
        except ValueError:
            dt = None
        if dt is not None:
            return dt, "UTC"
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        dt = None
    if dt is not None:
        if dt.tzinfo is None:
            return dt, "artifact-local"
        return dt, _zone_label(dt)
    m = _NESSUS_EN.match(text)
    if m:
        mon = _MONTHS.get(m.group(1).lower())
        if mon:
            try:
                dt = datetime(
                    int(m.group(6)),
                    mon,
                    int(m.group(2)),
                    int(m.group(3)),
                    int(m.group(4)),
                    int(m.group(5)),
                )
            except ValueError:
                dt = None
            if dt is not None:
                return dt, "artifact-local"
    for fmt in _NESSUS_HOST_START:
        try:
            dt = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return dt, "artifact-local"
    try:
        return datetime.combine(date.fromisoformat(text[:10]), datetime.min.time()), "artifact-local"
    except ValueError:
        return None


def cmp_scan_dt(left: datetime, right: datetime) -> int:
    """Compare two parsed stamps. Naive is treated as UTC. -1 / 0 / 1.

    Primary key is the UTC instant (so mixed naive/aware never TypeError).
    Same instant, different offsets: earlier local calendar date wins.
    """
    a = left if left.tzinfo is not None else left.replace(tzinfo=timezone.utc)
    b = right if right.tzinfo is not None else right.replace(tzinfo=timezone.utc)
    if a < b:
        return -1
    if a > b:
        return 1
    if left.date() < right.date():
        return -1
    if left.date() > right.date():
        return 1
    return 0


def earlier_scan_raw(current: Any, incoming: Any, *, now: datetime | date | None = None) -> Any:
    """Keep the earliest parseable observation. File order does not win.

    Exact UTC-instant + local-date ties break on the raw stamp string so
    the stored value is deterministic (lexicographically smaller wins).
    """
    if incoming in (None, ""):
        return current
    if current in (None, ""):
        return incoming
    parsed_in = parse_scan_datetime(incoming, now=now)
    parsed_cur = parse_scan_datetime(current, now=now)
    if parsed_in and parsed_cur:
        order = cmp_scan_dt(parsed_in[0], parsed_cur[0])
        if order < 0:
            return incoming
        if order > 0:
            return current
        in_s, cur_s = str(incoming), str(current)
        return incoming if in_s < cur_s else current
    if parsed_in:
        return incoming
    return current


def _zone_label(dt: datetime) -> str:
    off = dt.utcoffset()
    if off is None or off.total_seconds() == 0:
        return "UTC"
    total = int(off.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    hours, rem = divmod(total, 3600)
    minutes = rem // 60
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def calendar_date(raw: Any, *, now: datetime | date | None = None) -> date | None:
    parsed = parse_scan_datetime(raw, now=now)
    if not parsed:
        return None
    return parsed[0].date()


def to_date(raw: Any, *, now: datetime | date | None = None) -> date | None:
    """Public date parse used by ledger / KEV. No silent UTC day-shift."""
    return calendar_date(raw, now=now)


def format_detection_date(raw: Any, *, now: datetime | date | None = None) -> str:
    parsed = parse_scan_datetime(raw, now=now)
    if not parsed:
        return NOT_RECORDED
    return parsed[0].date().isoformat()


def zone_for(raw: Any, *, now: datetime | date | None = None) -> str:
    parsed = parse_scan_datetime(raw, now=now)
    return parsed[1] if parsed else ""


def _scan_value(src: dict[str, Any]) -> Any:
    """First listed scan-time key, case-insensitive (Argus B4)."""
    if not isinstance(src, dict):
        return None
    for key in _SCAN_KEYS:
        val = src.get(key)
        if val not in (None, ""):
            return val
    lower_map = {str(k).lower(): v for k, v in src.items() if v not in (None, "")}
    for key in _SCAN_KEYS:
        val = lower_map.get(key.lower())
        if val not in (None, ""):
            return val
    return None


def extra_scan_raw(rec: dict[str, Any]) -> Any:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    hit = _scan_value(extra)
    if hit not in (None, ""):
        return hit
    for blob in (extra, rec):
        info = blob.get("finding_info") if isinstance(blob, dict) else None
        if isinstance(info, dict):
            hit = _scan_value(info)
            if hit not in (None, ""):
                return hit
    return _scan_value(rec)


def artifact_detection(
    rec: dict[str, Any],
    *,
    now: datetime | date | None = None,
) -> tuple[date | None, str, str]:
    """``(date_or_None, basis, zone_label)``. Missing → not recorded, never run date."""
    raw = extra_scan_raw(rec)
    parsed = parse_scan_datetime(raw, now=now)
    if parsed:
        return parsed[0].date(), "scanner", parsed[1]
    return None, "not_recorded", ""


def merge_detection(
    stored: str,
    incoming_raw: Any,
    *,
    now: datetime | date | None = None,
) -> str:
    """First observed wins; earliest real wins over ``not recorded``; never later."""
    stored_d = calendar_date(stored, now=now) if stored and stored != NOT_RECORDED else None
    incoming_d = calendar_date(incoming_raw, now=now)
    if stored_d and incoming_d:
        return stored_d.isoformat() if stored_d <= incoming_d else incoming_d.isoformat()
    if incoming_d and not stored_d:
        return incoming_d.isoformat()
    if stored_d:
        return stored_d.isoformat()
    return NOT_RECORDED


def sibling_meta_scan_time(path: Path | None) -> str:
    """pack_drop ``meta.json`` generated_at / created_at next to a leaf file."""
    if path is None:
        return ""
    parent = path.parent if path.is_file() else path
    meta = parent / "meta.json"
    if not meta.is_file():
        return ""
    try:
        doc = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(doc, dict):
        return ""
    for key in ("generated_at", "created_at", "ts", "timestamp", "scan_time"):
        val = doc.get(key)
        if val not in (None, ""):
            return str(val)
    return ""


def pick_row_scan_time(row: dict[str, Any], fallback: str = "") -> str:
    extra = row.get("extra") if isinstance(row.get("extra"), dict) else {}
    for src in (extra, row):
        hit = _scan_value(src)
        if hit not in (None, ""):
            return str(hit)
    return fallback
