"""Artifact scan timestamps for original_detection_date.

Never use the pack run date. When the artifact records no scan time the
literal ``not recorded`` is written. Calendar dates keep the timestamp's
own zone (no silent UTC day-shift).
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

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


def parse_scan_datetime(raw: Any) -> tuple[datetime, str] | None:
    """Parse an artifact timestamp.

    Returns ``(datetime, zone_label)``. The datetime's ``.date()`` is the
    calendar day in the recorded zone — it is not converted to UTC first.
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
    if isinstance(raw, (int, float)) or (isinstance(raw, str) and raw.strip().isdigit()):
        try:
            epoch = int(raw)
            if epoch >= 10**11:
                epoch //= 1000
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
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


def calendar_date(raw: Any) -> date | None:
    parsed = parse_scan_datetime(raw)
    if not parsed:
        return None
    return parsed[0].date()


def to_date(raw: Any) -> date | None:
    """Public date parse used by ledger / KEV. No silent UTC day-shift."""
    return calendar_date(raw)


def format_detection_date(raw: Any) -> str:
    parsed = parse_scan_datetime(raw)
    if not parsed:
        return NOT_RECORDED
    return parsed[0].date().isoformat()


def zone_for(raw: Any) -> str:
    parsed = parse_scan_datetime(raw)
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


def artifact_detection(rec: dict[str, Any]) -> tuple[date | None, str, str]:
    """``(date_or_None, basis, zone_label)``. Missing → not recorded, never run date."""
    raw = extra_scan_raw(rec)
    parsed = parse_scan_datetime(raw)
    if parsed:
        return parsed[0].date(), "scanner", parsed[1]
    return None, "not_recorded", ""


def merge_detection(
    stored: str,
    incoming_raw: Any,
) -> str:
    """First observed wins; earliest real wins over ``not recorded``; never later."""
    stored_d = calendar_date(stored) if stored and stored != NOT_RECORDED else None
    incoming_d = calendar_date(incoming_raw)
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
