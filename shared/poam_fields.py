"""FedRAMP R3.0-style POA&M fields derived from data the pack already has.

No invented owners. Scheduled completion dates are *defaults* (30/90/180 days
from original detection by risk rating), clearly labeled as such; `due` stays
the human-committed date and is left blank. Dates are UTC calendar dates.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from typing import Any

from shared.schema import ciso_finding_severity

POAM_EXTRA_FIELDS = (
    "poam_id",
    "finding_ref_id",
    "controls",
    "weakness_description",
    "detector_source",
    "weakness_source_id",
    "original_detection_date",
    "scheduled_completion_date",
    "status_date",
    "milestones",
    "original_risk_rating",
    "point_of_contact",
    "cve",
)

RISK_RATING = {"critical": "Critical", "high": "High", "medium": "Moderate", "low": "Low"}
# FedRAMP POA&M Template R3.0 Instructions A9: High/Critical 30, Moderate 90, Low 180.
SLA_DAYS = {"Critical": 30, "High": 30, "Moderate": 90, "Low": 180}
FIRST_MILESTONE_DAYS = {30: 7, 90: 14, 180: 30}
KNOWN_CVE = (("heartbleed", "CVE-2014-0160"),)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
SLA_NOTE = (
    "Scheduled completion dates are DEFAULTS computed from original detection date + risk rating "
    "(Critical/High 30 days, Moderate 90, Low 180; FedRAMP POA&M R3.0 convention). They are not a "
    "committed date: `due` stays blank until a human commits one. Owner and point of contact are "
    "blank for a human to assign. Dates are UTC."
)


def _to_date(raw: Any) -> date | None:
    if raw in (None, ""):
        return None
    if isinstance(raw, (int, float)) or (isinstance(raw, str) and raw.strip().isdigit()):
        try:
            return datetime.fromtimestamp(int(raw), tz=timezone.utc).date()
        except (OverflowError, OSError, ValueError):
            return None
    text = str(raw).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.date()


def risk_rating(severity: Any) -> str:
    return RISK_RATING[ciso_finding_severity(severity)]


def detection_date(rec: dict[str, Any], fallback: date) -> date:
    """first-seen if present, else scan time, else collected_at, else the run date."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    for raw in (
        extra.get("first_seen"), extra.get("firstSeen"), extra.get("first_seen_at"),
        rec.get("first_seen"), rec.get("firstSeen"),
        extra.get("scan_time"), extra.get("scan_start"),
        rec.get("collected_at"),
    ):
        got = _to_date(raw)
        if got:
            return got
    return fallback


def detector_source(rec: dict[str, Any]) -> str:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    source = str(rec.get("source") or "").strip() or "unknown"
    tool = str(extra.get("tool") or extra.get("scanner") or "").strip()
    nse = str(extra.get("nse_script") or "").strip()
    tools = extra.get("tools") if isinstance(extra.get("tools"), list) else []
    merged = [str(t).strip() for t in tools if str(t).strip()]
    if nse:
        tool = f"{tool or 'nmap'} NSE {nse}"
    elif merged:
        tool = ", ".join(dict.fromkeys(merged))
    return f"{source} ({tool})" if tool else source


def source_identifier(rec: dict[str, Any]) -> str:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    for key in ("check_id", "plugin_id", "pluginID", "template_id", "template-id", "rule", "id"):
        val = str(extra.get(key) or "").strip()
        if val:
            return val
    return ""


def cve_for(rec: dict[str, Any]) -> str:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    found: list[str] = []
    for raw in (extra.get("cve"), rec.get("ref_id"), rec.get("name"), rec.get("description")):
        for match in _CVE_RE.findall(str(raw or "")):
            up = match.upper()
            if up not in found:
                found.append(up)
    if not found:
        blob = f"{rec.get('name') or ''} {rec.get('description') or ''}".lower()
        for needle, cve in KNOWN_CVE:
            if needle in blob:
                found.append(cve)
    return ", ".join(found)


def milestones(control_name: str, detected: date, scheduled: date, days: int) -> str:
    first = detected + timedelta(days=FIRST_MILESTONE_DAYS.get(days, 7))
    fix_by = max(first, scheduled - timedelta(days=7))
    return "; ".join(
        (
            f"M1 {first.isoformat()} Validate finding, confirm asset owner and scope",
            f"M2 {fix_by.isoformat()} Apply fix: {control_name}",
            f"M3 {scheduled.isoformat()} Rescan to verify closure and attach evidence",
        )
    )


def poam_fields(rec: dict[str, Any], mapped: dict[str, Any], today: date) -> dict[str, str]:
    rating = risk_rating(rec.get("severity"))
    days = SLA_DAYS[rating]
    detected = detection_date(rec, today)
    scheduled = detected + timedelta(days=days)
    ref = str(rec.get("ref_id") or "")
    return {
        "poam_id": f"POAM-{ref}" if ref else "",
        "finding_ref_id": ref,
        "controls": ", ".join(mapped.get("nist_800_53") or []),
        "weakness_description": str(rec.get("description") or rec.get("name") or ""),
        "detector_source": detector_source(rec),
        "weakness_source_id": source_identifier(rec),
        "original_detection_date": detected.isoformat(),
        "scheduled_completion_date": scheduled.isoformat(),
        "status_date": today.isoformat(),
        "milestones": milestones(str(mapped.get("control_name") or "remediate"), detected, scheduled, days),
        "original_risk_rating": rating,
        "point_of_contact": "",
        "cve": cve_for(rec),
    }
