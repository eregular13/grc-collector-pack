"""FedRAMP R3.0-style POA&M fields derived from data the pack already has.

No invented owners. Scheduled completion dates follow the Evergreen default
schedule (15/30/90/180 days from original detection by risk rating), clearly
labeled as such; `due` stays the human-committed date and is left blank.
Detection dates come from the artifact scan timestamp (labeled UTC / recorded
offset in poam.md). Missing scan time is the literal ``not recorded`` — never
the pack run date. The separate FedRAMP export keeps its own template values.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from typing import Any

from shared.scan_time import (  # noqa: F401 — re-exported for callers/tests
    NOT_RECORDED,
    PENDING_DUE,
    artifact_detection,
    calendar_date,
    merge_detection,
)
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
# Evergreen default schedule. Not a FedRAMP deadline set. Critical 15 / High 30 /
# Moderate 90 / Low 180. Documented here so the clock is not silent.
SLA_DAYS = {"Critical": 15, "High": 30, "Moderate": 90, "Low": 180}
FIRST_MILESTONE_DAYS = {15: 3, 30: 7, 90: 14, 180: 30}
KNOWN_CVE = (("heartbleed", "CVE-2014-0160"),)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
SLA_NOTE = (
    "Scheduled completion dates are the Evergreen default schedule, computed from "
    "original detection date + risk rating (Critical 15 days, High 30, Moderate 90, "
    "Low 180). They are not a committed date: `due` stays blank until a human commits "
    "one. Owner and point of contact are blank for a human to assign. Original Detection "
    "Date is the artifact scan timestamp's calendar day in the recorded timezone (UTC "
    "when the artifact is Zulu; offset-preserving when the artifact carries one — a "
    "23:00 PT scan stays that calendar day, not the next UTC day). The poam.csv column "
    "name is unchanged; this UTC / recorded-zone note lives here. When the artifact has "
    "no scan time the cell is the literal 'not recorded' (never the pack run date) and "
    "scheduled / milestone dates stay 'pending due date'. status_date is the UTC "
    "calendar day (YYYY-MM-DD), not a local civil day — the same UTC date is written "
    "on poam.csv, poam_fedramp.csv, and poam-ledger.json."
)


def utc_run_date(now: datetime | None = None) -> date:
    """UTC calendar day for status_date. Naive datetimes are treated as UTC."""
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    return clock.astimezone(timezone.utc).date()


def _to_date(raw: Any) -> date | None:
    """Parse a date without converting an offset timestamp onto the next UTC day."""
    return calendar_date(raw)


def risk_rating(severity: Any) -> str:
    return RISK_RATING[ciso_finding_severity(severity)]


def detection_date(rec: dict[str, Any], fallback: date | None = None) -> date | None:
    """Artifact scan timestamp only. Never collected_at or the pack run date.

    ``fallback`` is accepted for call-site compatibility and ignored.
    """
    del fallback
    detected, _basis, _tz = artifact_detection(rec)
    return detected


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
    for key in (
        "check_id",
        "plugin_id",
        "pluginID",
        "template_id",
        "template-id",
        "rule_id",
        "rule",
        "id",
    ):
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
    detected = detection_date(rec)
    ref = str(rec.get("ref_id") or "")
    if detected is None:
        odd = NOT_RECORDED
        scheduled_s = PENDING_DUE
        ms = PENDING_DUE
    else:
        scheduled = detected + timedelta(days=days)
        odd = detected.isoformat()
        scheduled_s = scheduled.isoformat()
        ms = milestones(str(mapped.get("control_name") or "remediate"), detected, scheduled, days)
    return {
        "poam_id": f"POAM-{ref}" if ref else "",
        "finding_ref_id": ref,
        "controls": ", ".join(mapped.get("nist_800_53") or []),
        "weakness_description": str(rec.get("description") or rec.get("name") or ""),
        "detector_source": detector_source(rec),
        "weakness_source_id": source_identifier(rec),
        "original_detection_date": odd,
        "scheduled_completion_date": scheduled_s,
        "status_date": utc_run_date().isoformat() if today is None else today.isoformat(),
        "milestones": ms,
        "original_risk_rating": rating,
        "point_of_contact": "",
        "cve": cve_for(rec),
    }


def apply_ledger_detection(
    fields: dict[str, str],
    item: dict[str, Any],
    rec: dict[str, Any],
    mapped: dict[str, Any],
) -> dict[str, str]:
    """Stamp ledger-stable original_detection_date onto poam.csv fields."""
    out = dict(fields)
    stored = str(item.get("original_detection_date") or NOT_RECORDED)
    incoming, _basis, _tz = artifact_detection(rec)
    odd = merge_detection(stored, incoming)
    out["original_detection_date"] = odd
    detected = calendar_date(odd) if odd != NOT_RECORDED else None
    if detected is None:
        out["scheduled_completion_date"] = PENDING_DUE
        out["milestones"] = PENDING_DUE
        return out
    rating = risk_rating(rec.get("severity"))
    days = SLA_DAYS[rating]
    scheduled = detected + timedelta(days=days)
    out["scheduled_completion_date"] = scheduled.isoformat()
    out["milestones"] = milestones(
        str(mapped.get("control_name") or "remediate"), detected, scheduled, days
    )
    return out
