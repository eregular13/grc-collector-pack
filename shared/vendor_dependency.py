"""FedRAMP R3.0 Open O/P/Q — Vendor Dependency. Never invent Yes.

Default O=No with vd_source=default. Operator override is the only path to Yes.
Scanner "no fix available" is suggestion-only: vd_source=suggested, O stays No.
KEV / BOD 22-01 due dates are not suspended by a vendor dependency.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from shared.finding_types import extra_dict
from shared.poam_fields import _to_date

VD_YES = "Yes"
VD_NO = "No"
VD_SOURCES = frozenset({"default", "operator", "suggested"})

VENDOR_CHECKIN_OVERDUE = "VENDOR_CHECKIN_OVERDUE"
VD_MISSING_PRODUCT = "VD_MISSING_PRODUCT"
VD_HIGH_NOT_MITIGATED = "VD_HIGH_NOT_MITIGATED"
VD_INVALID_OVERRIDE = "VD_INVALID_OVERRIDE"
VD_NOT_CLOSED = "VD_NOT_CLOSED"

# Spec §2.3 / acceptance: overdue when run − P > 31 days (fires at 32, not 31).
CHECKIN_OVERDUE_AFTER_DAYS = 31
HIGH_UNMITIGATED_AFTER_DAYS = 30

VD_NOTE = (
    "Vendor Dependency = No is a default, not a verified determination. "
    "O stays No until an operator override confirms Yes. A scanner "
    "'no fix available' hint is suggestion-only (vd_source=suggested). "
    "Vendor Dependency does not suspend KEV / BOD 22-01 due dates. "
    "Last Vendor Check-in Date and Vendor Dependent Product Name are "
    "blank when O=No (never N/A or None). Product Name uses "
    "'Vendor – Product' when O=Yes."
)

SUGGEST_COMMENT = (
    "Scanner reported no fix available; Vendor Dependency stays No until "
    "the operator confirms."
)
KEV_NOT_SUSPENDED_COMMENT = (
    "Vendor Dependency does not suspend the KEV / BOD 22-01 due date."
)

_BLANK_TOKENS = frozenset({"", "n/a", "na", "none", "null", "-", "n.a."})
_NO_FIX_MARKERS = (
    "no fix available",
    "no patch available",
    "no remediation available",
    "will not fix",
    "won't fix",
    "wontfix",
)
_EN_DASH = " – "


def canon_yes_no(raw: Any) -> str | None:
    token = str(raw or "").strip().lower()
    if token == "yes":
        return VD_YES
    if token == "no":
        return VD_NO
    return None


def format_vendor_product(raw: Any) -> str:
    """Return 'Vendor – Product' or a non-N/A operator string. Empty if blank."""
    text = str(raw or "").strip()
    if text.lower() in _BLANK_TOKENS:
        return ""
    unified = text.replace("—", "–").replace(" - ", _EN_DASH)
    if "–" in unified:
        parts = [p.strip() for p in unified.split("–")]
        parts = [p for p in parts if p and p.lower() not in _BLANK_TOKENS]
        if len(parts) >= 2:
            return f"{parts[0]}{_EN_DASH}{parts[1]}"
        if len(parts) == 1:
            return parts[0]
    return text


def scanner_suggests_no_fix(rec: dict[str, Any] | None) -> bool:
    """True only when the scanner explicitly says no fix is available."""
    if not rec:
        return False
    extra = extra_dict(rec)
    for key in ("no_fix_available", "no_fix", "wontfix"):
        val = extra.get(key)
        if val in (True, "true", "True", "yes", "Yes", "1", 1):
            return True
    if extra.get("fix_available") in (False, "false", "False", "no", "No", "0", 0):
        return True
    blob = " ".join(
        str(extra.get(key) or "")
        for key in ("solution", "remediation", "fix", "plugin_output", "fix_available_text")
    ).lower()
    return any(marker in blob for marker in _NO_FIX_MARKERS)


def _append_comment(item: dict[str, Any], note: str) -> None:
    comments = list(item.get("vd_comments") or [])
    if note not in comments:
        comments.append(note)
    item["vd_comments"] = comments


def finalize_vendor_fields(
    item: dict[str, Any],
    rec: dict[str, Any] | None = None,
    *,
    run_date: date,
    override: dict[str, str] | None = None,
) -> list[str]:
    """Fill O/P/Q. Never invent Yes. Return flag codes raised this pass."""
    ov = override or {}
    ov_vd = canon_yes_no(ov.get("vendor_dependency"))
    persisted = canon_yes_no(item.get("vendor_dependency"))
    source = str(item.get("vd_source") or "").strip()
    # Current override wins. Persist prior operator Yes/No only when the
    # file is absent so run N without overrides.csv keeps the last call.
    persist_yes = ov_vd is None and source == "operator" and persisted == VD_YES
    persist_no = ov_vd is None and source == "operator" and persisted == VD_NO

    if ov_vd == VD_YES or persist_yes:
        item["vendor_dependency"] = VD_YES
        item["vd_source"] = "operator"
        if ov.get("last_vendor_checkin"):
            parsed = _to_date(ov.get("last_vendor_checkin"))
            item["last_vendor_checkin"] = parsed.isoformat() if parsed else ""
        elif item.get("last_vendor_checkin"):
            parsed = _to_date(item.get("last_vendor_checkin"))
            item["last_vendor_checkin"] = parsed.isoformat() if parsed else ""
        product_src = ov.get("vendor_product") or item.get("vendor_product")
        item["vendor_product"] = format_vendor_product(product_src)
    else:
        suggested = scanner_suggests_no_fix(rec)
        item["vendor_dependency"] = VD_NO
        item["last_vendor_checkin"] = ""
        item["vendor_product"] = ""
        if ov_vd == VD_NO or persist_no:
            item["vd_source"] = "operator"
        elif suggested:
            item["vd_source"] = "suggested"
            _append_comment(item, SUGGEST_COMMENT)
        else:
            item["vd_source"] = "default"

    if item["vd_source"] not in VD_SOURCES:
        item["vd_source"] = "default"

    flags: list[str] = []
    if item["vendor_dependency"] == VD_NO:
        item["last_vendor_checkin"] = ""
        item["vendor_product"] = ""
    else:
        item["vendor_product"] = format_vendor_product(item.get("vendor_product"))
        if not item["vendor_product"]:
            flags.append(VD_MISSING_PRODUCT)
        checkin = _to_date(item.get("last_vendor_checkin"))
        if checkin is None or (run_date - checkin).days > CHECKIN_OVERDUE_AFTER_DAYS:
            flags.append(VENDOR_CHECKIN_OVERDUE)
        rating = str(item.get("original_risk_rating") or "")
        adjusted = str(item.get("adjusted_risk_rating") or "").strip()
        odd = _to_date(item.get("original_detection_date"))
        if rating == "High" and not adjusted and odd is not None:
            if (run_date - odd).days > HIGH_UNMITIGATED_AFTER_DAYS:
                flags.append(VD_HIGH_NOT_MITIGATED)
        if item.get("kev_due"):
            _append_comment(item, KEV_NOT_SUSPENDED_COMMENT)

    item["vd_flags"] = flags
    return flags
