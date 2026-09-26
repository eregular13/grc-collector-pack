"""FedRAMP R3.0-shaped POA&M CSV (new file). Does not touch poam.csv.

Header order = S1 Open tab row 5 B→AB. Extra columns, if any, go after AB.
Col M (Scheduled Completion Date) is blank — the template formula owns it.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Mapping

from shared.kev import (
    HEADER_BOD_DUE,
    HEADER_BOD_TRACKING,
    HEADER_CVE,
    KevCatalog,
    format_cves,
)
from shared.poam_ledger import pending_comment
from shared.io_util import redact
from shared.vendor_dependency import (
    DEFAULT_COMMENT,
    VD_NO,
    VD_NOTE,
    VD_YES,
    format_vendor_product,
)

# S1 Open tab row 5 B→AB (R3.0). Match by header text, never by letter.
FEDRAMP_OPEN_HEADERS: tuple[str, ...] = (
    "POAM ID",
    "Controls",
    "Weakness Name",
    "Weakness Description",
    "Weakness Detector Source",
    "Weakness Source Identifier",
    "Asset Identifier",
    "Point of Contact",
    "Resources Required",
    "Overall Remediation Plan",
    "Original Detection Date",
    "Scheduled Completion Date",
    "Status Date",
    "Vendor Dependency",
    "Last Vendor Check-in Date",
    "Vendor Dependent Product Name",
    "Original Risk Rating",
    "Adjusted Risk Rating",
    "Risk Adjustment",
    "False Positive",
    "Operational Requirement",
    "Deviation Rationale",
    "Supporting Documents",
    "Comments",
    HEADER_BOD_TRACKING,
    HEADER_BOD_DUE,
    HEADER_CVE,
)

FEDRAMP_CSV_NAME = "poam_fedramp.csv"
FEDRAMP_CLOSED_CSV_NAME = "poam_fedramp_closed.csv"
KEV_PROV_NAME = "kev_provenance.json"
# Extra columns sit after AB (CVE). B→AB stay FEDRAMP_OPEN_HEADERS.
FEDRAMP_EXTRA_HEADERS: tuple[str, ...] = ("Framework Tags",)
FEDRAMP_CSV_HEADERS: tuple[str, ...] = FEDRAMP_OPEN_HEADERS + FEDRAMP_EXTRA_HEADERS

M_BLANK_NOTE = (
    "Scheduled Completion Date (col M) is blank in this CSV — the FedRAMP "
    "template formula computes it (High/Critical +30, Moderate +90, Low +180). "
    "Internal effective_due = min(template-derived due, earliest KEV dueDate) "
    "and is stored on the ledger only."
)
PLAN_ONLY_NOTE = (
    "poam_fedramp.csv Open lists only ledger items whose POAM ID is on "
    "poam.csv (the operator plan). Ledger items that stay off the plan "
    "(excluded / collapsed) are not exported as Open rows."
)
CRITICAL_R_NOTE = (
    "Original Risk Rating writes Critical when the mapped poam.csv row is "
    "Critical. The FedRAMP R3.0 template formula for col M has no Critical "
    "branch and folds Critical into High (+30); this CSV does not fold col R."
)
CRITICAL_COMMENT = (
    "Scanner rating Critical. This CSV writes Critical on Original Risk Rating. "
    "FedRAMP template col M has no Critical branch (treats Critical as High +30)."
)


def plan_by_poam_id(
    header: list[str], rows: list[list[str]]
) -> dict[str, dict[str, str]]:
    """Index poam.csv rows by POAM ID for the FedRAMP export overlay."""
    idx = {name: i for i, name in enumerate(header)}
    pid_i = idx.get("poam_id")
    if pid_i is None:
        return {}
    out: dict[str, dict[str, str]] = {}

    def cell(row: list[str], key: str) -> str:
        i = idx.get(key)
        if i is None or i >= len(row):
            return ""
        return str(row[i] or "")

    for row in rows:
        if pid_i >= len(row):
            continue
        pid = str(row[pid_i] or "").strip()
        if not pid:
            continue
        out[pid] = {
            "controls": cell(row, "controls"),
            "recommended_fix": cell(row, "recommended_fix"),
            "original_risk_rating": cell(row, "original_risk_rating"),
            "framework_refs": cell(row, "framework_refs"),
        }
    return out


def _plan_cell(plan: Mapping[str, Any] | None, key: str) -> str:
    if not plan:
        return ""
    return str(plan.get(key) or "")


def _export_risk_rating(item: dict[str, Any], plan: Mapping[str, Any] | None) -> str:
    planned = _plan_cell(plan, "original_risk_rating")
    if planned:
        return planned
    scanner = str(item.get("current_scanner_rating") or "").strip().lower()
    if item.get("scanner_critical") or scanner == "critical":
        return "Critical"
    return str(item.get("original_risk_rating") or "")


def _comments(item: dict[str, Any], plan: Mapping[str, Any] | None = None) -> str:
    parts: list[str] = []
    rating = _export_risk_rating(item, plan)
    if item.get("scanner_critical") or rating == "Critical":
        parts.append(CRITICAL_COMMENT)
    parts.extend(item.get("kev_comments") or [])
    if str(item.get("status") or "") == "pending_verification":
        parts.append(pending_comment(item))
    if item.get("prior_poam_id"):
        parts.append(f"Reopened from {item['prior_poam_id']}; closed row remains on Closed.")
    parts.extend(item.get("vd_comments") or [])
    if str(item.get("vd_source") or "") == "default" and DEFAULT_COMMENT not in parts:
        parts.append(DEFAULT_COMMENT)
    for flag in item.get("vd_flags") or []:
        parts.append(str(flag))
    return "\n".join(parts)


def item_to_row(
    item: dict[str, Any], plan: Mapping[str, Any] | None = None
) -> list[str]:
    cves = item.get("cves") or []
    vd = str(item.get("vendor_dependency") or VD_NO)
    if vd not in {VD_YES, VD_NO}:
        vd = VD_NO
    controls = _plan_cell(plan, "controls") or str(item.get("controls") or "")
    remediation = _plan_cell(plan, "recommended_fix") or str(
        item.get("remediation_plan") or ""
    )
    tags = _plan_cell(plan, "framework_refs") or str(item.get("framework_refs") or "")
    return [
        str(item.get("poam_id") or ""),
        controls,
        str(item.get("name") or ""),
        str(item.get("description") or ""),
        str(item.get("source_family") or ""),
        str(item.get("weakness_key") or ""),
        str(item.get("display_asset") or item.get("asset_key") or ""),
        str(item.get("point_of_contact") or ""),
        "",
        remediation,
        str(item.get("original_detection_date") or ""),
        "",  # M — template formula; never written
        str(item.get("status_date") or ""),
        vd,
        str(item.get("last_vendor_checkin") or "") if vd == VD_YES else "",
        format_vendor_product(item.get("vendor_product")) if vd == VD_YES else "",
        _export_risk_rating(item, plan),
        "",
        "",
        "",
        "",
        "",
        "",
        _comments(item, plan),
        str(item.get("kev_tracking") or ""),
        str(item.get("kev_due") or ""),
        format_cves(cves),
        tags,
    ]


def _write_csv(path: Path, rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(list(FEDRAMP_CSV_HEADERS))
        for row in rows:
            writer.writerow([redact(c) if isinstance(c, str) else c for c in row])


def _vendor_dependent(item: dict[str, Any]) -> bool:
    return str(item.get("vendor_dependency") or "").strip().lower() == "yes"


def write_fedramp_poam(
    out_poam: Path,
    ledger: dict[str, Any],
    plan_by_id: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Path]:
    open_rows: list[list[str]] = []
    closed_rows: list[list[str]] = []
    restrict_open = plan_by_id is not None

    def _plan_for(item: dict[str, Any]) -> Mapping[str, Any] | None:
        if plan_by_id is None:
            return None
        return plan_by_id.get(str(item.get("poam_id") or ""))

    def _is_open(item: dict[str, Any]) -> bool:
        # Spec §2.2: don't put VDs on the Closed tab.
        return _vendor_dependent(item) or str(item.get("status") or "") != "closed"

    if restrict_open:
        by_id: dict[str, dict[str, Any]] = {}
        for item in (ledger.get("items") or {}).values():
            pid = str(item.get("poam_id") or "")
            if pid:
                by_id[pid] = item
        for item in ledger.get("closed") or []:
            pid = str(item.get("poam_id") or "")
            if pid and pid not in by_id:
                by_id[pid] = item
        for pid, plan in plan_by_id.items():
            item = by_id.get(pid)
            if item is None or not _is_open(item):
                continue
            open_rows.append(item_to_row(item, plan))
        for item in (ledger.get("items") or {}).values():
            if not _is_open(item):
                closed_rows.append(item_to_row(item, _plan_for(item)))
        for item in ledger.get("closed") or []:
            if not _is_open(item):
                closed_rows.append(item_to_row(item, _plan_for(item)))
    else:
        for item in (ledger.get("items") or {}).values():
            row = item_to_row(item)
            if _is_open(item):
                open_rows.append(row)
            else:
                closed_rows.append(row)
        for item in ledger.get("closed") or []:
            row = item_to_row(item)
            if _is_open(item):
                open_rows.append(row)
            else:
                closed_rows.append(row)
    open_path = out_poam / FEDRAMP_CSV_NAME
    closed_path = out_poam / FEDRAMP_CLOSED_CSV_NAME
    _write_csv(open_path, open_rows)
    _write_csv(closed_path, closed_rows)
    return {"open": open_path, "closed": closed_path}


def kev_md_footer(catalog: KevCatalog, ledger: dict[str, Any]) -> str:
    lines = [
        "",
        "## KEV catalog (offline snapshot)",
        "",
        M_BLANK_NOTE,
        "",
        f"kev_evaluated: {str(catalog.kev_evaluated).lower()}",
    ]
    if not catalog.kev_evaluated:
        lines.append(
            "No in/kev/ snapshot. Binding Operational Directive 22-01 columns are blank "
            "(not 'checked, not in KEV')."
        )
    else:
        lines.extend(
            [
                f"catalogVersion: {catalog.catalog_version}",
                f"dateReleased: {catalog.date_released}",
                f"count: {catalog.count}",
                f"sha256: {catalog.sha256}",
                f"source_url: {catalog.source_url}",
                f"fetched_at_utc: {catalog.fetched_at_utc}",
            ]
        )
        if catalog.stale:
            lines.append(f"stale: {catalog.stale}")
    if ledger.get("warnings"):
        lines.append("ledger_warnings: " + ", ".join(ledger["warnings"]))
    lines.append(VD_NOTE)
    lines.append("Provenance copy: out/poam/kev_provenance.json. Ledger: out/poam/poam-ledger.json.")
    lines.append("FedRAMP-shaped export: out/poam/poam_fedramp.csv (existing poam.csv header unchanged).")
    lines.append(PLAN_ONLY_NOTE)
    lines.append(CRITICAL_R_NOTE)
    lines.append(
        "Original Detection Date is the artifact scan timestamp's calendar day in the "
        "recorded timezone (UTC when the artifact is Zulu). Missing scan time is the "
        "literal 'not recorded' — never the pack run date. Scheduled / milestone dates "
        "are not computed from 'not recorded'."
    )
    return "\n".join(lines) + "\n"
