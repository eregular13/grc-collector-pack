"""FedRAMP R3.0-shaped POA&M CSV (new file). Does not touch poam.csv.

Header order = S1 Open tab row 5 B→AB. Extra columns, if any, go after AB.
Col M (Scheduled Completion Date) is blank — the template formula owns it.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from shared.kev import (
    HEADER_BOD_DUE,
    HEADER_BOD_TRACKING,
    HEADER_CVE,
    KevCatalog,
    format_cves,
)
from shared.poam_ledger import pending_comment
from shared.io_util import redact

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


def _comments(item: dict[str, Any]) -> str:
    parts: list[str] = []
    if item.get("scanner_critical"):
        parts.append("Scanner rating Critical (col R maps Critical→High; template M has no Critical branch).")
    parts.extend(item.get("kev_comments") or [])
    if str(item.get("status") or "") == "pending_verification":
        parts.append(pending_comment(item))
    if item.get("prior_poam_id"):
        parts.append(f"Reopened from {item['prior_poam_id']}; closed row remains on Closed.")
    return "\n".join(parts)


def item_to_row(item: dict[str, Any]) -> list[str]:
    cves = item.get("cves") or []
    return [
        str(item.get("poam_id") or ""),
        "",
        str(item.get("name") or ""),
        str(item.get("description") or ""),
        str(item.get("source_family") or ""),
        str(item.get("weakness_key") or ""),
        str(item.get("display_asset") or item.get("asset_key") or ""),
        str(item.get("point_of_contact") or ""),
        "",
        str(item.get("remediation_plan") or ""),
        str(item.get("original_detection_date") or ""),
        "",  # M — template formula; never written
        str(item.get("status_date") or ""),
        str(item.get("vendor_dependency") or ""),
        str(item.get("last_vendor_checkin") or ""),
        str(item.get("vendor_product") or ""),
        str(item.get("original_risk_rating") or ""),
        "",
        "",
        "",
        "",
        "",
        "",
        _comments(item),
        str(item.get("kev_tracking") or ""),
        str(item.get("kev_due") or ""),
        format_cves(cves),
        str(item.get("framework_refs") or ""),
    ]


def _write_csv(path: Path, rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(list(FEDRAMP_CSV_HEADERS))
        for row in rows:
            writer.writerow([redact(c) if isinstance(c, str) else c for c in row])


def write_fedramp_poam(
    out_poam: Path,
    ledger: dict[str, Any],
    *,
    included_ids: set[str] | None = None,
) -> dict[str, Path]:
    """Export included rollup rows only (G0: Open rows == poam.csv rows)."""
    if included_ids is not None:
        keep = {str(x) for x in included_ids if x}
    else:
        keep = {
            str(item.get("poam_id") or "")
            for item in (ledger.get("items") or {}).values()
            if item.get("include") is True
        }
        if not keep:
            # apply_rollups not run — fail closed to included-or-open-unmarked
            keep = {
                str(item.get("poam_id") or "")
                for item in (ledger.get("items") or {}).values()
                if item.get("include") is not False and str(item.get("status") or "") != "closed"
            }
    open_rows: list[list[str]] = []
    closed_rows: list[list[str]] = []
    for item in (ledger.get("items") or {}).values():
        row = item_to_row(item)
        pid = str(item.get("poam_id") or "")
        if str(item.get("status") or "") == "closed":
            closed_rows.append(row)
            continue
        if pid and pid in keep:
            open_rows.append(row)
    for item in ledger.get("closed") or []:
        closed_rows.append(item_to_row(item))
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
    lines.append("Provenance copy: out/poam/kev_provenance.json. Ledger: out/poam/poam-ledger.json.")
    lines.append("FedRAMP-shaped export: out/poam/poam_fedramp.csv (existing poam.csv header unchanged).")
    lines.append(
        "Original Detection Date is the artifact scan timestamp's calendar day in the "
        "recorded timezone (UTC when the artifact is Zulu). Missing scan time is the "
        "literal 'not recorded' — never the pack run date. Scheduled / milestone dates "
        "are not computed from 'not recorded'."
    )
    return "\n".join(lines) + "\n"
