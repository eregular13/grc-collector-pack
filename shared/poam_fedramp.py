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

M_BLANK_NOTE = (
    "Scheduled Completion Date (col M) is blank in this CSV — this is the "
    "FedRAMP template's own schedule (High/Critical +30, Moderate +90, Low +180), "
    "not the Evergreen default (Critical 15 / High 30 / Moderate 90 / Low 180). "
    "Internal effective_due = min(FedRAMP-template due, earliest KEV dueDate) "
    "and is stored on the ledger only. Evergreen-schedule text and the KEV note "
    "use Critical 15 days."
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


def item_to_row(
    item: dict[str, Any],
    *,
    weakness: str = "",
    controls: str = "",
    description: str = "",
    asset: str = "",
    detector: str = "",
    source_id: str = "",
    remediation: str = "",
    poam_id: str = "",
) -> list[str]:
    cves = item.get("cves") or []
    return [
        str(poam_id or item.get("poam_id") or ""),
        str(controls or item.get("controls") or ""),
        str(weakness or item.get("weakness_name") or item.get("name") or ""),
        str(description or item.get("description") or ""),
        str(detector or item.get("source_family") or ""),
        str(source_id or item.get("weakness_key") or ""),
        str(asset or item.get("display_asset") or item.get("asset_key") or ""),
        str(item.get("point_of_contact") or ""),
        "",
        str(remediation or item.get("remediation_plan") or ""),
        str(item.get("original_detection_date") or ""),
        "",  # M — FedRAMP template formula (Crit/High +30); never written
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
    ]


def decision_to_row(decision: dict[str, Any]) -> list[str]:
    """One FedRAMP row from the same POA&M decision the operator CSV used."""
    item = decision.get("item") if isinstance(decision.get("item"), dict) else {}
    rec = decision.get("rec") if isinstance(decision.get("rec"), dict) else {}
    mapped = decision.get("mapped") if isinstance(decision.get("mapped"), dict) else {}
    fields = decision.get("fields") if isinstance(decision.get("fields"), dict) else {}
    controls = str(fields.get("controls") or "") or ", ".join(mapped.get("nist_800_53") or [])
    return item_to_row(
        item,
        weakness=str(decision.get("weakness") or ""),
        controls=controls,
        description=str(
            fields.get("weakness_description") or rec.get("description") or ""
        ),
        asset=str(decision.get("assets_s") or ""),
        detector=str(fields.get("detector_source") or ""),
        source_id=str(fields.get("weakness_source_id") or item.get("weakness_key") or ""),
        remediation=str(mapped.get("recommended_fix") or item.get("remediation_plan") or ""),
        poam_id=str(fields.get("poam_id") or item.get("poam_id") or ""),
    )


def _write_csv(path: Path, rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(list(FEDRAMP_OPEN_HEADERS))
        for row in rows:
            writer.writerow([redact(c) if isinstance(c, str) else c for c in row])


def write_fedramp_poam(
    out_poam: Path,
    ledger: dict[str, Any],
    *,
    decisions: list[dict[str, Any]] | None = None,
) -> dict[str, Path]:
    """Write FedRAMP Open rows from the same included POA&M decisions only.

    The ledger may still hold info / honeypot / lighter-excluded items for
    coverage. Those never become Open rows. Open == poam.csv.
    """
    open_rows: list[list[str]] = []
    closed_rows: list[list[str]] = []
    if decisions is not None:
        open_rows = [decision_to_row(row) for row in decisions]
    for item in (ledger.get("items") or {}).values():
        if str(item.get("status") or "") == "closed":
            closed_rows.append(item_to_row(item))
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
        "Evergreen default schedule (poam.csv / KEV note): Critical 15 days, "
        "High 30, Moderate 90, Low 180. FedRAMP col M uses FedRAMP's own "
        "Critical/High +30 formula and stays blank in the CSV.",
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
