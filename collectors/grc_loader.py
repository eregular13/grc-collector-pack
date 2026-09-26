#!/usr/bin/env python3
"""Normalize canonical JSONL into CISO Assistant + POA&M + OCSF outputs.

RiskReady JSON is LICENSE-LOCK stay-out and is not generated. Count identity
is findings + vulnerabilities == risk_scenarios; POA&M == open_risks.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
from pathlib import Path

from shared.asset_ledger import AssetLedger, attach_asset_uids
from shared.control_map import (
    LIGHTER_ENV,
    extra_labels,
    iter_poam_decisions,
    map_finding,
    poam_breakdown,
    poam_lighter_requested,
    weakness_name_for,
)
from shared.poam_rollup import (
    POAM_MEMBERS_FIELDS,
    flood_guard_summary,
    reason_code_of,
)
from shared.estate_pages import (
    PageContext,
    classify_estate,
    write_client_pages,
    write_csv_with_estate,
    write_estate_sidecar,
    write_export_manifest,
)
from shared.evidence import build_evidence_rows
from shared.ciso_shape import EXCLUDED_FIELDS
from shared.finding_types import dedupe_weaknesses, finding_identity, primary_asset
from shared.port_fold import fold_port_only_into_specific
from shared.hardening_dedup import dedupe_hardening
from shared.iiw import write_iiw
from shared.kev import KevSnapshotError, load_kev_catalog
from shared.poam_fedramp import item_from_poam_row, kev_md_footer, write_fedramp_poam
from shared.poam_fields import POAM_EXTRA_FIELDS, SLA_NOTE, apply_ledger_detection, poam_fields, utc_run_date
from shared.poam_ledger import apply_rollups, ledger_run_delta, run_ledger, write_ledger
from shared.io_util import (
    in_dir,
    iso_now,
    load_sensor_coverage,
    out_dir,
    read_jsonl,
    redact,
    stable_hash as _stable_hash,
    write_json,
    write_text,
)
from shared.schema import (
    ASSET_TYPES,
    canon_severity,
    ciso_finding_severity,
    ciso_vuln_severity,
    control_priority,
    residual_level,
    scenario_level,
    slug,
)

ASSETS_HEADER = [
    "ref_id",
    "name",
    "description",
    "domain",
    "type",
    "reference_link",
    "observation",
    "filtering_labels",
    "parent_assets",
]
CONTROLS_HEADER = [
    "ref_id",
    "name",
    "description",
    "domain",
    "status",
    "category",
    "priority",
    "csf_function",
]
EVIDENCE_HEADER = ["name", "description"]
FINDINGS_HEADER = ["ref_id", "name", "description", "severity", "status", "filtering_labels"]
VULN_HEADER = ["ref_id", "name", "description", "status", "severity", "assets", "applied_controls"]
SCENARIO_HEADER = [
    "ref_id",
    "assets",
    "threats",
    "name",
    "description",
    "existing_controls",
    "current_impact",
    "current_proba",
    "current_risk",
    "additional_controls",
    "residual_impact",
    "residual_proba",
    "residual_risk",
    "treatment",
]

VULN_CATEGORIES = {"vulnerability", "secrets", "sast"}


def _domain() -> str:
    return os.environ.get("GRC_DOMAIN", "Global")


def _load_canonical() -> list[dict]:
    folder = out_dir() / "canonical"
    records: list[dict] = []
    if not folder.exists():
        return records
    for path in sorted(folder.glob("*.jsonl")):
        for row in read_jsonl(path):
            if isinstance(row, dict):
                records.append(row)
    return records


def _asset_type(rec: dict) -> str:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    raw = str(extra.get("asset_type") or rec.get("type") or "")
    if raw in ASSET_TYPES:
        return raw
    cat = str(rec.get("category") or "").lower()
    if cat in {"identity", "saas-tenant", "saas"}:
        return "SP"
    return "PR"


class _DedupeResult(list):
    """List of kept records plus the merge audit trail."""

    merges: list[dict]


def _dedupe(records: list[dict]) -> list[dict]:
    """Collapse exact dupes. Findings key on full identity + normalized asset.

    SARIF/Trivy (and any source that stamps the same rule/CVE into ref_id via
    ``slug(..., maxlen=48)``) must not drop a second host. Display slugs stay
    truncated; this key uses the full extra.rule / extra.cve / check_id.

    Returns a list. ``.merges`` is the dropped-finding audit
    (DUPLICATE_INSTANCE → kept ref_id) for excluded/members.
    """
    assets: dict[str, dict] = {}
    others: dict[tuple[str, ...], dict] = {}
    leftover: list[dict] = []
    merges: list[dict] = []
    for rec in records:
        kind = rec.get("kind")
        if kind == "asset":
            extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
            uid = str(extra.get("asset_uid") or "").strip()
            name = str(rec.get("name") or "").strip().lower()
            key = uid or name or _stable_hash(
                str(rec.get("source") or ""),
                str(rec.get("ref_id") or rec.get("name") or ""),
            )
            if key not in assets:
                assets[key] = rec
            continue
        ref = str(rec.get("ref_id") or "")
        if kind == "finding" and (ref or finding_identity(rec)):
            slot = (str(kind), finding_identity(rec) or ref.lower(), primary_asset(rec))
            if slot not in others:
                others[slot] = rec
            else:
                kept = others[slot]
                merges.append(
                    {
                        "rec": rec,
                        "kept": kept,
                        "reason_code": "DUPLICATE_INSTANCE",
                        "rolled_into": str(kept.get("ref_id") or ""),
                        "source": rec.get("source") or "",
                        "detail": "same finding_identity + primary_asset",
                    }
                )
            continue
        if kind and ref:
            slot = (str(kind), ref.lower())
            if slot not in others:
                others[slot] = rec
            elif kind == "finding":
                kept = others[slot]
                merges.append(
                    {
                        "rec": rec,
                        "kept": kept,
                        "reason_code": "DUPLICATE_INSTANCE",
                        "rolled_into": str(kept.get("ref_id") or ""),
                        "source": rec.get("source") or "",
                        "detail": "same kind + ref_id",
                    }
                )
            continue
        leftover.append(rec)
    out = _DedupeResult(list(assets.values()) + list(others.values()) + leftover)
    out.merges = merges
    return out


def estate_label(records: list[dict]) -> str:
    """Allowed estate label. SAMPLE/DEMO/LAB/fallback never become CLIENT."""
    return classify_estate(records).label


def estate_banner(label: str) -> str:
    """One-line banner for a known label (tests + leave-behind stamps)."""
    stamp = classify_estate([], env={"GRC_ESTATE_LABEL": label.split(":")[0].split()[0]})
    if label in {stamp.label, stamp.kind}:
        return stamp.banner_oneline()
    return f"{label}: not a client estate. SAMPLE/DEMO/LAB output is never client KEEP."


def _labels(rec: dict, estate: str | None = None) -> str:
    parts = [str(x).strip() for x in rec.get("labels") or [] if str(x).strip()]
    if estate:
        token = f"estate_{estate.lower()}"
        if token not in parts:
            parts.append(token)
    for stamp in extra_labels(rec):
        if stamp not in parts:
            parts.append(stamp)
    return ",".join(x for x in parts if ":" not in x)


def _is_vuln(rec: dict) -> bool:
    """CVE/secrets/sast only. pack_drop exposure stays on findings + risk_scenarios."""
    cat = str(rec.get("category") or "").lower()
    ref = str(rec.get("ref_id") or "")
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    cve = str(extra.get("cve") or "")
    return cat in VULN_CATEGORIES or ref.upper().startswith("CVE") or cve.upper().startswith("CVE") or ref.upper().startswith("VULN-CVE")


def _write_csv(path: Path, header: list[str], rows: list[list], delimiter: str = ",", stamp=None) -> None:
    cleaned = [[redact(c) if isinstance(c, str) else c for c in row] for row in rows]
    if stamp is None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh, delimiter=delimiter, lineterminator="\n")
            writer.writerow(header)
            for row in cleaned:
                writer.writerow(row)
        return
    write_csv_with_estate(path, header, cleaned, stamp, delimiter=delimiter)


def load() -> dict:
    # Asset UIDs first (EGA- ledger), then ref_id collapse, weakness, HK keys.
    asset_ledger = AssetLedger.load(in_dir() / "assets" / "asset-ledger.json")
    overrides = in_dir() / "assets" / "assets-overrides.csv"
    if overrides.is_file():
        asset_ledger.apply_overrides(overrides)
    raw = attach_asset_uids(_load_canonical(), asset_ledger)
    deduped = _dedupe(raw)
    merge_rows = list(getattr(deduped, "merges", []) or [])
    records = dedupe_hardening(dedupe_weaknesses(deduped))
    merged_n = max(0, len(raw) - len(records))
    now = iso_now()
    try:
        kev_catalog = load_kev_catalog()
    except KevSnapshotError as exc:
        raise SystemExit(str(exc)) from exc
    domain = _domain()
    try:
        dest_in = in_dir()
    except Exception:
        dest_in = Path(os.environ["IN_DIR"]) if os.environ.get("IN_DIR") else None
    stamp = classify_estate(records, in_dir=dest_in, generated_at=now)
    estate = stamp.label
    estate_kind = stamp.kind
    assets = [r for r in records if r.get("kind") == "asset"]
    findings = [r for r in records if r.get("kind") == "finding"]
    fold_port_only_into_specific(findings)
    evidences_in = [r for r in records if r.get("kind") == "evidence"]
    severity_unmapped = sum(
        1
        for r in findings
        if isinstance(r.get("extra"), dict) and r["extra"].get("severity_unmapped")
    )

    sources = sorted({str(r.get("source") or "sensor") for r in records})

    ciso_assets = []
    for rec in assets:
        atype = _asset_type(rec)
        extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
        ciso_assets.append(
            [
                rec.get("ref_id") or make_fallback_ref(rec),
                rec.get("name") or rec.get("ref_id"),
                rec.get("description") or rec.get("name"),
                domain,
                atype,
                extra.get("arn") or extra.get("reference_link") or "",
                extra.get("observation") or "",
                _labels(rec, estate_kind),
                extra.get("parent_assets") or "",
            ]
        )

    vuln_findings = [r for r in findings if _is_vuln(r)]
    other_findings = [r for r in findings if not _is_vuln(r)]

    ciso_findings = []
    for rec in other_findings:
        ciso_findings.append(
            [
                rec.get("ref_id"),
                rec.get("name"),
                rec.get("description"),
                ciso_finding_severity(rec.get("severity")),
                rec.get("status") or "identified",
                _labels(rec, estate_kind),
            ]
        )

    controls = []
    control_ids_by_finding: dict[str, str] = {}
    mapped_by_ref: dict[str, dict] = {}
    for rec in other_findings + vuln_findings:
        mapped = map_finding(rec)
        mapped_by_ref[str(rec.get("ref_id"))] = mapped
        cid = f"CTL-{slug(str(rec.get('ref_id') or rec.get('name') or 'ctrl'))}"
        control_ids_by_finding[str(rec.get("ref_id"))] = cid
        controls.append(
            [
                cid,
                mapped["control_name"],
                mapped["recommended_fix"],
                domain,
                "to_do",
                "technical",
                control_priority(rec.get("severity")),
                mapped["csf_function"],
            ]
        )
    # unique controls by ref
    seen_ctl: set[str] = set()
    uniq_controls = []
    for row in controls:
        if row[0] in seen_ctl:
            continue
        seen_ctl.add(row[0])
        uniq_controls.append(row)

    ciso_vulns = []
    for rec in vuln_findings:
        cid = control_ids_by_finding.get(str(rec.get("ref_id")), "")
        ciso_vulns.append(
            [
                rec.get("ref_id"),
                rec.get("name"),
                rec.get("description"),
                "Exploitable",
                ciso_vuln_severity(rec.get("severity")),
                "|".join(rec.get("assets") or []),
                cid,
            ]
        )

    scenarios = []
    for rec in findings:
        level = scenario_level(rec.get("severity"))
        resid = residual_level(level)
        cid = control_ids_by_finding.get(str(rec.get("ref_id")), "")
        scenarios.append(
            [
                f"RSK-{slug(str(rec.get('ref_id') or rec.get('name')))}",
                "|".join(rec.get("assets") or []),
                rec.get("category") or rec.get("source"),
                rec.get("name"),
                rec.get("description"),
                "",
                level,
                level,
                level,
                cid,
                resid,
                resid,
                resid,
                "mitigate",
            ]
        )

    evidence_rows = build_evidence_rows(sources, findings, len(records), now)
    for rec in evidences_in:
        name = str(rec.get("name") or "").strip()
        if not name or any(row[0] == name for row in evidence_rows):
            continue
        evidence_rows.append([name, str(rec.get("description") or "")])

    poam_header = [
        "weakness",
        "asset",
        "severity",
        "framework_refs",
        "recommended_fix",
        "owner",
        "due",
        "status",
        "estate",
        *POAM_EXTRA_FIELDS,
    ]
    today = utc_run_date()
    lighter = poam_lighter_requested()
    weaknesses = other_findings + vuln_findings
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    poam_ledger = run_ledger(findings, kev_catalog)
    for item in (poam_ledger.get("items") or {}).values():
        mapped = mapped_by_ref.get(str(item.get("ref_id") or ""))
        if mapped:
            item["framework_refs"] = mapped.get("framework_refs") or ""
    for item in poam_ledger.get("closed") or []:
        mapped = mapped_by_ref.get(str(item.get("ref_id") or ""))
        if mapped:
            item["framework_refs"] = mapped.get("framework_refs") or ""
    ledger_by_ref = {
        str(item.get("ref_id") or ""): item for item in (poam_ledger.get("items") or {}).values()
    }
    poam_rows: list[list] = []
    excluded_rows: list[list] = []
    ranked = sorted(
        weaknesses,
        key=lambda rec: (
            sev_rank.get(ciso_finding_severity(rec.get("severity")), 9),
            str(rec.get("name") or rec.get("ref_id") or ""),
            str(rec.get("ref_id") or ""),
        ),
    )
    breakdown = poam_breakdown(ranked, lighter=lighter)
    decision_pairs = iter_poam_decisions(
        ranked, lighter=lighter, ledger=poam_ledger, assets_n=len(ciso_assets)
    )
    member_rows: list[list] = []
    for rec, decision in decision_pairs:
        mapped = mapped_by_ref.get(str(rec.get("ref_id"))) or map_finding(rec)
        assets_s = "|".join(rec.get("assets") or [])
        weakness = weakness_name_for(rec, mapped)
        if not decision.get("include"):
            winner_ref = str(
                decision.get("superseded_by_ref") or decision.get("rolled_into_ref") or ""
            )
            winner_item = ledger_by_ref.get(winner_ref) if winner_ref else None
            superseded_by = ""
            if winner_item:
                superseded_by = str(winner_item.get("poam_id") or "")
            if not superseded_by:
                superseded_by = str(decision.get("superseded_by") or "")
            reason = str(decision.get("reason") or "unexplained")
            code = str(decision.get("reason_code") or reason_code_of(reason))
            source = str(rec.get("source") or "")
            detail = ""
            if reason == "superseded_by_specific":
                detail = f"folded into {winner_ref or superseded_by}"
            elif reason == "telemetry_duplicate":
                detail = f"E1 same rule+asset as {winner_ref}"
            elif reason == "telemetry":
                detail = "detection/telemetry; not a posture weakness"
            excluded_rows.append(
                [
                    rec.get("ref_id") or "",
                    weakness,
                    assets_s,
                    canon_severity(rec.get("severity")),
                    reason,
                    superseded_by,
                    code,
                    superseded_by,
                    source,
                    detail,
                ]
            )
            if superseded_by or winner_ref:
                member_rows.append(
                    [
                        rec.get("ref_id") or "",
                        winner_ref,
                        str((ledger_by_ref.get(str(rec.get("ref_id") or "")) or {}).get("poam_id") or ""),
                        superseded_by,
                        code,
                        source,
                        detail,
                    ]
                )
            continue
        fields = poam_fields(rec, mapped, today)
        item = ledger_by_ref.get(str(rec.get("ref_id") or ""))
        status = "open"
        if item:
            fields = apply_ledger_detection(fields, item, rec, mapped)
            status = str(item.get("status") or "open")
        poam_rows.append(
            [
                weakness,
                assets_s,
                ciso_finding_severity(rec.get("severity")),
                mapped["framework_refs"],
                mapped["recommended_fix"],
                "",
                "",
                status,
                estate,
                *[fields[key] for key in POAM_EXTRA_FIELDS],
            ]
        )
    _pid_idx = poam_header.index("poam_id")
    listed_ids = {str(row[_pid_idx]) for row in poam_rows if len(row) > _pid_idx and row[_pid_idx]}
    observed_refs = {str(rec.get("ref_id") or "") for rec in weaknesses if rec.get("ref_id")}
    pending_carried = 0
    for item in (poam_ledger.get("items") or {}).values():
        pid = str(item.get("poam_id") or "")
        status = str(item.get("status") or "")
        if not pid or pid in listed_ids:
            continue
        if status not in {"open", "pending_verification", "reopened"}:
            continue
        # Present this scan but excluded / collapsed: stay off the plan.
        # Only carry items the scanner did not observe (pending FLAP, etc.).
        if str(item.get("ref_id") or "") in observed_refs:
            continue
        pending_carried += 1
        listed_ids.add(pid)
        fields = {key: "" for key in POAM_EXTRA_FIELDS}
        fields["poam_id"] = pid
        fields["finding_ref_id"] = str(item.get("ref_id") or "")
        fields["weakness_description"] = str(item.get("description") or item.get("name") or "")
        fields["detector_source"] = str(item.get("source_family") or "")
        fields["weakness_source_id"] = str(item.get("weakness_key") or "")
        fields["original_detection_date"] = str(item.get("original_detection_date") or "")
        fields["status_date"] = str(item.get("status_date") or "")
        fields["original_risk_rating"] = str(item.get("original_risk_rating") or "")
        poam_rows.append(
            [
                str(item.get("name") or item.get("weakness_key") or ""),
                str(item.get("display_asset") or item.get("asset_key") or ""),
                str(item.get("severity") or item.get("current_scanner_rating") or ""),
                "",
                "",
                "",
                "",
                status,
                estate,
                *[fields[key] for key in POAM_EXTRA_FIELDS],
            ]
        )

    out_ciso = out_dir() / "ciso-assistant"
    _write_csv(out_ciso / "assets.csv", ASSETS_HEADER, ciso_assets, stamp=stamp)
    _write_csv(out_ciso / "applied_controls.csv", CONTROLS_HEADER, uniq_controls, stamp=stamp)
    _write_csv(out_ciso / "evidences.csv", EVIDENCE_HEADER, evidence_rows, stamp=stamp)
    _write_csv(out_ciso / "findings.csv", FINDINGS_HEADER, ciso_findings, stamp=stamp)
    _write_csv(out_ciso / "vulnerabilities.csv", VULN_HEADER, ciso_vulns, stamp=stamp)
    _write_csv(out_ciso / "risk_scenarios.csv", SCENARIO_HEADER, scenarios, delimiter=";", stamp=stamp)
    write_estate_sidecar(
        out_ciso,
        stamp,
        note=(
            "CISO Assistant import CSVs start with the locked importer header "
            f"(no # preamble). filtering_labels include {stamp.token()}. "
            "SAMPLE/DEMO/LAB cannot be suppressed and is never client KEEP."
        ),
    )
    for merge in merge_rows:
        rec = merge.get("rec") or {}
        kept = merge.get("kept") or {}
        kept_ref = str(merge.get("rolled_into") or kept.get("ref_id") or "")
        kept_item = ledger_by_ref.get(kept_ref) if kept_ref else None
        parent_id = str((kept_item or {}).get("poam_id") or "")
        member_rows.append(
            [
                rec.get("ref_id") or "",
                kept_ref,
                "",
                parent_id,
                "DUPLICATE_INSTANCE",
                rec.get("source") or "",
                str(merge.get("detail") or "dedupe"),
            ]
        )
    out_poam = out_dir() / "poam"
    _write_csv(out_poam / "poam.csv", poam_header, poam_rows, stamp=stamp)
    _write_csv(out_poam / "excluded.csv", list(EXCLUDED_FIELDS), excluded_rows)
    _write_csv(out_poam / "poam_members.csv", list(POAM_MEMBERS_FIELDS), member_rows)
    if lighter:
        plan_line = (
            "POA&M plan: lighter — Lows and non-key Mediums excluded at operator "
            f"request ({LIGHTER_ENV}=1). Infos and honeypot hits stay off. "
            "See poam/excluded.csv."
        )
    else:
        plan_line = (
            "POA&M plan: full — Lows (180-day Evergreen default) and non-key "
            "Mediums (90-day) are on the plan, sorted by risk. Infos and honeypot "
            "hits are listed in poam/excluded.csv, not on the plan. Info-level "
            "telemetry is excluded (telemetry_info); repeated low alerts that "
            "share a rule/check id and asset collapse to one row. A bare "
            "port-open row on a host+port that already has a specific finding "
            "is excluded as superseded_by_specific (winner = highest severity, "
            "then lowest EGP- id)."
        )
    lines = [
        stamp.banner_md(),
        "",
        "# POA&M (operator draft)",
        "",
        plan_line,
        "Owner and due are blank — a human fills them. No invented owners.",
        "",
        SLA_NOTE,
        "",
        "| POAM ID | Weakness | Asset | Risk | 800-53 controls | Detected (UTC / recorded zone) | Scheduled (default) | Recommended fix | Milestones | Status |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    idx = {name: i for i, name in enumerate(poam_header)}
    for row in poam_rows:
        cell = lambda key: str(row[idx[key]]).replace("|", "/")  # noqa: E731
        lines.append(
            f"| {cell('poam_id')} | {cell('weakness')} | {cell('asset')} | {cell('original_risk_rating')} | "
            f"{cell('controls')} | {cell('original_detection_date')} | {cell('scheduled_completion_date')} | "
            f"{cell('recommended_fix')} | {cell('milestones')} | {cell('status')} |"
        )
    apply_rollups(poam_ledger, decision_pairs, included_ids=listed_ids)
    write_ledger(poam_ledger)
    ledger_by_id = {
        str(item.get("poam_id") or ""): item
        for item in (poam_ledger.get("items") or {}).values()
        if item.get("poam_id")
    }
    open_items = []
    for row in poam_rows:
        pid = str(row[_pid_idx] or "") if len(row) > _pid_idx else ""
        open_items.append(ledger_by_id.get(pid) or item_from_poam_row(row, poam_header))
    write_fedramp_poam(
        out_poam, poam_ledger, included_ids=listed_ids, open_items=open_items
    )
    write_json(out_poam / "kev_provenance.json", kev_catalog.provenance())
    write_text(out_poam / "poam.md", "\n".join(lines) + kev_md_footer(kev_catalog, poam_ledger))
    write_estate_sidecar(
        out_poam,
        stamp,
        note=(
            "POA&M is an operator draft, not a CISO Assistant import. "
            "poam.csv, poam_fedramp.csv, and poam_fedramp_closed.csv start "
            "with the operator header (no # preamble). Banner lives in "
            "ESTATE.txt. Ledger and kev_provenance.json are JSON (no # "
            "banner). poam.csv carries a per-row estate column. "
            "SAMPLE/DEMO/LAB cannot be suppressed and is never client KEEP."
        ),
    )
    out_sr = out_dir() / "simplerisk"
    _write_csv(out_sr / "poam.csv", poam_header, poam_rows, stamp=stamp)
    write_text(
        out_sr / "README.md",
        stamp.banner_md()
        + "\n\n# SimpleRisk leave-behind\n\n"
        "Copy of POA&M rows under `out/` only. No SimpleRisk API. No push.\n"
        "Owner/due stay blank. CISO Assistant (clica/UI) is the SoR.\n"
        "RiskReady JSON is not generated. Count identity is CISO register + POA&M.\n",
    )
    write_estate_sidecar(out_sr, stamp)

    ocsf = []
    for rec in other_findings:
        ocsf.append(
            {
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "severity": ciso_finding_severity(rec.get("severity")),
                "finding_info": {
                    "uid": rec.get("ref_id"),
                    "title": rec.get("name"),
                    "desc": rec.get("description"),
                },
                "compliance": {
                    "control": rec.get("extra", {}).get("check_id") or rec.get("ref_id"),
                    "status": "FAIL",
                },
                "time": rec.get("collected_at") or now,
                "unmapped": {"source": rec.get("source"), "assets": rec.get("assets")},
                "metadata": {
                    "product": {"name": "grc-collector-pack"},
                    "version": "1.0.0",
                },
            }
        )

    write_json(out_dir() / "ocsf" / "compliance_findings.json", ocsf)
    leftover_rr = out_dir() / "riskready"
    if leftover_rr.exists():
        shutil.rmtree(leftover_rr)

    excluded_poam = max(
        0, len(other_findings) + len(vuln_findings) - (len(poam_rows) - pending_carried)
    )
    sensor_rows = load_sensor_coverage(out_dir())
    summary = {
        "assets": len(ciso_assets),
        "findings": len(ciso_findings),
        "vulnerabilities": len(ciso_vulns),
        "evidences": len(evidence_rows),
        "applied_controls": len(uniq_controls),
        "poam": len(poam_rows),
        "risk_scenarios": len(scenarios),
        "weaknesses": len(findings),
        "weaknesses_total": int(breakdown["weaknesses_total"]) + pending_carried,
        "poam_included": int(breakdown["poam_included"]) + pending_carried,
        "pending_carried": pending_carried,
        "excluded": len(excluded_rows),
        "excluded_by_reason": breakdown["excluded_by_reason"],
        "poam_plan": breakdown.get("poam_plan") or ("lighter" if lighter else "full"),
        "poam_plan_note": (
            "Lows and non-key Mediums excluded at operator request"
            if lighter
            else "full plan; Lows and non-key Mediums included"
        ),
        "open_risks": len(poam_rows),
        "ocsf": len(ocsf),
        "canonical": len(records),
        "severity_unmapped": severity_unmapped,
        "demo": any("demo" in (r.get("labels") or []) for r in records),
        "estate": estate,
        "estate_kind": estate_kind,
        "client": False if estate_kind != "CLIENT" else True,
        "duplicates_merged": merged_n,
        "flood_guard": flood_guard_summary(
            decision_pairs,
            profile=str(breakdown.get("poam_plan") or ("lighter" if lighter else "full")),
            assets_n=len(ciso_assets),
            merges_n=len(merge_rows),
            members_n=len(member_rows),
        ),
        "sensors": {row["source"]: row for row in sensor_rows},
        "coverage": {"sensors": sensor_rows},
        "count_basis": (
            "deduped weaknesses (normalized asset + finding type); "
            "risk_scenarios == weaknesses == findings + vulnerabilities; "
            "POA&M is 1:1 with open risks (poam_decision + pending carry-forward); "
            "weaknesses_total == poam_included + excluded == weaknesses + pending_carried; "
            "port-only rows superseded by a specific finding on the same host+port "
            "are excluded as superseded_by_specific"
        ),
        "generated_at": now,
    }
    write_json(out_dir() / "summary.json", summary)
    families = {str(r.get("source") or "") for r in records if r.get("source")}
    asset_ledger.close_run(now=now, source_families=families)
    asset_ledger.save(out_dir() / "assets" / "asset-ledger.json")
    write_iiw(asset_ledger, dest_dir=out_dir() / "iiw", observed=set(asset_ledger._observed))
    poam_dicts = [
        {
            "severity": str(row[2] or "").lower(),
            "weakness": row[0],
            "asset": row[1],
            "ref_id": row[idx["finding_ref_id"]] if "finding_ref_id" in idx else "",
        }
        for row in poam_rows
    ]
    ctx = PageContext(
        stamp=stamp,
        records=records,
        findings=other_findings + vuln_findings,
        poam_rows=poam_dicts,
        mapped_by_ref=mapped_by_ref,
        findings_csv_n=len(ciso_findings),
        vuln_n=len(ciso_vulns),
        risk_n=len(scenarios),
        poam_n=len(poam_rows),
        merged=str(merged_n),
        excluded_poam=excluded_poam,
        in_dir=dest_in,
        generated_at=now,
        run_delta=ledger_run_delta(poam_ledger),
        sensor_rows=sensor_rows,
    )
    write_client_pages(out_dir(), ctx)
    write_text(
        out_dir() / "evidence" / "lab-report.md",
        "# Lab report\n\n"
        + json.dumps(summary, indent=2)
        + f"\n\nGenerated by grc-loader. {estate_kind} mode. No live scan. No /api/risks POST.\n"
        + "POA&M: out/poam/poam.csv — owner/due blank for a human. "
        + "Excluded Infos/honeypot/telemetry (and lighter-plan Lows/non-key Mediums) "
        + "are in out/poam/excluded.csv.\n"
        + "SimpleRisk leave-behind: out/simplerisk/ — no API.\n"
        + "RiskReady JSON is not generated. Never POST /api/risks.\n",
    )
    write_export_manifest(out_dir(), stamp)
    return summary


def make_fallback_ref(rec: dict) -> str:
    return slug(str(rec.get("name") or "asset"))


def main() -> None:
    summary = load()
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
