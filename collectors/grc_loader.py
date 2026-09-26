#!/usr/bin/env python3
"""Normalize canonical JSONL into CISO Assistant + RiskReady + OCSF outputs."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from shared.control_map import extra_labels, map_finding, poam_breakdown
from shared.estate_pages import (
    PageContext,
    classify_estate,
    write_client_pages,
    write_csv_with_estate,
    write_estate_sidecar,
    write_export_manifest,
)
from shared.evidence import build_evidence_rows
from shared.finding_types import dedupe_weaknesses, finding_identity, primary_asset
from shared.hardening_dedup import dedupe_hardening
from shared.poam_fields import POAM_EXTRA_FIELDS, SLA_NOTE, poam_fields
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
    ciso_finding_severity,
    ciso_vuln_severity,
    control_priority,
    residual_level,
    rr_likelihood_impact,
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


def _dedupe(records: list[dict]) -> list[dict]:
    """Collapse exact dupes. Findings key on full identity + normalized asset.

    SARIF/Trivy (and any source that stamps the same rule/CVE into ref_id via
    ``slug(..., maxlen=48)``) must not drop a second host. Display slugs stay
    truncated; this key uses the full extra.rule / extra.cve / check_id.
    """
    assets: dict[str, dict] = {}
    others: dict[tuple[str, ...], dict] = {}
    leftover: list[dict] = []
    for rec in records:
        kind = rec.get("kind")
        if kind == "asset":
            name = str(rec.get("name") or "").strip().lower()
            key = name or _stable_hash(str(rec.get("source") or ""), str(rec.get("ref_id") or rec.get("name") or ""))
            if key not in assets:
                assets[key] = rec
            continue
        ref = str(rec.get("ref_id") or "")
        if kind == "finding" and (ref or finding_identity(rec)):
            slot = (str(kind), finding_identity(rec) or ref.lower(), primary_asset(rec))
            if slot not in others:
                others[slot] = rec
            continue
        if kind and ref:
            slot = (str(kind), ref.lower())
            if slot not in others:
                others[slot] = rec
            continue
        leftover.append(rec)
    return list(assets.values()) + list(others.values()) + leftover


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
    if "cpg_2_W" not in parts:
        parts.append("cpg_2_W")
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
    # ref_id collapse, then same-issue-same-asset, then HK/Lynis/oscap keys.
    raw_records = _load_canonical()
    records = dedupe_hardening(dedupe_weaknesses(_dedupe(raw_records)))
    merged_n = max(0, len(raw_records) - len(records))
    now = iso_now()
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
    incidents = [r for r in records if r.get("kind") == "incident"]
    evidences_in = [r for r in records if r.get("kind") == "evidence"]

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
    today = datetime.now(timezone.utc).date()
    breakdown = poam_breakdown(other_findings + vuln_findings)
    poam_rows: list[list] = []
    for rec in other_findings + vuln_findings:
        mapped = mapped_by_ref.get(str(rec.get("ref_id"))) or map_finding(rec)
        if not mapped.get("include_poam"):
            continue
        assets_s = "|".join(rec.get("assets") or [])
        fields = poam_fields(rec, mapped, today)
        poam_rows.append(
            [
                rec.get("name") or rec.get("ref_id"),
                assets_s,
                ciso_finding_severity(rec.get("severity")),
                mapped["framework_refs"],
                mapped["recommended_fix"],
                "",
                "",
                "open",
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
    out_poam = out_dir() / "poam"
    _write_csv(out_poam / "poam.csv", poam_header, poam_rows, stamp=stamp)
    lines = [
        stamp.banner_md(),
        "",
        "# POA&M (operator draft)",
        "",
        "Pentera (or any scanner) finds it. Evergreen maps it.",
        "Owner and due are blank — a human fills them. No invented owners.",
        "",
        SLA_NOTE,
        "",
        "| POAM ID | Weakness | Asset | Risk | 800-53 controls | Detected | Scheduled (default) | Recommended fix | Milestones | Status |",
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
    write_text(out_poam / "poam.md", "\n".join(lines) + "\n")
    write_estate_sidecar(
        out_poam,
        stamp,
        note=(
            "POA&M is an operator draft, not a CISO Assistant import. "
            "poam.csv starts with the operator header (no # preamble) and "
            "carries a per-row estate column. SAMPLE/DEMO/LAB cannot be "
            "suppressed and is never client KEEP."
        ),
    )
    out_sr = out_dir() / "simplerisk"
    _write_csv(out_sr / "poam.csv", poam_header, poam_rows, stamp=stamp)
    write_text(
        out_sr / "README.md",
        stamp.banner_md()
        + "\n\n# SimpleRisk leave-behind\n\n"
        "Copy of POA&M rows under `out/` only. No SimpleRisk API. No push.\n"
        "Owner/due stay blank. CISO Assistant (clica/UI) is the SoR.\n",
    )
    write_estate_sidecar(out_sr, stamp)

    rr_assets = []
    for rec in assets:
        extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
        atype = _asset_type(rec)
        service = str(extra.get("service") or extra.get("cloudProvider") or "").lower()
        cloud = "NONE"
        if "aws" in service or str(extra.get("arn") or "").startswith("arn:aws"):
            cloud = "AWS"
        elif "azure" in service:
            cloud = "AZURE"
        elif "gcp" in service:
            cloud = "GCP"
        rr_type = "Identity" if atype == "SP" else ("Cloud" if cloud != "NONE" else "Server")
        crit = "HIGH" if rec.get("severity") in {"high", "critical"} else "MEDIUM"
        rr_assets.append(
            {
                "name": rec.get("name"),
                "assetType": extra.get("assetType") or rr_type,
                "status": "ACTIVE",
                "businessCriticality": extra.get("businessCriticality") or crit,
                "dataClassification": extra.get("dataClassification") or "INTERNAL",
                "cloudProvider": extra.get("cloudProvider") or cloud,
                "inIsmsScope": True,
                "source": rec.get("source"),
                "notes": rec.get("description") or "",
            }
        )

    rr_incidents = []
    for rec in incidents:
        rr_incidents.append(_incident(rec))
    for rec in findings:
        if str(rec.get("severity")) in {"high", "critical"}:
            rr_incidents.append(_incident(rec))

    rr_evidence = []
    for name, desc in evidence_rows:
        src = str(name).split(" ")[0]
        rr_evidence.append(
            {
                "title": name,
                "description": desc,
                "evidenceType": "TECHNICAL",
                "sourceType": "SENSOR",
                "status": "DRAFT",
                "source": src,
            }
        )

    proposed = []
    for rec in findings:
        if str(rec.get("severity")) not in {"high", "critical"}:
            continue
        like, impact = rr_likelihood_impact(rec.get("severity"))
        proposed.append(
            {
                "ref_id": rec.get("ref_id"),
                "name": rec.get("name"),
                "description": rec.get("description"),
                "likelihood": like,
                "impact": impact,
                "severity": rec.get("severity"),
                "assets": rec.get("assets") or [],
                "source": rec.get("source"),
                "treatment": "mitigate",
            }
        )

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

    out_rr = out_dir() / "riskready"
    write_json(out_rr / "assets.json", rr_assets)
    write_json(out_rr / "incidents.json", rr_incidents)
    write_json(out_rr / "evidence.json", rr_evidence)
    write_json(out_rr / "risks_proposed.json", proposed)
    write_json(out_dir() / "ocsf" / "compliance_findings.json", ocsf)

    excluded_poam = max(0, len(other_findings) + len(vuln_findings) - len(poam_rows))
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
        "weaknesses_total": breakdown["weaknesses_total"],
        "poam_included": breakdown["poam_included"],
        "excluded_by_reason": breakdown["excluded_by_reason"],
        "open_risks": len(poam_rows),
        "incidents": len(rr_incidents),
        "risks_proposed": len(proposed),
        "ocsf": len(ocsf),
        "canonical": len(records),
        "demo": any("demo" in (r.get("labels") or []) for r in records),
        "estate": estate,
        "estate_kind": estate_kind,
        "client": False if estate_kind != "CLIENT" else True,
        "duplicates_merged": merged_n,
        "sensors": {row["source"]: row for row in sensor_rows},
        "coverage": {"sensors": sensor_rows},
        "count_basis": (
            "deduped weaknesses (normalized asset + finding type); "
            "risk_scenarios == weaknesses == findings + vulnerabilities; "
            "POA&M is 1:1 with open risks (include_poam); "
            "weaknesses_total == poam_included + sum(excluded_by_reason)"
        ),
        "generated_at": now,
    }
    write_json(out_dir() / "summary.json", summary)
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
    )
    write_client_pages(out_dir(), ctx)
    write_text(
        out_dir() / "evidence" / "lab-report.md",
        "# Lab report\n\n"
        + json.dumps(summary, indent=2)
        + "\n\nGenerated by grc-loader. Demo mode. No live scan. No /api/risks POST.\n"
        + "POA&M: out/poam/poam.csv — owner/due blank for a human.\n"
        + "SimpleRisk leave-behind: out/simplerisk/ — no API.\n",
    )
    write_export_manifest(out_dir(), stamp)
    return summary


def make_fallback_ref(rec: dict) -> str:
    return slug(str(rec.get("name") or "asset"))


def _incident(rec: dict) -> dict:
    return {
        "title": rec.get("name"),
        "description": rec.get("description"),
        "severity": str(rec.get("severity") or "medium").upper(),
        "status": "OPEN",
        "source": rec.get("source"),
        "relatedAssets": rec.get("assets") or [],
    }


def main() -> None:
    summary = load()
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
