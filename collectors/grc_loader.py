#!/usr/bin/env python3
"""Normalize canonical JSONL into CISO Assistant + RiskReady + OCSF outputs."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

from shared.control_map import extra_labels, map_finding
from shared.evidence import build_evidence_rows
from shared.io_util import iso_now, out_dir, read_jsonl, redact, stable_hash as _stable_hash, write_json, write_text
from shared.schema import (
    ASSET_TYPES,
    ciso_finding_severity,
    ciso_vuln_severity,
    control_priority,
    csf_function,
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
    assets: dict[str, dict] = {}
    others: dict[tuple[str, str], dict] = {}
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
        if kind and ref:
            slot = (str(kind), ref.lower())
            if slot not in others:
                others[slot] = rec
            continue
        leftover.append(rec)
    return list(assets.values()) + list(others.values()) + leftover


def _labels(rec: dict) -> str:
    parts = [str(x).strip() for x in rec.get("labels") or [] if str(x).strip()]
    for stamp in extra_labels(rec):
        if stamp not in parts:
            parts.append(stamp)
    if "cpg_2_W" not in parts:
        parts.append("cpg_2_W")
    return ",".join(x for x in parts if ":" not in x)


def _is_vuln(rec: dict) -> bool:
    cat = str(rec.get("category") or "").lower()
    ref = str(rec.get("ref_id") or "")
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    cve = str(extra.get("cve") or "")
    return cat in VULN_CATEGORIES or ref.upper().startswith("CVE") or cve.upper().startswith("CVE") or ref.upper().startswith("VULN-CVE")


def _write_csv(path: Path, header: list[str], rows: list[list], delimiter: str = ",") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter=delimiter, lineterminator="\n")
        writer.writerow(header)
        for row in rows:
            writer.writerow([redact(c) if isinstance(c, str) else c for c in row])


def load() -> dict:
    records = _dedupe(_load_canonical())
    now = iso_now()
    domain = _domain()
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
                _labels(rec),
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
                _labels(rec),
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
                mapped["csf_function"] or csf_function(rec.get("severity")),
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
    ]
    poam_rows: list[list] = []
    for rec in other_findings + vuln_findings:
        mapped = mapped_by_ref.get(str(rec.get("ref_id"))) or map_finding(rec)
        if not mapped.get("include_poam"):
            continue
        assets_s = "|".join(rec.get("assets") or [])
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
            ]
        )

    out_ciso = out_dir() / "ciso-assistant"
    _write_csv(out_ciso / "assets.csv", ASSETS_HEADER, ciso_assets)
    _write_csv(out_ciso / "applied_controls.csv", CONTROLS_HEADER, uniq_controls)
    _write_csv(out_ciso / "evidences.csv", EVIDENCE_HEADER, evidence_rows)
    _write_csv(out_ciso / "findings.csv", FINDINGS_HEADER, ciso_findings)
    _write_csv(out_ciso / "vulnerabilities.csv", VULN_HEADER, ciso_vulns)
    _write_csv(out_ciso / "risk_scenarios.csv", SCENARIO_HEADER, scenarios, delimiter=";")
    out_poam = out_dir() / "poam"
    _write_csv(out_poam / "poam.csv", poam_header, poam_rows)
    lines = [
        "# POA&M (operator draft)",
        "",
        "Pentera (or any scanner) finds it. Evergreen maps it.",
        "Owner and due are blank — a human fills them. No invented dates.",
        "",
        "| Weakness | Asset | Severity | Framework | Recommended fix | Status |",
        "|---|---|---|---|---|---|",
    ]
    for row in poam_rows:
        fix = str(row[4]).replace("|", "/")
        lines.append(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {fix} | {row[7]} |")
    write_text(out_poam / "poam.md", "\n".join(lines) + "\n")

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

    summary = {
        "assets": len(ciso_assets),
        "findings": len(ciso_findings),
        "vulnerabilities": len(ciso_vulns),
        "evidences": len(evidence_rows),
        "applied_controls": len(uniq_controls),
        "poam": len(poam_rows),
        "risk_scenarios": len(scenarios),
        "incidents": len(rr_incidents),
        "risks_proposed": len(proposed),
        "ocsf": len(ocsf),
        "canonical": len(records),
        "demo": any("demo" in (r.get("labels") or []) for r in records),
        "generated_at": now,
    }
    write_json(out_dir() / "summary.json", summary)
    write_text(
        out_dir() / "evidence" / "lab-report.md",
        "# Lab report\n\n"
        + json.dumps(summary, indent=2)
        + "\n\nGenerated by grc-loader. Demo mode. No live scan. No /api/risks POST.\n"
        + "POA&M: out/poam/poam.csv — owner/due blank for a human.\n",
    )
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
