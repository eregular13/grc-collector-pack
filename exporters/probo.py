"""Probo addRisk / addFinding draft exporter.

Shapes follow getprobo/probo public MCP/GraphQL docs:
- addRisk: name, category, treatment, inherent/residual 1–5
- addFinding: kind, description, source, status, priority

organization_id / owner_id stay null — the operator fills them on their
Probo instance. This pack never POSTs GraphQL or MCP.

File-drop only. posted=false. SAMPLE/DEMO ≠ client.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from exporters.model import (
    PackEstate,
    PackFinding,
    load_pack_estate,
    residual_score,
    score_scenario_level,
    score_severity,
)
from shared.schema import canon_severity

# Probo FindingKind / FindingStatus / FindingPriority (public MCP docs).
_KIND = {
    "info": "OBSERVATION",
    "low": "OBSERVATION",
    "medium": "MINOR_NONCONFORMITY",
    "high": "MINOR_NONCONFORMITY",
    "critical": "MAJOR_NONCONFORMITY",
}
_PRIORITY = {
    "info": "LOW",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "HIGH",
}
# Probo RiskTreatment has no OPEN/DRAFT — MITIGATED is the CISO "mitigate" map.
# Honesty: draft intent only; not posted.
_TREATMENT = {
    "mitigate": "MITIGATED",
    "mitigated": "MITIGATED",
    "accept": "ACCEPTED",
    "accepted": "ACCEPTED",
    "avoid": "AVOIDED",
    "avoided": "AVOIDED",
    "transfer": "TRANSFERRED",
    "transferred": "TRANSFERRED",
}


def _category(finding: PackFinding) -> str:
    for label in finding.labels:
        low = label.lower()
        if low in {"demo", "sample"} or low.startswith("cpg_") or low.startswith("csf_") or low.startswith("nist_"):
            continue
        return label
    if finding.kind == "vulnerability":
        return "Vulnerability"
    return "Security Assessment"


def _add_finding(finding: PackFinding, estate: PackEstate) -> dict[str, Any]:
    sev = canon_severity(finding.severity)
    desc = finding.description or finding.name
    if finding.assets:
        desc = f"{desc} [assets: {', '.join(finding.assets)}]"
    source = (
        "grc-collector-pack (LAB/DEMO dest_in file-drop)"
        if estate.lab and not estate.sample
        else "grc-collector-pack (SAMPLE/DEMO file-drop)"
    )
    return {
        "shape": "addFinding",
        "documentation_only": True,
        "posted": False,
        "organization_id": None,
        "owner_id": None,
        "ref_id": finding.ref_id,
        "kind": _KIND[sev],
        "description": desc,
        "source": source,
        "status": "OPEN",
        "priority": _PRIORITY[sev],
        "note": estate.banner,
    }


def _add_risk_from_finding(finding: PackFinding, estate: PackEstate) -> dict[str, Any]:
    like = impact = score_severity(finding.severity)
    res = residual_score(like)
    return {
        "shape": "addRisk",
        "documentation_only": True,
        "posted": False,
        "organization_id": None,
        "owner_id": None,
        "ref_id": finding.ref_id,
        "name": finding.name,
        "description": finding.description,
        "category": _category(finding),
        "treatment": "MITIGATED",
        "inherent_likelihood": like,
        "inherent_impact": impact,
        "residual_likelihood": res,
        "residual_impact": res,
        "note": (
            f"{estate.banner} Draft treatment maps CISO mitigate → MITIGATED. "
            "Operator confirms before any live addRisk."
        ),
    }


def _add_risk_from_scenario(scenario, estate: PackEstate) -> dict[str, Any]:
    like = score_scenario_level(scenario.current_proba or scenario.current_risk)
    impact = score_scenario_level(scenario.current_impact or scenario.current_risk)
    res_like = (
        score_scenario_level(scenario.residual_proba or scenario.residual_risk)
        if scenario.residual_proba or scenario.residual_risk
        else residual_score(like)
    )
    res_impact = (
        score_scenario_level(scenario.residual_impact or scenario.residual_risk)
        if scenario.residual_impact or scenario.residual_risk
        else residual_score(impact)
    )
    treatment = _TREATMENT.get(str(scenario.treatment or "mitigate").lower(), "MITIGATED")
    return {
        "shape": "addRisk",
        "documentation_only": True,
        "posted": False,
        "organization_id": None,
        "owner_id": None,
        "ref_id": scenario.ref_id,
        "name": scenario.name,
        "description": scenario.description,
        "category": scenario.threats or "Security Assessment",
        "treatment": treatment,
        "inherent_likelihood": like,
        "inherent_impact": impact,
        "residual_likelihood": res_like,
        "residual_impact": res_impact,
        "note": (
            f"{estate.banner} Draft treatment maps CISO {scenario.treatment or 'mitigate'} "
            f"→ {treatment}. Operator confirms before any live addRisk."
        ),
    }


def _create_risk_compat(add_risk: dict[str, Any]) -> dict[str, Any]:
    """Keep the older createRisk preview shape for existing tests."""
    return {
        "shape": "createRisk",
        "documentation_only": True,
        "ref_id": add_risk.get("ref_id"),
        "name": add_risk.get("name"),
        "description": add_risk.get("description"),
        "severity": None,
        "status": "draft",
        "addRisk": {
            "organization_id": None,
            "name": add_risk.get("name"),
            "category": add_risk.get("category"),
            "treatment": add_risk.get("treatment"),
            "inherent_likelihood": add_risk.get("inherent_likelihood"),
            "inherent_impact": add_risk.get("inherent_impact"),
            "residual_likelihood": add_risk.get("residual_likelihood"),
            "residual_impact": add_risk.get("residual_impact"),
            "note": add_risk.get("note"),
        },
    }


def build_probo_preview(out: Path | None = None, estate: PackEstate | None = None) -> dict[str, Any]:
    estate = estate or load_pack_estate(out)
    add_findings = [_add_finding(f, estate) for f in estate.all_findings]
    add_risks: list[dict[str, Any]] = [_add_risk_from_scenario(s, estate) for s in estate.scenarios]
    seen = {str(row.get("ref_id") or "").lower() for row in add_risks}
    for finding in estate.all_findings:
        if finding.severity not in {"high", "critical"}:
            continue
        key = finding.ref_id.lower()
        if key in seen:
            continue
        add_risks.append(_add_risk_from_finding(finding, estate))
        seen.add(key)
    create_risk = []
    for finding in estate.findings:
        if finding.severity not in {"high", "critical"}:
            continue
        draft = _add_risk_from_finding(finding, estate)
        compat = _create_risk_compat(draft)
        compat["severity"] = finding.severity
        create_risk.append(compat)
    stamp = estate.estate_stamp()
    return {
        "estate": stamp.label,
        "estate_banner": stamp.banner_oneline(),
        "product": "grc-collector-pack",
        "sink": "probo",
        "posted": False,
        "http": False,
        "documentation_only": True,
        "sample": True,
        "client": False,
        "paying_day": "FAIL",
        "organization_id": None,
        "createRisk": create_risk,
        "addRisk": add_risks,
        "addFinding": add_findings,
        "count": len(create_risk),
        "counts": {
            "createRisk": len(create_risk),
            "addRisk": len(add_risks),
            "addFinding": len(add_findings),
        },
        "import": (
            "Operator pastes addRisk / addFinding arguments into Probo MCP "
            "(`tools/call` name=addRisk|addFinding) or GraphQL after filling "
            "organization_id. This file is not a live create."
        ),
        **estate.honesty(),
    }


def write_probo(out: Path | None = None, estate: PackEstate | None = None) -> Path:
    from exporters.model import out_dir

    dest_root = out_dir(out)
    dest_dir = dest_root / "import_preview"
    dest_dir.mkdir(parents=True, exist_ok=True)
    payload = build_probo_preview(out, estate=estate)
    dest = dest_dir / "probo.json"
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    stamp = (estate or load_pack_estate(out)).estate_stamp()
    (dest_root / "probo" / "README.md").parent.mkdir(parents=True, exist_ok=True)
    (dest_root / "probo" / "README.md").write_text(
        stamp.banner_md()
        + "\n\n# Probo import preview (documentation only)\n\n"
        f"{stamp.banner_oneline()}\n\n"
        "Canonical file: `out/import_preview/probo.json`.\n\n"
        "- `addFinding` — one draft per CISO finding/vulnerability.\n"
        "- `addRisk` — CISO risk_scenarios plus high/critical findings.\n"
        "- `createRisk` — backward-compatible high/critical subset.\n\n"
        "`organization_id` and `owner_id` are null. Fill them on the Probo "
        "instance. posted=false. No GraphQL/MCP from this pack.\n",
        encoding="utf-8",
    )
    return dest
