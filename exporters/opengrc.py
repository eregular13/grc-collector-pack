"""OpenGRC Data Manager CSV exporter.

Public import is a four-step CSV wizard
(https://docs.opengrc.com/data-manager/import/). Headers match the
Risk / Asset / Implementation fillable fields from LeeMangold/OpenGRC.
Foreign-key IDs (taxonomy, owner) are omitted — the wizard maps columns;
the operator supplies IDs in their own OpenGRC instance.

File-drop only. posted=false. No sockets. SAMPLE/DEMO ≠ client.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from exporters.model import (
    HONESTY_BANNER,
    PackEstate,
    load_pack_estate,
    residual_score,
    score_scenario_level,
    score_severity,
)

# OpenGRC Risk fillable (app/Models/Risk.php) + import-by-code upsert.
RISKS_HEADER = [
    "code",
    "name",
    "description",
    "status",
    "inherent_likelihood",
    "inherent_impact",
    "inherent_risk",
    "residual_likelihood",
    "residual_impact",
    "residual_risk",
    "is_active",
]
# OpenGRC Asset fillable minus FK / financial fields we cannot invent.
ASSETS_HEADER = [
    "asset_tag",
    "name",
    "hostname",
    "ip_address",
    "notes",
    "is_active",
    "alternative_name",
]
# Implementation create fields the wizard can map without FKs.
IMPLEMENTATIONS_HEADER = ["title", "details", "notes"]


def _write_csv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def _risk_row_from_scenario(scenario) -> list[Any]:
    like = score_scenario_level(scenario.current_proba or scenario.current_risk)
    impact = score_scenario_level(scenario.current_impact or scenario.current_risk)
    res_like = score_scenario_level(scenario.residual_proba or scenario.residual_risk) if scenario.residual_proba or scenario.residual_risk else residual_score(like)
    res_impact = score_scenario_level(scenario.residual_impact or scenario.residual_risk) if scenario.residual_impact or scenario.residual_risk else residual_score(impact)
    desc = scenario.description
    extra = []
    if scenario.assets:
        extra.append(f"assets={scenario.assets}")
    if scenario.threats:
        extra.append(f"threats={scenario.threats}")
    if scenario.additional_controls:
        extra.append(f"controls={scenario.additional_controls}")
    extra.append(HONESTY_BANNER)
    if extra:
        desc = (desc + " — " if desc else "") + "; ".join(extra)
    return [
        scenario.ref_id,
        scenario.name,
        desc,
        "Not Assessed",
        like,
        impact,
        like * impact,
        res_like,
        res_impact,
        res_like * res_impact,
        "true",
    ]


def _risk_row_from_finding(finding) -> list[Any]:
    like = impact = score_severity(finding.severity)
    res = residual_score(like)
    desc = finding.description
    extra = [HONESTY_BANNER]
    if finding.assets:
        extra.append("assets=" + ",".join(finding.assets))
    if finding.labels:
        extra.append("labels=" + ",".join(finding.labels[:8]))
    desc = (desc + " — " if desc else "") + "; ".join(extra)
    return [
        finding.ref_id,
        finding.name,
        desc,
        "Not Assessed",
        like,
        impact,
        like * impact,
        res,
        res,
        res * res,
        "true",
    ]


def build_opengrc_rows(estate: PackEstate) -> dict[str, list[list[Any]]]:
    scenario_ids = {s.ref_id.lower() for s in estate.scenarios}
    # Scenario refs are often RSK-<finding-slug>; also skip finding ids already used.
    finding_ids_in_scenarios = set()
    for scenario in estate.scenarios:
        slug = scenario.ref_id.lower()
        if slug.startswith("rsk-"):
            finding_ids_in_scenarios.add(slug[4:])
    risks: list[list[Any]] = [_risk_row_from_scenario(s) for s in estate.scenarios]
    seen = {str(row[0]).lower() for row in risks}
    for finding in estate.all_findings:
        key = finding.ref_id.lower()
        if key in seen or key in scenario_ids or key in finding_ids_in_scenarios:
            continue
        risks.append(_risk_row_from_finding(finding))
        seen.add(key)

    assets: list[list[Any]] = []
    for asset in estate.assets:
        notes = asset.description or asset.name
        notes = f"{notes} — {HONESTY_BANNER}"
        assets.append(
            [
                asset.ref_id,
                asset.name,
                asset.hostname,
                asset.ip_address,
                notes,
                "true",
                asset.reference_link,
            ]
        )

    implementations: list[list[Any]] = []
    for control in estate.controls:
        implementations.append(
            [
                control.name,
                control.description,
                f"{control.ref_id} category={control.category} csf={control.csf_function} — {HONESTY_BANNER}",
            ]
        )
    return {"risks": risks, "assets": assets, "implementations": implementations}


def write_opengrc(out: Path | None = None, estate: PackEstate | None = None) -> dict[str, Any]:
    """Write OpenGRC import CSVs under out/opengrc/. Never POSTs."""
    from exporters.model import out_dir

    estate = estate or load_pack_estate(out)
    dest_root = out_dir(out)
    dest = dest_root / "opengrc"
    rows = build_opengrc_rows(estate)
    _write_csv(dest / "risks.csv", RISKS_HEADER, rows["risks"])
    _write_csv(dest / "assets.csv", ASSETS_HEADER, rows["assets"])
    _write_csv(dest / "implementations.csv", IMPLEMENTATIONS_HEADER, rows["implementations"])
    stamp = {
        "product": "grc-collector-pack",
        "sink": "opengrc",
        "posted": False,
        "http": False,
        "sample": True,
        "client": False,
        "paying_day": "FAIL",
        "counts": {
            "risks": len(rows["risks"]),
            "assets": len(rows["assets"]),
            "implementations": len(rows["implementations"]),
        },
        "files": ["risks.csv", "assets.csv", "implementations.csv", "README.md"],
        "import": (
            "OpenGRC Data Manager → Import Data → select Risks / Assets / "
            "Implementations → map headers (auto-map on field names) → review. "
            "Omit id to create. code / asset_tag upsert if they already exist. "
            "No taxonomy FKs invented. SAMPLE/DEMO ≠ client."
        ),
        **estate.honesty(),
    }
    (dest / "MANIFEST.json").write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    (dest / "README.md").write_text(
        "# OpenGRC import drop (file-only)\n\n"
        f"{HONESTY_BANNER}\n\n"
        "These CSVs match the OpenGRC Data Manager import wizard "
        "(https://docs.opengrc.com/data-manager/import/).\n\n"
        "## Files\n\n"
        "| File | Entity | Required-ish columns |\n"
        "|---|---|---|\n"
        "| `risks.csv` | Risks | `code`, `name`, `description`, `status`, 1–5 likelihood/impact |\n"
        "| `assets.csv` | Assets | `asset_tag`, `name` (hostname/IP when known) |\n"
        "| `implementations.csv` | Implementations | `title`, `details` (from CISO applied_controls) |\n\n"
        "## Operator path\n\n"
        "1. Produce CISO CSVs: `python3 -m dropbox ciso` or `python3 scripts/prove_ciso.py`.\n"
        "2. `python3 -m exporters --sink opengrc` (reads `out/ciso-assistant`).\n"
        "3. In OpenGRC: Data Manager → Import Data → Risks, then Assets, then Implementations.\n"
        "4. Download the in-app CSV template if the wizard rejects a header; map columns.\n"
        "5. Status is **Not Assessed**. Owner / department / taxonomy FKs stay blank.\n\n"
        "posted=false. No REST. RiskReady is stay-out. This is not a paying-day PASS.\n",
        encoding="utf-8",
    )
    stamp["dir"] = str(dest)
    return stamp
