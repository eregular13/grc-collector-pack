"""Behavior FBPA: wizard risk_scenarios emit comma (prepare path only).

Tip entrypoint after pr-d-code: shared.ciso_wizard_map.map_ciso_csvs.
Pack SoR seed stays semicolon; wizard out must be default-DictReader comma
with header field 'name'. Synthetic only.
"""
from __future__ import annotations

import csv
from pathlib import Path

from shared.ciso_wizard_map import map_ciso_csvs


def _seed(src: Path) -> None:
    src.mkdir(parents=True, exist_ok=True)
    (src / "assets.csv").write_text(
        "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets\n"
        "A1,web,ad,Global,PR,,,,\n",
        encoding="utf-8",
    )
    (src / "applied_controls.csv").write_text(
        "ref_id,name,description,domain,status,category,priority,csf_function\n"
        "C1,TLS 1.2,cd,Global,to_do,technical,1,protect\n",
        encoding="utf-8",
    )
    (src / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n"
        "F1,Open admin,short-desc,high,identified,demo\n",
        encoding="utf-8",
    )
    (src / "vulnerabilities.csv").write_text(
        "ref_id,name,description,status,severity,applied_controls,findings,assets,"
        "reference_link,folder,filtering_labels,ema_id\n"
        "V1,vname,vd,open,high,C1,F1,A1,,,,\n",
        encoding="utf-8",
    )
    (src / "evidences.csv").write_text(
        "ref_id,name,description,attachment,folder,status,filtering_labels\n"
        "E1,ev,ed,,,created,\n",
        encoding="utf-8",
    )
    # pack SoR shape: semicolon risk_scenarios
    rows = [
        {
            "ref_id": "RS-1",
            "assets": "web",
            "threats": "T1",
            "name": "Open admin",
            "description": "demo",
            "existing_controls": "",
            "current_impact": "Moderate",
            "current_proba": "Low",
            "current_risk": "Moderate",
            "additional_controls": "TLS 1.2",
            "residual_impact": "Low",
            "residual_proba": "Low",
            "residual_risk": "Low",
            "treatment": "mitigate",
        }
    ]
    fields = list(rows[0].keys())
    with (src / "risk_scenarios.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, delimiter=";", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def test_wizard_risk_csv_is_comma_readable_by_default_dictreader(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    _seed(src)
    map_ciso_csvs(src, dst, domain="Global")
    rs = dst / "risk_scenarios.csv"
    assert rs.is_file(), "expected mapped risk_scenarios.csv"
    text = rs.read_text(encoding="utf-8")
    # Default DictReader = comma delimiter
    rows = list(csv.DictReader(text.splitlines()))
    assert rows, f"expected rows via comma DictReader; head={text[:120]!r}"
    assert "name" in rows[0], (
        f"comma DictReader must see field 'name'; keys={list(rows[0].keys())!r} head={text[:120]!r}"
    )
    assert rows[0].get("name") == "Open admin"
