"""Fail-before/pass-after: risk_scenarios wizard shape via map_ciso_csvs."""
from __future__ import annotations

import csv
from pathlib import Path

from shared.ciso_wizard_map import map_ciso_csvs


def _write_pack_ciso(tmp: Path) -> Path:
    ciso = tmp / "ciso-assistant"
    ciso.mkdir(parents=True)
    (ciso / "assets.csv").write_text(
        "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets\n"
        "AST-1,10.0.0.10,desc,Global,Server,,,,\n",
        encoding="utf-8",
    )
    (ciso / "applied_controls.csv").write_text(
        "ref_id,name,description,domain,status,category,priority,csf_function\n"
        "CTL-ssh-lock,Lock down SSH,desc,Global,to_do,Technical,P1,protect\n"
        "CTL-web-fix,Fix web issue,desc,Global,to_do,Technical,P1,protect\n",
        encoding="utf-8",
    )
    (ciso / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n"
        "F-1,Open SSH,desc,high,open,\n",
        encoding="utf-8",
    )
    (ciso / "vulnerabilities.csv").write_text(
        "ref_id,name,description,status,severity,assets,applied_controls\n",
        encoding="utf-8",
    )
    (ciso / "risk_scenarios.csv").write_text(
        "ref_id;assets;threats;name;description;existing_controls;"
        "current_impact;current_proba;current_risk;additional_controls;"
        "residual_impact;residual_proba;residual_risk;treatment\n"
        "RS-1;10.0.0.10;network;Open SSH;desc;;High;High;High;CTL-ssh-lock;"
        "Low;Low;Low;mitigate\n"
        "RS-2;10.0.0.10;web;XSS;desc;;Moderate;Moderate;Moderate;CTL-web-fix;"
        "Low;Low;Low;mitigate\n",
        encoding="utf-8",
    )
    return ciso


def test_map_ciso_csvs_risk_scenarios_wizard_headers(tmp_path: Path) -> None:
    """Tip entrypoint map_ciso_csvs must rewrite risk_scenarios to wizard headers.

    Fail-before risk-scenarios unit: threats/existing_controls headers remain.
    Pass-after: threat / existing_applied_controls + CTL→control name mapping.
    Full stack may use comma or semicolon delimiter (wizard-csv later).
    """
    ciso = _write_pack_ciso(tmp_path)
    dest = tmp_path / "mapped"
    stats = map_ciso_csvs(ciso, dest, domain="Global")
    assert "risk_scenarios" in stats.get("paths", {})
    text = (dest / "risk_scenarios.csv").read_text(encoding="utf-8")
    header = text.splitlines()[0]
    delim = ";" if header.count(";") >= header.count(",") else ","
    cols = header.split(delim)
    assert "threat" in cols, header
    assert "existing_applied_controls" in cols, header
    assert "threats" not in cols, header
    assert "existing_controls" not in cols, header
    rows = list(csv.DictReader(text.splitlines(), delimiter=delim))
    assert len(rows) == 2
    assert rows[0]["additional_controls"] == "Lock down SSH", rows[0]["additional_controls"]
    assert rows[1]["additional_controls"] == "Fix web issue", rows[1]["additional_controls"]
    for row in rows:
        ac = (row.get("additional_controls") or "").strip()
        assert ac and not ac.startswith("CTL-"), ac
        assert "CTL-" not in ac
