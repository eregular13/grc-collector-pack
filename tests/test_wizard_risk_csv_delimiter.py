"""prior-unit Item A: wizard risk_scenarios emit comma (prepare path only)."""
from __future__ import annotations

import csv
import tempfile
from pathlib import Path


def _write_semi_src(path: Path) -> None:
    # pack SoR shape still semicolon with threats header possible
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
            "additional_controls": "CTL-TLS-1.2",
            "residual_impact": "Low",
            "residual_proba": "Low",
            "residual_risk": "Low",
            "treatment": "mitigate",
        }
    ]
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, delimiter=";", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def test_wizard_risk_csv_is_comma_readable_by_default_dictreader():
    """Default csv.DictReader (comma) must see header field 'name' on wizard output."""
    from shared.ciso_wizard_map import map_risk_scenarios_for_wizard

    td = Path(tempfile.mkdtemp())
    src = td / "in.csv"
    dest = td / "out.csv"
    _write_semi_src(src)
    controls = [{"ref_id": "CTL-TLS-1.2", "name": "TLS 1.2 min [CTL-TLS-1.2]"}]
    stats = map_risk_scenarios_for_wizard(src, dest, controls=controls)
    text = dest.read_text(encoding="utf-8")
    # Default DictReader = comma delimiter
    rows = list(csv.DictReader(text.splitlines()))
    assert rows, "wizard output empty"
    assert "name" in rows[0], f"default comma DictReader missing 'name'; keys={list(rows[0].keys())}"
    assert rows[0]["name"] == "Open admin"
    assert stats.get("delimiter") == ","
    # header line must use commas not only one semicolon field
    header = text.splitlines()[0]
    assert "," in header and header.count(";") == 0
