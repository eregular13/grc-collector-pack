from __future__ import annotations

import json
from pathlib import Path

from shared.control_map import map_finding, poam_rows

ROOT = Path(__file__).resolve().parents[1]


def test_smbv1_golden_maps() -> None:
    golden = json.loads((ROOT / "dropbox" / "fixtures" / "smbv1.json").read_text(encoding="utf-8"))
    mapped = map_finding(golden)
    assert "CPG_2_W" in mapped["controls"]
    assert "UNMAPPED" not in mapped["controls"]
    rows = poam_rows([golden])
    assert rows[0]["status"] == "open"
    assert rows[0]["owner"] == ""
    assert rows[0]["milestone"] == ""
    assert "SMBv1" in rows[0]["recommended_action"] or "445" in rows[0]["recommended_action"]


def test_unknown_is_unmapped() -> None:
    mapped = map_finding({"name": "obscure widget misconfig", "description": "n/a"})
    assert mapped["controls"] == ["UNMAPPED"]
