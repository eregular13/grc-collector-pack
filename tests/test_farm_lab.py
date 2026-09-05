"""DEMO farm-lab: plan → fixture discover → ingest → Layer C. Not pack in/."""

from __future__ import annotations

from pathlib import Path

from scripts.farm_lab import farm_lab

ROOT = Path(__file__).resolve().parents[1]


def test_farm_lab_demo_path_does_not_use_pack_in(monkeypatch) -> None:
    # farm_lab sets its own IN_DIR/OUT_DIR under farm/work
    stamp = farm_lab(ROOT)
    assert stamp["status"] == "pass"
    assert stamp["demo"] is True
    assert stamp["pack_in_used"] is False
    assert stamp["counts"]["demo"] is True
    assert stamp["counts"]["assets"] >= 20
    assert stamp["counts"]["findings"] >= 20
    assert stamp["counts"]["evidences"] >= 8
    assert stamp["counts"]["poam"] >= 8
    assert "farm/work" in stamp["in_dir"]
    pack_files = [p for p in (ROOT / "in").rglob("*") if p.is_file() and p.name != ".gitkeep"]
    assert pack_files == []
    assert Path(stamp["poam"]).is_file()
    assert "DEMO" in Path(stamp["in_dir"]).joinpath("nmap", "FARM-DEMO.txt").read_text(encoding="utf-8")
