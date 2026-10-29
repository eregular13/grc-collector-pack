"""Behavior FBPA: pr-g3 wizard name <=200 + full title preserved in description.

Tip entrypoint: shared.ciso_wizard_map.map_ciso_csvs — synthetic CSVs only.
Fail-before = finding name longer than 200 (DEFAULT 255 path); not symbol checks.
"""
from __future__ import annotations

import csv
from pathlib import Path

from shared.ciso_wizard_map import map_ciso_csvs


def _seed(src: Path, long_title: str) -> None:
    src.mkdir(parents=True, exist_ok=True)
    (src / "assets.csv").write_text(
        "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets\n"
        "A1,asset1,ad,Global,PR,,,,\n",
        encoding="utf-8",
    )
    (src / "applied_controls.csv").write_text(
        "ref_id,name,description,domain,status,category,priority,csf_function\n"
        "C1,ctl,cd,Global,to_do,technical,1,protect\n",
        encoding="utf-8",
    )
    (src / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n"
        f"F1,{long_title},short-desc,high,identified,demo\n",
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


def test_map_findings_name_capped_at_200_and_title_in_description(tmp_path: Path) -> None:
    long_title = "TITLE-" + ("Z" * 230)
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    _seed(src, long_title)
    map_ciso_csvs(src, dst, domain="Global")
    rows = list(csv.DictReader((dst / "findings.csv").open(encoding="utf-8-sig")))
    assert rows, "expected mapped findings"
    name = rows[0].get("name") or ""
    desc = rows[0].get("description") or ""
    assert len(name) <= 200, f"wizard name must be <=200, got len={len(name)} name={name[:60]!r}"
    assert long_title[:40] in desc, (
        f"full title must be preserved in description when truncated; desc={desc[:80]!r}"
    )
