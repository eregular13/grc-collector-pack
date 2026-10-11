"""Fail-before/pass-after residual: finding wizard names <=200 (pr-g3).

Tip entrypoint: shared.ciso_wizard_map.map_ciso_csvs — synthetic CSVs only.
Pre-g3 DEFAULT_NAME_MAX=255 keeps long finding titles >200; g3 caps at 200.
Real AssertionError before — not ImportError/symbol theater.
NEW test file (not prior-wave fixture copy). Inventory: tip-AE code left after
252–270 was i4+m-code+thin; a-pq6 has no fail-before on this host; g3 residual
fills the third slot with a real tip AE.
"""
from __future__ import annotations

import csv
from pathlib import Path

from shared.ciso_wizard_map import map_ciso_csvs


def test_finding_name_capped_at_200_g3_residual(tmp_path: Path) -> None:
    long_title = "FIND-" + ("Z" * 230)
    assert len(long_title) > 200
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir(parents=True)
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
        f"F1,{long_title},fd,high,identified,demo\n",
        encoding="utf-8",
    )
    (src / "vulnerabilities.csv").write_text(
        "ref_id,name,description,status,severity,applied_controls,findings,assets,"
        "reference_link,folder,filtering_labels,ema_id\n"
        "V1,shortv,vd,open,high,C1,F1,asset1,,,,\n",
        encoding="utf-8",
    )
    (src / "evidences.csv").write_text(
        "ref_id,name,description,attachment,folder,status,filtering_labels\n"
        "E1,ev,ed,,,created,\n",
        encoding="utf-8",
    )
    map_ciso_csvs(src, dst, domain="Global")
    rows = list(csv.DictReader((dst / "findings.csv").open(encoding="utf-8-sig")))
    assert rows, "expected mapped findings"
    name = rows[0].get("name") or ""
    assert len(name) <= 200, (
        f"finding name must be <=200 after g3, got len={len(name)} name={name[:70]!r}"
    )
