"""Unit tests for CISO wizard mapping (PQ-4/5/7/8 + PQ-9). File-only."""

from __future__ import annotations

import csv
from pathlib import Path

from shared.ciso_wizard_map import (
    VULN_NAME_MAX,
    map_ciso_csvs,
    plan_vuln_chunks,
    strip_ref_suffix,
    unique_display_name,
    write_vuln_chunks,
)


def test_unique_display_name_short() -> None:
    assert unique_display_name("SSH exposed", "CTL-1") == "SSH exposed [CTL-1]"


def test_unique_display_name_strips_prior_suffix() -> None:
    assert unique_display_name("SSH exposed [OLD]", "CTL-1") == "SSH exposed [CTL-1]"


def test_unique_display_name_truncates_title_keeps_ref_tail() -> None:
    title = "A" * 250
    rid = "VULN-" + ("x" * 40)
    out = unique_display_name(title, rid, max_len=VULN_NAME_MAX)
    assert len(out) == VULN_NAME_MAX
    assert out.endswith(f" [{rid}]")
    assert out.startswith("A")


def test_unique_display_name_overlong_ref_uses_hash() -> None:
    rid = "VULN-" + ("y" * 300)
    out = unique_display_name("title", rid, max_len=VULN_NAME_MAX)
    assert len(out) <= VULN_NAME_MAX
    assert "[" not in out  # hash form, not suffix form


def test_plan_vuln_chunks_5148_default_500() -> None:
    ranges = plan_vuln_chunks(5148, chunk_size=500)
    assert ranges[0] == (0, 500)
    assert ranges[-1] == (5000, 5148)
    assert sum(b - a for a, b in ranges) == 5148
    assert len(ranges) == 11  # 10*500 + 148


def test_write_vuln_chunks(tmp_path: Path) -> None:
    src = tmp_path / "vulnerabilities.csv"
    with src.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["ref_id", "name"], lineterminator="\n")
        w.writeheader()
        for i in range(7):
            w.writerow({"ref_id": f"V-{i}", "name": f"n{i}"})
    plan = write_vuln_chunks(src, tmp_path / "chunks", chunk_size=3)
    assert plan["n_chunks"] == 3
    assert plan["ranges"][-1]["n"] == 1
    last = list(csv.DictReader((tmp_path / "chunks" / "vulnerabilities_chunk03.csv").open()))
    assert last == [{"ref_id": "V-6", "name": "n6"}]


def test_map_ciso_csvs_unique_domain_and_vuln_cap(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "assets.csv").write_text(
        "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets\n"
        "A-1,host-a,d,Global,PR,,,,\n",
        encoding="utf-8",
    )
    (src / "applied_controls.csv").write_text(
        "ref_id,name,description,domain,status,category,priority,csf_function\n"
        "CTL-1,Reduce exposure,fix,Global,to_do,technical,1,protect\n"
        "CTL-1,dup ignored,fix,Global,to_do,technical,1,protect\n",
        encoding="utf-8",
    )
    (src / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n"
        "F-1,SSH exposed,open 22,high,identified,demo\n",
        encoding="utf-8",
    )
    long_title = "T" * 220
    (src / "vulnerabilities.csv").write_text(
        "ref_id,name,description,status,severity,assets,applied_controls\n"
        f"V-1,{long_title},desc,Exploitable,High,host-a,CTL-1\n"
        "V-drop,nope,desc,Exploitable,Low,missing-asset,CTL-1\n",
        encoding="utf-8",
    )
    (src / "evidences.csv").write_text("name,description\ne1,d\n", encoding="utf-8")
    dest = tmp_path / "dest"
    stats = map_ciso_csvs(src, dest, domain="lab-folder-demo")
    assert stats["ok"] is True
    assert stats["counts"]["vulnerabilities"] == 1
    assert stats["pq4"]["dropped_no_asset_row"] == 1
    assert stats["dup_name_counts"]["vulnerabilities"] == 0
    assert stats["max_name_len"]["vulnerabilities"] <= VULN_NAME_MAX

    assets = list(csv.DictReader((dest / "assets.csv").open()))
    assert assets[0]["domain"] == "lab-folder-demo"
    controls = list(csv.DictReader((dest / "applied_controls.csv").open()))
    assert len(controls) == 1
    assert controls[0]["name"] == "Reduce exposure [CTL-1]"
    assert controls[0]["domain"] == "lab-folder-demo"
    findings = list(csv.DictReader((dest / "findings.csv").open()))
    assert findings[0]["name"] == "SSH exposed [F-1]"
    vulns = list(csv.DictReader((dest / "vulnerabilities.csv").open()))
    assert len(vulns[0]["name"]) <= VULN_NAME_MAX
    assert vulns[0]["name"].endswith(" [V-1]")
    assert strip_ref_suffix(vulns[0]["name"]).startswith("T")
