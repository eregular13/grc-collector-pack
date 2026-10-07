"""CISO wizard name ≤200 — G3 (job54). Collects on D-code; fails until G3 map."""
from __future__ import annotations

import csv
from pathlib import Path

from shared import ciso_wizard_map as cwm
from shared.ciso_wizard_map import VULN_NAME_MAX, map_ciso_csvs, unique_display_name


def _wizard_max() -> int:
    return int(getattr(cwm, "WIZARD_NAME_MAX", getattr(cwm, "DEFAULT_NAME_MAX", 255)))


def test_wizard_name_max_constant_is_200() -> None:
    assert hasattr(cwm, "WIZARD_NAME_MAX"), "G3 must define WIZARD_NAME_MAX"
    assert cwm.WIZARD_NAME_MAX == 200
    assert VULN_NAME_MAX == 200
    assert cwm.DEFAULT_NAME_MAX == 200


def test_deterministic_unique_suffix_same_input_same_name() -> None:
    title = "Deterministic Title " + ("Q" * 220)
    rid = "F-DET-42"
    a = unique_display_name(title, rid, max_len=200)
    b = unique_display_name(title, rid, max_len=200)
    assert a == b
    assert len(a) <= 200
    assert a.endswith(f" [{rid}]")


def test_collisions_share_prefix_get_distinct_names() -> None:
    prefix = "Shared prefix collision " + ("Z" * 240)
    a = unique_display_name(prefix, "REF-aaa-001", max_len=200)
    b = unique_display_name(prefix, "REF-bbb-002", max_len=200)
    assert a != b
    assert len(a) <= 200 and len(b) <= 200
    assert a.endswith("[REF-aaa-001]")
    assert b.endswith("[REF-bbb-002]")


def _seed_src(src: Path, *, long: str) -> None:
    src.mkdir(parents=True, exist_ok=True)
    (src / "assets.csv").write_text(
        "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets\n"
        f"A-1,{long},asset-desc,Global,PR,,,,\n",
        encoding="utf-8",
    )
    (src / "applied_controls.csv").write_text(
        "ref_id,name,description,domain,status,category,priority,csf_function\n"
        f"CTL-LONG-1,{long},ctl-desc,Global,to_do,technical,1,protect\n",
        encoding="utf-8",
    )
    (src / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n"
        f"F-1,{long},short-f,high,identified,demo\n"
        f"F-2,{long},other-f,high,identified,demo\n",
        encoding="utf-8",
    )
    (src / "vulnerabilities.csv").write_text(
        "ref_id,name,description,status,severity,assets,applied_controls\n"
        f"V-LONG-1,{long},v-desc,Exploitable,High,A-1,CTL-LONG-1\n",
        encoding="utf-8",
    )
    (src / "evidences.csv").write_text(
        "name,description\n"
        f"{long},e-desc\n",
        encoding="utf-8",
    )


def test_each_wizard_model_name_cap(tmp_path: Path) -> None:
    """findings, assets, evidences, applied_controls, vulns all ≤200 after map."""
    assert _wizard_max() == 200
    long = "Title " + ("X" * 300)
    src = tmp_path / "src"
    _seed_src(src, long=long)
    dest = tmp_path / "dest"
    stats = map_ciso_csvs(src, dest, domain="lab-folder-demo")
    assert stats.get("ok") is True
    for key in ("findings", "assets", "applied_controls", "vulnerabilities", "evidences"):
        mx = (stats.get("max_name_len") or {}).get(key)
        assert mx is not None and mx <= 200, f"{key} max_name_len={mx}"
    for fname in (
        "findings.csv",
        "assets.csv",
        "applied_controls.csv",
        "vulnerabilities.csv",
        "evidences.csv",
    ):
        rows = list(csv.DictReader((dest / fname).open()))
        assert rows, fname
        for r in rows:
            assert len(r.get("name") or "") <= 200, (fname, r.get("name"))


def test_full_title_kept_in_description_and_ref_id_unchanged(tmp_path: Path) -> None:
    long = "Nikto finding preserved " + ("Y" * 280)
    src = tmp_path / "src"
    _seed_src(src, long=long)
    dest = tmp_path / "dest"
    stats = map_ciso_csvs(src, dest, domain="lab-folder-demo")
    assert stats.get("ok") is True
    findings = list(csv.DictReader((dest / "findings.csv").open()))
    assert len(findings) == 2
    assert findings[0]["name"] != findings[1]["name"]
    assert findings[0]["ref_id"] == "F-1"
    assert findings[1]["ref_id"] == "F-2"
    assert "Nikto finding preserved" in findings[0]["description"]
    assert ("Y" * 40) in findings[0]["description"]
    ctls = list(csv.DictReader((dest / "applied_controls.csv").open()))
    assert ctls[0]["ref_id"] == "CTL-LONG-1"
    assert "Nikto finding preserved" in (ctls[0].get("description") or "")
    vulns = list(csv.DictReader((dest / "vulnerabilities.csv").open()))
    assert vulns[0]["ref_id"] == "V-LONG-1"
