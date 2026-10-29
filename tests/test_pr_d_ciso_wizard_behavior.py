"""prior-unit: ciso wizard map behavior via NEW module (lazy import = real AE fail-before).

shared.ciso_wizard_map does not exist until pr-d-code. Resolve symbols inside the
test so collection succeeds and missing module yields AssertionError, not ImportError.
Synthetic CSV only.
"""
from __future__ import annotations

import importlib
from pathlib import Path


def _map_mod():
    try:
        return importlib.import_module("shared.ciso_wizard_map")
    except Exception:
        return None


def test_unique_display_name_keeps_ref_tail() -> None:
    mod = _map_mod()
    assert mod is not None, "shared.ciso_wizard_map missing (pr-d-code not applied)"
    unique_display_name = getattr(mod, "unique_display_name", None)
    VULN_NAME_MAX = getattr(mod, "VULN_NAME_MAX", None)
    assert unique_display_name is not None and callable(unique_display_name)
    assert isinstance(VULN_NAME_MAX, int) and VULN_NAME_MAX > 0
    title = "A" * 250
    rid = "VULN-" + ("x" * 40)
    out = unique_display_name(title, rid, max_len=VULN_NAME_MAX)
    assert len(out) == VULN_NAME_MAX
    assert out.endswith(f" [{rid}]")


def test_map_ciso_csvs_drops_orphan_vuln(tmp_path: Path) -> None:
    mod = _map_mod()
    assert mod is not None, "shared.ciso_wizard_map missing (pr-d-code not applied)"
    map_ciso_csvs = getattr(mod, "map_ciso_csvs", None)
    assert map_ciso_csvs is not None and callable(map_ciso_csvs)
    src = tmp_path / "src"
    src.mkdir()
    (src / "assets.csv").write_text(
        "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets\n"
        "A-1,host-a,d,Global,PR,,,,\n",
        encoding="utf-8",
    )
    (src / "applied_controls.csv").write_text(
        "ref_id,name,description,domain,status,category,priority,csf_function\n"
        "CTL-1,Reduce exposure,fix,Global,to_do,technical,1,protect\n",
        encoding="utf-8",
    )
    (src / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n"
        "F-1,SSH exposed,open 22,high,identified,demo\n",
        encoding="utf-8",
    )
    (src / "vulnerabilities.csv").write_text(
        "ref_id,name,description,status,severity,assets,applied_controls\n"
        "V-1,Short title,desc,Exploitable,High,host-a,CTL-1\n"
        "V-drop,nope,desc,Exploitable,Low,missing-asset,CTL-1\n",
        encoding="utf-8",
    )
    (src / "evidences.csv").write_text("name,description\ne1,d\n", encoding="utf-8")
    dest = tmp_path / "dest"
    stats = map_ciso_csvs(src, dest, domain="lab-folder-demo")
    assert stats.get("ok") is True
    assert stats.get("counts", {}).get("vulnerabilities") == 1
