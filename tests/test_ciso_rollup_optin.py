"""Fail-before/pass-after: opt-in CISO export rollup by POA&M parent (E).

Default off is byte-identical. On: members of a multi-member POA&M parent fold
into one RSK-/CTL-/VULN-rollup-<poam_id> row; singletons and nmap rows pass
through; the member->parent map lands in rollup-map.json. Synthetic only.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from shared.ciso_wizard_map import map_ciso_csvs

IMG = "example/app:1.0 (debian 12)"
KEYS = ["cve-2024-0001-example-app", "cve-2024-0002-example-app", "cve-2024-0003-example-app"]
PARENT = "EGP-00000000P1"


def _w(path: Path, fields: list[str], rows: list[dict], delimiter: str = ",") -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, delimiter=delimiter, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def _tree(tmp: Path) -> tuple[Path, Path]:
    src = tmp / "ciso"
    poam = tmp / "poam"
    src.mkdir()
    poam.mkdir()
    _w(src / "assets.csv", ["ref_id", "name", "domain"], [{"ref_id": "AST-1", "name": IMG, "domain": "Global"}])
    _w(src / "findings.csv", ["ref_id", "name"], [])
    sev = ["High", "Critical", "Low"]
    _w(src / "vulnerabilities.csv", ["ref_id", "name", "description", "status", "severity", "assets", "applied_controls"],
       [{"ref_id": f"VULN-{k}", "name": f"v{i}", "description": "d", "status": "Exploitable",
         "severity": sev[i], "assets": IMG, "applied_controls": f"CTL-vuln-{k}"} for i, k in enumerate(KEYS)])
    _w(src / "applied_controls.csv", ["ref_id", "name", "description", "domain", "status", "category", "priority"],
       [{"ref_id": f"CTL-vuln-{k}", "name": f"Fix {k}", "description": "d", "domain": "Global",
         "status": "to_do", "category": "technical", "priority": str(3 - i)} for i, k in enumerate(KEYS)]
       + [{"ref_id": "CTL-nmap-x", "name": "Reduce exposure", "description": "d", "domain": "Global",
           "status": "to_do", "category": "technical", "priority": "2"}])
    lv = ["Moderate", "Very High", "Low"]
    rf = ["ref_id", "assets", "threats", "name", "description", "existing_controls", "current_impact",
          "current_proba", "current_risk", "additional_controls", "residual_impact", "residual_proba",
          "residual_risk", "treatment"]
    _w(src / "risk_scenarios.csv", rf,
       [{"ref_id": f"RSK-vuln-{k}", "assets": IMG, "threats": "vuln", "name": f"r{i}", "description": "d",
         "current_impact": lv[i], "current_proba": lv[i], "current_risk": lv[i],
         "additional_controls": f"CTL-vuln-{k}", "residual_impact": "Low", "residual_proba": "Low",
         "residual_risk": "Low", "treatment": "mitigate"} for i, k in enumerate(KEYS)]
       + [{"ref_id": "RSK-nmap-x", "assets": IMG, "threats": "exposure", "name": "SSH exposed",
           "additional_controls": "CTL-nmap-x", "current_risk": "Moderate", "treatment": "mitigate"}],
       delimiter=";")
    _w(poam / "poam_members.csv", ["poam_id", "finding_ref_id", "egp_id", "asset", "severity", "estate"],
       [{"poam_id": f"EGP-0000000{i}", "finding_ref_id": f"VULN-{k}", "egp_id": f"EGP-0000000{i}",
         "asset": IMG} for i, k in enumerate(KEYS)])
    _w(poam / "poam-id-migration.csv", ["old_id", "new_id", "disposition", "reason"],
       [{"old_id": "EGP-00000000", "new_id": PARENT, "disposition": "rolled_into_pkg_parent"},
        {"old_id": "EGP-00000001", "new_id": PARENT, "disposition": "rolled_into_pkg_parent"},
        {"old_id": "EGP-00000002", "new_id": "EGP-00000002", "disposition": "kept_same_id"}])
    _w(poam / "poam.csv", ["poam_id", "weakness", "asset", "severity"],
       [{"poam_id": PARENT, "weakness": "example-lib: package rollup (2 CVEs/findings)", "asset": IMG},
        {"poam_id": "EGP-00000002", "weakness": "CVE-2024-0003 in other", "asset": IMG}])
    return src, poam


def _rows(path: Path) -> list[dict[str, str]]:
    return list(csv.DictReader(path.open(encoding="utf-8")))


def test_rollup_off_is_byte_identical(tmp_path: Path) -> None:
    src, _ = _tree(tmp_path)
    a, b = tmp_path / "a", tmp_path / "b"
    map_ciso_csvs(src, a, domain="Global")
    map_ciso_csvs(src, b, domain="Global", rollup_poam_dir=None)
    for f in sorted(p.name for p in a.iterdir()):
        assert (a / f).read_bytes() == (b / f).read_bytes(), f
    assert not (a / "rollup-map.json").exists()


def test_rollup_on_one_row_per_poam_parent(tmp_path: Path) -> None:
    src, poam = _tree(tmp_path)
    dest = tmp_path / "on"
    stats = map_ciso_csvs(src, dest, domain="Global", rollup_poam_dir=poam)
    vulns = _rows(dest / "vulnerabilities.csv")
    refs = sorted(v["ref_id"] for v in vulns)
    assert refs == sorted([f"VULN-rollup-{PARENT}", f"VULN-{KEYS[2]}"]), refs
    rolled = next(v for v in vulns if v["ref_id"] == f"VULN-rollup-{PARENT}")
    assert rolled["severity"] == "Critical"
    ctl = {c["ref_id"] for c in _rows(dest / "applied_controls.csv")}
    assert ctl == {f"CTL-rollup-{PARENT}", f"CTL-vuln-{KEYS[2]}", "CTL-nmap-x"}
    risks = _rows(dest / "risk_scenarios.csv")
    assert len(risks) == 3
    rr = next(r for r in risks if r["ref_id"] == f"RSK-rollup-{PARENT}")
    assert rr["current_risk"] == "Very High"
    meta = json.loads((dest / "rollup-map.json").read_text(encoding="utf-8"))
    assert meta["map"] == {PARENT: [f"VULN-{KEYS[0]}", f"VULN-{KEYS[1]}"]}
    assert stats["rollup"]["groups"] == 1
    assert stats["ok"]
