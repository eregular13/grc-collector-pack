"""#157 regression: Nessus 'Multiple Vulnerabilities' plugins are not XSS.

Master typed Apache 2.2 < 2.2.23, Samba 3.x < 3.3.16, Safari < 10.0.2, and
Firefox < 50.1 as web_xss because the description listed XSS among other
issues and Nessus plugin IDs are digits (the Nikto heuristic). Same-type
dedupe then merged three rows (POA&M 221 → 218), dropped Samba
CVE-2011-2522 / CVE-2011-2694, and stamped the XSS playbook.
"""

from __future__ import annotations

import csv
import importlib
import json
from pathlib import Path

from collectors import vuln_scan
from shared.control_map import map_finding
from shared.finding_types import dedupe_weaknesses, finding_type, has_xss_signal
from shared.kev import collect_cves
from shared.poam_ledger import fp_v1, weakness_key

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "nessus" / "multi-vuln-xss-regression.nessus"

PLUGINS = {
    "62284": "Apache 2.2 < 2.2.23 Multiple Vulnerabilities",
    "55732": "Samba 3.x < 3.3.16 Multiple Vulnerabilities",
    "96672": "Safari < 10.0.2 Multiple Vulnerabilities",
    "95813": "Firefox < 50.1 Multiple Vulnerabilities",
}
SAMBA_CVES = ("CVE-2011-2522", "CVE-2011-2694")
XSS_PLAYBOOK = "cross-site scripting"


def _findings() -> list[dict]:
    recs = vuln_scan.parse_file(FIXTURE)
    return [r for r in recs if r["kind"] == "finding"]


def test_four_multi_vuln_plugins_stay_four_rows() -> None:
    findings = _findings()
    assert len(findings) == 4
    by_id = {str((r.get("extra") or {}).get("id")): r for r in findings}
    assert set(by_id) == set(PLUGINS)
    for plugin, title in PLUGINS.items():
        rec = by_id[plugin]
        assert rec["name"] == title
        assert "cross-site scripting" in rec["description"].lower()
        assert finding_type(rec) != "web_xss"
        assert has_xss_signal(rec) is False
        extra = rec.get("extra") or {}
        assert extra.get("tool") == "nessus"
        assert extra.get("plugin_family")
    merged = [r for r in dedupe_weaknesses(findings) if r.get("kind") == "finding"]
    assert len(merged) == 4


def test_samba_cves_kept_and_no_xss_playbook() -> None:
    findings = _findings()
    samba = next(r for r in findings if (r.get("extra") or {}).get("id") == "55732")
    safari = next(r for r in findings if (r.get("extra") or {}).get("id") == "96672")
    cves = collect_cves(samba)
    assert "CVE-2011-2522" in cves
    assert "CVE-2011-2694" in cves
    for rec in (samba, safari, *findings):
        mapped = map_finding(rec)
        control = str(mapped.get("control_name") or "").lower()
        fix = str(mapped.get("recommended_fix") or "").lower()
        assert XSS_PLAYBOOK not in control
        assert "reflected web-app" not in control
        assert XSS_PLAYBOOK not in fix
        assert mapped.get("finding_type") != "web_xss"


def test_egp_ids_stay_distinct_per_plugin() -> None:
    findings = _findings()
    keys = [weakness_key(r) for r in findings]
    fps = [fp_v1(r) for r in findings]
    assert len(set(keys)) == 4
    assert len(set(fps)) == 4
    assert {k.split(":", 1)[-1] for k in keys} == set(PLUGINS)


def test_name_family_or_cwe_still_types_xss() -> None:
    rec = {
        "kind": "finding",
        "source": "vuln-scan",
        "name": "Apache mod_proxy XSS",
        "description": "unrelated",
        "labels": ["vuln", "nessus"],
        "assets": ["10.0.0.40"],
        "extra": {"id": "999001", "tool": "nessus", "plugin_family": "Web Servers"},
    }
    assert has_xss_signal(rec) is True
    assert finding_type(rec) == "web_xss"
    family_only = dict(rec)
    family_only["name"] = "Apache 2.2 < 2.2.23 Multiple Vulnerabilities"
    family_only["extra"] = {
        "id": "62284",
        "tool": "nessus",
        "plugin_family": "Web Application Cross-Site Scripting",
    }
    assert has_xss_signal(family_only) is True
    cwe_only = dict(rec)
    cwe_only["name"] = "Apache 2.2 < 2.2.23 Multiple Vulnerabilities"
    cwe_only["extra"] = {"id": "62284", "tool": "nessus", "plugin_family": "Web Servers", "cwe": "CWE-79"}
    assert has_xss_signal(cwe_only) is True
    desc_only = dict(rec)
    desc_only["name"] = "Apache 2.2 < 2.2.23 Multiple Vulnerabilities"
    desc_only["description"] = "includes a cross-site scripting issue and xss among others"
    desc_only["extra"] = {"id": "62284", "tool": "nessus", "plugin_family": "Web Servers"}
    assert has_xss_signal(desc_only) is False
    assert finding_type(desc_only) != "web_xss"


def test_four_plugins_poam_row_count(tmp_path: Path, monkeypatch) -> None:
    findings = _findings()
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    with (out / "canonical" / "nessus.jsonl").open("w", encoding="utf-8") as fh:
        for rec in findings:
            fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    dest_in = tmp_path / "in"
    dest_in.mkdir(parents=True)
    monkeypatch.setenv("IN_DIR", str(dest_in))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    poam = out / "poam" / "poam.csv"
    assert poam.is_file()
    with poam.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 4
    blob = " ".join(json.dumps(r).lower() for r in rows)
    assert "cve-2011-2522" in blob
    assert "cve-2011-2694" in blob
    assert "reflected web-app" not in blob
    assert "stop reflected web-app cross-site scripting" not in blob
