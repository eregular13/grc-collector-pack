"""Fail-before/pass-after: grype, OpenSCAP (XCCDF/ARF + OVAL) and Wazuh
vulnerability-detector CVEs reach the risk register / POA&M.

Before: these reports had no vulnerability collector, so a drop that
contained one stopped with CVE_ACCOUNTING_FAIL (grype was not parsed at all,
OpenSCAP rule-results kept no structured CVEs, and Wazuh vulnerability alerts
were folded into one incident per rule id). Synthetic fixtures only
(fixtures/samples/{grype,xccdf,wazuh}/synthetic_*; *.example.test, CVE-2099-*).
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
GRYPE = SAMPLES / "grype" / "synthetic_grype-image.json"
ARF = SAMPLES / "xccdf" / "synthetic_arf-oval-cves.xml"
OVAL = SAMPLES / "xccdf" / "synthetic_oval-results.xml"
WZ_ALERTS = SAMPLES / "wazuh" / "synthetic_vuln-alerts.jsonl"
WZ_STATES = SAMPLES / "wazuh" / "synthetic_vuln-states.json"
WZ_API = SAMPLES / "wazuh" / "synthetic_vuln-api-host-h.json"

EXPECTED = {
    "CVE-2099-41001", "CVE-2099-41002", "CVE-2099-41003",  # grype (41002 via relatedVulnerabilities)
    "CVE-2099-42001", "CVE-2099-42002", "CVE-2099-42003",  # ARF failing rule -> OVAL patch defs
    "CVE-2099-42004",  # ARF OVAL vulnerability def true, no rule-result
    "CVE-2099-42006",  # XCCDF <ident system=cve> on a failing rule
    "CVE-2099-43001",  # standalone OVAL results
    "CVE-2099-44001", "CVE-2099-44003", "CVE-2099-44004",  # wazuh alerts / 4.8 states / API
}
NOT_FINDINGS = {
    "CVE-2099-42005",  # OVAL def false
    "CVE-2099-42007", "CVE-2099-42008",  # passing rule (ident / its OVAL def)
    "CVE-2099-43002",  # OVAL def false
    "CVE-2099-44002",  # wazuh: latest state Solved
    "CVE-2099-44005",  # wazuh API: OBSOLETE
    "CVE-2099-49990", "CVE-2099-49995", "CVE-2099-49996", "CVE-2099-49997",
    "CVE-2099-49998", "CVE-2099-49999",  # prose / reference URLs only
}


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r.get("kind") == "finding"]


def _cves(recs: list[dict]) -> set[str]:
    return {c for r in _findings(recs) for c in (r.get("extra") or {}).get("cves") or []}


def test_grype_matches_become_trivy_shaped_findings() -> None:
    from collectors.vuln_scan import parse_file

    recs = parse_file(GRYPE)
    assets = [r for r in recs if r["kind"] == "asset"]
    assert [a["name"] for a in assets] == ["registry.example.test/app:1.0"]
    found = _findings(recs)
    assert {r["name"] for r in found} == {
        "CVE-2099-41001 in libssl3", "CVE-2099-41001 in openssl",
        "CVE-2099-41002 in examplelib", "CVE-2099-41003 in zlib1g",
    }
    by = {r["name"]: r for r in found}
    assert by["CVE-2099-41001 in libssl3"]["extra"]["fixed_version_hint"] == "3.0.1-1"
    assert by["CVE-2099-41002 in examplelib"]["extra"]["advisory"] == "GHSA-2099-aaaa-bbbb"
    assert by["CVE-2099-41003 in zlib1g"]["extra"].get("no_fix_available") is True
    assert all(r["extra"]["tool"] == "grype" and "grype" in r["labels"] for r in found)
    assert all(r["extra"].get("scan_time") == "2099-01-02T03:04:05Z" for r in found)
    assert _cves(recs) == {"CVE-2099-41001", "CVE-2099-41002", "CVE-2099-41003"}


def test_openscap_xccdf_idents_and_oval_cves() -> None:
    from collectors.host_wazuh import parse_file

    arf = parse_file(ARF)
    by = {(r["extra"] or {}).get("check_id"): r for r in _findings(arf)}
    assert by["security_patches_up_to_date"]["extra"]["cves"] == [
        "CVE-2099-42001", "CVE-2099-42002", "CVE-2099-42003"]
    assert by["example_cve_ident"]["extra"]["cves"] == ["CVE-2099-42006"]
    assert by["oval:org.example.test:def:3"]["extra"]["cves"] == ["CVE-2099-42004"]
    assert "example_passing" not in by
    assert {r["assets"][0] for r in _findings(arf)} == {"host-c.example.test"}
    oval = parse_file(OVAL)
    assert _cves(oval) == {"CVE-2099-43001"}
    assert _findings(oval)[0]["assets"] == ["host-d.example.test"]
    assert _findings(oval)[0]["severity"] == "critical"


def test_wazuh_vulnerability_detector_rows() -> None:
    from collectors.host_wazuh import parse_file

    alerts = parse_file(WZ_ALERTS)
    found = _findings(alerts)
    assert sorted((r["assets"][0], r["extra"]["cve"], r["extra"]["pkg"]) for r in found) == [
        ("host-e.example.test", "CVE-2099-44001", "curl"),
        ("host-f.example.test", "CVE-2099-44001", "curl"),
    ]
    # vulnerability alerts are no longer folded into per-rule incidents
    assert not [r for r in alerts if r["kind"] == "incident"]
    assert _cves(parse_file(WZ_STATES)) == {"CVE-2099-44003"}
    api = parse_file(WZ_API)
    assert _cves(api) == {"CVE-2099-44004"}
    # API vulnerability rows are not minted as Wazuh agents
    assert not any(r["kind"] == "asset" and r["name"] in {"sudo", "vim"} for r in api)


def test_input_extractor_agrees_with_collectors(tmp_path: Path) -> None:
    from shared.cve_accounting import input_cves

    root = tmp_path / "in"
    for sub, files in {"vuln": [GRYPE], "wazuh": [ARF, OVAL, WZ_ALERTS, WZ_STATES, WZ_API]}.items():
        (root / sub).mkdir(parents=True)
        for f in files:
            shutil.copy(f, root / sub / f.name)
    got = set(input_cves(root))
    assert got == EXPECTED, got ^ EXPECTED
    assert not got & NOT_FINDINGS


def test_hardening_dedupe_keeps_merged_away_cves() -> None:
    from shared.hardening_dedup import dedupe_hardening

    keep = {"kind": "finding", "assets": ["h"], "labels": ["lynis"], "extra": {"control_key": "k", "tool": "lynis"}}
    gone = {"kind": "finding", "assets": ["h"], "labels": ["openscap"],
            "extra": {"control_key": "k", "tool": "openscap", "cves": ["CVE-2099-42999"]}}
    out = dedupe_hardening([keep, gone])
    assert len(out) == 1 and out[0]["extra"]["cves"] == ["CVE-2099-42999"]


def _run(work: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHON=sys.executable, SOURCE_DATE_EPOCH="1790007200", PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        ["bash", str(ROOT / "scripts" / "lab_drop_to_sor.sh"), "--work", str(work)],
        cwd=str(ROOT), env=env, capture_output=True, text=True,
    )


def _drop(work: Path) -> Path:
    (work / "in" / "vuln").mkdir(parents=True)
    (work / "in" / "wazuh").mkdir(parents=True)
    (work / "in" / "LAB.txt").write_text("LAB/DEMO -- not a client estate. Synthetic.\n", encoding="utf-8")
    shutil.copy(GRYPE, work / "in" / "vuln" / GRYPE.name)
    for f in (ARF, OVAL, WZ_ALERTS, WZ_STATES, WZ_API):
        shutil.copy(f, work / "in" / "wazuh" / f.name)
    return work


def _poam(work: Path) -> list[dict[str, str]]:
    with (work / "out" / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_drop_with_grype_openscap_wazuh_passes_cve_accounting(tmp_path: Path) -> None:
    work = _drop(tmp_path / "a")
    proc = _run(work)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out[-3000:]
    assert "CVE_ACCOUNTING_FAIL" not in out
    rep = json.loads((work / "out" / "poam" / "cve_accounting.json").read_text(encoding="utf-8"))
    assert rep["ok"] and rep["input_cves"] == len(EXPECTED), rep
    assert not rep["input_not_parsed"] and not rep["canonical_unaccounted"], rep
    rows = _poam(work)
    blob = json.dumps(rows)
    for cve in EXPECTED - {"CVE-2099-42002", "CVE-2099-42003"}:
        assert cve in blob, cve  # 42002/42003 ride on the same OpenSCAP row as 42001
    assert {"CVE-2099-42001", "CVE-2099-42002", "CVE-2099-42003"} <= {
        c for r in rows for c in __import__("re").findall(r"CVE-\d{4}-\d+", json.dumps(r))}
    for cve in NOT_FINDINGS:
        assert cve not in blob, cve
    # stable POA&M ids: a second fresh run of the same drop mints the same ids
    work2 = _drop(tmp_path / "b")
    assert _run(work2).returncode == 0
    ids = lambda rs: sorted((r["poam_id"], r.get("weakness_name") or r.get("weakness") or "") for r in rs)
    assert ids(_poam(work2)) == ids(rows)
