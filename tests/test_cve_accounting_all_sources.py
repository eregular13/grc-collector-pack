"""Fail-before/pass-after: CVE-completeness accounting for every scanner source.

Before, only the Trivy PQ-1 rollup checked CVE conservation. A CVE that a
non-Trivy parser, filter or dedupe dropped vanished silently. Now
scripts/cve_accounting.py (run by lab_drop_to_sor.sh) fails closed.
Synthetic data only (203.0.113.40, host-b.example.test, CVE-2099-*).
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NIKTO_XML = """<?xml version="1.0" ?>
<niktoscan version="2.1.5">
<scandetails targetip="203.0.113.40" targethostname="203.0.113.40" targetport="80" sitename="http://203.0.113.40:80">
<item id="999984" osvdbid="0" method="GET">
<description><![CDATA[Server leaks inodes via ETags, header found with file /, fields: 0x1 0x2. See CVE-2099-3001]]></description>
<uri><![CDATA[/]]></uri>
</item>
<item id="000123" osvdbid="0" method="GET">
<description><![CDATA[/cgi-bin/example.cgi: example app 1.0 remote issue.]]></description>
<uri><![CDATA[/cgi-bin/example.cgi]]></uri>
<references><![CDATA[https://cve.example.test/CVE-2099-3002]]></references>
</item>
</scandetails>
</niktoscan>
"""

GRYPE = {
    "matches": [
        {"vulnerability": {"id": "CVE-2099-4001", "severity": "High"},
         "artifact": {"name": "examplelib", "version": "1.0"}}
    ],
    "source": {"type": "image", "target": {"userInput": "example/app:1.0"}},
}


def _run(work: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHON=sys.executable, SOURCE_DATE_EPOCH="1790007200", PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        ["bash", str(ROOT / "scripts" / "lab_drop_to_sor.sh"), "--work", str(work)],
        cwd=str(ROOT), env=env, capture_output=True, text=True,
    )


def _drop(tmp_path: Path, name: str, body: str) -> Path:
    work = tmp_path / "w"
    (work / "in" / "vuln").mkdir(parents=True)
    (work / "in" / "LAB.txt").write_text("LAB/DEMO -- not a client estate. Synthetic.\n", encoding="utf-8")
    (work / "in" / "vuln" / name).write_text(body, encoding="utf-8")
    return work


def _accounted(work: Path, cve: str) -> bool:
    poam = (work / "out" / "poam" / "poam.csv").read_text(encoding="utf-8")
    if cve in poam:
        return True
    with (work / "out" / "poam" / "excluded.csv").open(encoding="utf-8", newline="") as fh:
        return any(cve in (r.get("cves") or "") and r.get("excluded_reason") for r in csv.DictReader(fh))


def test_nikto_cve_rows_are_kept_and_accounted(tmp_path: Path) -> None:
    work = _drop(tmp_path, "nikto_80.xml", NIKTO_XML)
    proc = _run(work)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]
    for cve in ("CVE-2099-3001", "CVE-2099-3002"):
        assert _accounted(work, cve), cve
    rep = json.loads((work / "out" / "poam" / "cve_accounting.json").read_text(encoding="utf-8"))
    assert rep["ok"] and rep["input_cves"] == 2, rep


def test_unparsed_scanner_cves_fail_closed(tmp_path: Path) -> None:
    """A grype report has no collector: its CVEs must not vanish silently."""
    work = _drop(tmp_path, "nikto_80.xml", NIKTO_XML)
    (work / "in" / "vuln" / "grype-example.json").write_text(json.dumps(GRYPE), encoding="utf-8")
    proc = _run(work)
    assert proc.returncode != 0, (proc.stdout + proc.stderr)[-2000:]
    assert "CVE_ACCOUNTING_FAIL" in proc.stdout + proc.stderr
    assert "CVE-2099-4001" in proc.stdout + proc.stderr


def test_excluded_row_without_cve_ids_is_unaccounted(tmp_path: Path) -> None:
    """Export layer: a finding excluded with no CVE ids on the row is a loss."""
    from shared.cve_accounting import account

    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    (out / "poam").mkdir()
    rec = {"kind": "finding", "source": "inventory-nmap", "ref_id": "NMAP-x-80-vulners-rollup",
           "extra": {"cves": ["CVE-2099-5001", "CVE-2099-5002"]}}
    (out / "canonical" / "inventory-nmap.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    (out / "poam" / "poam.csv").write_text("weakness,poam_id,cve\nother,EGP-1,\n", encoding="utf-8")
    hdr = "id,finding_ref_id,excluded_reason,cves\n"
    (out / "poam" / "excluded.csv").write_text(hdr + "NMAP-x-80-vulners-rollup,NMAP-x-80-vulners-rollup,DUPLICATE_INSTANCE,\n", encoding="utf-8")
    rep = account(tmp_path)
    assert not rep["ok"]
    assert rep["canonical_unaccounted"]["inventory-nmap"] == [
        "CVE-2099-5001@NMAP-x-80-vulners-rollup", "CVE-2099-5002@NMAP-x-80-vulners-rollup"]
    (out / "poam" / "excluded.csv").write_text(
        hdr + "NMAP-x-80-vulners-rollup,NMAP-x-80-vulners-rollup,DUPLICATE_INSTANCE,CVE-2099-5001 CVE-2099-5002\n",
        encoding="utf-8")
    assert account(tmp_path)["ok"]


def test_input_extractors_cover_sources(tmp_path: Path) -> None:
    from shared.cve_accounting import input_cves

    root = tmp_path / "in"
    (root / "x").mkdir(parents=True)
    (root / "x" / "grype.json").write_text(json.dumps(GRYPE), encoding="utf-8")
    (root / "x" / "wazuh.jsonl").write_text(
        json.dumps({"data": {"vulnerability": {"cve": "CVE-2099-6001", "status": "Active"}}}) + "\n"
        + json.dumps({"data": {"vulnerability": {"cve": "CVE-2099-6002", "status": "Solved"}}}) + "\n",
        encoding="utf-8")
    (root / "x" / "oscap.xml").write_text(
        '<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult>'
        '<rule-result idref="r1"><result>fail</result><ident system="cve">CVE-2099-7001</ident></rule-result>'
        '<rule-result idref="r2"><result>pass</result><ident system="cve">CVE-2099-7002</ident></rule-result>'
        "</TestResult></Benchmark>", encoding="utf-8")
    (root / "x" / "testssl.json").write_text(json.dumps([
        {"id": "BREACH", "severity": "MEDIUM", "finding": "x", "cve": "CVE-2099-8101"},
        {"id": "HEARTBLEED", "severity": "OK", "finding": "not vulnerable", "cve": "CVE-2099-8102"},
    ]), encoding="utf-8")
    (root / "x" / "trivy.json").write_text(json.dumps({"Results": [{"Target": "example/app:1.0", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2099-9001", "References": ["https://example.test/CVE-2099-9999"]}]}]}), encoding="utf-8")
    got = set(input_cves(root))
    assert got == {"CVE-2099-4001", "CVE-2099-6001", "CVE-2099-7001", "CVE-2099-8101", "CVE-2099-9001"}, got
