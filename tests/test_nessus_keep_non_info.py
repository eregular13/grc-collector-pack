"""Nessus parser keeps every non-info ReportItem with faithful severity 1-4."""

from __future__ import annotations

from pathlib import Path

from collectors import vuln_scan
from shared.nessus import iter_nessus_items, parse_nessus

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "nessus" / "all-severities.nessus"


def test_nessus_keeps_every_non_info_with_real_severity() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    rows = iter_nessus_items(text)
    by_plugin = {r["plugin_id"]: r for r in rows}
    assert set(by_plugin) == {"70658", "10107", "42411", "156032"}
    assert by_plugin["70658"]["severity"] == "low"
    assert by_plugin["10107"]["severity"] == "medium"
    assert by_plugin["42411"]["severity"] == "high"
    assert by_plugin["156032"]["severity"] == "critical"
    assert all(r["severity"] != "info" for r in rows)
    assert "Scan Information" not in " ".join(r["name"] for r in rows)
    parsed = parse_nessus(FIXTURE)
    assert parsed is not None
    assert len(parsed) == 4


def test_nessus_info_and_risk_none_dropped() -> None:
    text = """<NessusClientData_v2><Report name="t"><ReportHost name="h">
    <ReportItem port="0" severity="0" pluginID="19506" pluginName="Nessus Scan Information">
    <risk_factor>None</risk_factor></ReportItem>
    <ReportItem port="0" severity="0" pluginID="19507" pluginName="Informational note">
    <risk_factor>Info</risk_factor></ReportItem>
    </ReportHost></Report></NessusClientData_v2>"""
    assert iter_nessus_items(text) == []


def test_vuln_scan_carries_host_start_scan_time() -> None:
    recs = vuln_scan.parse_file(FIXTURE)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 4
    assert {r["severity"] for r in findings} == {"low", "medium", "high", "critical"}
    for rec in findings:
        assert rec["extra"].get("scan_time")
        assert rec["extra"]["scan_time"].startswith("2026-09-25")
