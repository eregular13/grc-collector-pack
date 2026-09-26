"""Nessus parser must capture every <cve> child on a ReportItem (spec Gap 1 / §1.4)."""

from __future__ import annotations

from pathlib import Path

from collectors import vuln_scan
from shared.nessus import iter_nessus_items, parse_nessus

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "nessus" / "cve-tags.nessus"


def test_nessus_parser_captures_all_cve_child_elements() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    rows = iter_nessus_items(text)
    assert len(rows) == 1
    assert rows[0]["plugin_id"] == "156032"
    assert rows[0]["cves"] == ["CVE-2021-44228", "CVE-2021-45046"]
    assert rows[0]["protocol"] == "tcp"
    parsed = parse_nessus(FIXTURE)
    assert parsed is not None
    assert parsed[0]["cves"] == ["CVE-2021-44228", "CVE-2021-45046"]


def test_vuln_scan_nessus_extra_carries_cves_list() -> None:
    recs = vuln_scan.parse_file(FIXTURE)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    extra = findings[0]["extra"]
    assert extra["cves"] == ["CVE-2021-44228", "CVE-2021-45046"]
    assert "CVE-2021-44228" in extra["cve"]
    assert "CVE-2021-45046" in extra["cve"]
    assert extra["tool"] == "nessus"
    assert extra["protocol"] == "tcp"


def test_nessus_cve_attribute_and_case_normalize() -> None:
    from shared.nessus import _cves_from_item, iter_nessus_items
    import xml.etree.ElementTree as ET

    item = ET.fromstring(
        '<ReportItem cve="cve-2021-44228,CVE-2021-45046" severity="3" '
        'pluginID="1" pluginName="attr">'
        "<risk_factor>High</risk_factor>"
        "<cve>CVE-2021-44228</cve>"
        "</ReportItem>"
    )
    assert _cves_from_item(item) == ["CVE-2021-44228", "CVE-2021-45046"]
    rows = iter_nessus_items(
        "<NessusClientData_v2><Report name='t'><ReportHost name='h'>"
        '<ReportItem port="443" severity="3" pluginID="1" pluginName="attr" '
        'cve="CVE-2014-0160">'
        "<risk_factor>High</risk_factor>"
        "</ReportItem>"
        "</ReportHost></Report></NessusClientData_v2>"
    )
    assert rows[0]["cves"] == ["CVE-2014-0160"]
