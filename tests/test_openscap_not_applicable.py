"""prior-unit: OpenSCAP all-notapplicable is explicit NOT_APPLICABLE (10.0.0.x)."""
from __future__ import annotations

import shared.openscap as openscap
from shared.openscap import iter_openscap_failures


def test_openscap_all_notapplicable_is_explicit() -> None:
    xml = """<?xml version='1.0'?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_WRONG">
  <TestResult id="xccdf_org.open-scap_testresult_test" start-time="2026-01-01T00:00:00">
    <target>10.0.0.50</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_a" result="notapplicable"/>
    <rule-result idref="xccdf_org.ssgproject.content_rule_b" result="notselected"/>
  </TestResult>
</Benchmark>
"""
    assert iter_openscap_failures(xml) == []
    fn = getattr(openscap, "openscap_applicability", None)
    assert fn is not None, "openscap_applicability missing"
    note = fn(xml)
    assert note.get("status") == "NOT_APPLICABLE"
    msg = note.get("message", "")
    assert "NOT_APPLICABLE" in msg or "not-applicable" in msg.lower()
    # message must disambiguate from clean-host "zero findings"
    assert "not zero" in msg.lower() or "does not match" in msg.lower()
