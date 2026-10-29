"""UTF-8 BOM must not hide OpenSCAP XML shape or drop findings."""

from __future__ import annotations

from pathlib import Path

from shared.openscap import is_openscap, iter_openscap_failures

# Minimal XCCDF rule-result fail — synthetic, not a lab export.
_MIN_XCCDF = """<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <TestResult>
    <target>host-a</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_demo" severity="high">
      <result>fail</result>
    </rule-result>
  </TestResult>
</Benchmark>
"""


def test_openscap_utf8_bom_still_recognized() -> None:
    bombed = "\ufeff" + _MIN_XCCDF
    assert is_openscap(text=bombed, name="oscap-demo.xml")
    rows = iter_openscap_failures(bombed)
    assert rows, "BOM-prefixed OpenSCAP XML must still yield failures"


def test_openscap_plain_utf8_unchanged() -> None:
    assert is_openscap(text=_MIN_XCCDF, name="oscap-demo.xml")
    assert iter_openscap_failures(_MIN_XCCDF)


def test_host_wazuh_bom_prefixed_oscap(tmp_path: Path) -> None:
    import collectors.host_wazuh as host_wazuh

    dest = tmp_path / "oscap-rule-results.xml"
    dest.write_bytes(b"\xef\xbb\xbf" + _MIN_XCCDF.encode("utf-8"))
    recs = host_wazuh.parse_file(dest)
    findings = [r for r in recs if r.get("kind") == "finding"]
    assert findings, "host-wazuh must not silent-zero OpenSCAP with a UTF-8 BOM"
