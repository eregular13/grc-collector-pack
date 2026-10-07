"""Unit tests for nmap version-aware severity + nikto original_detection_date.

Synthetic fixtures only — no lab IPs or lab data.
"""

from __future__ import annotations

from pathlib import Path

from collectors import inventory_nmap
from shared import nmap_version_sev as nvs
from shared.nikto import parse_nikto
from shared.poam_fields import poam_fields
from shared.scan_time import NOT_RECORDED, format_detection_date
from shared.control_map import map_finding


ROOT = Path(__file__).resolve().parents[1]


def _nmap_xml(
    *,
    product: str,
    version: str,
    port: str = "22",
    service: str = "ssh",
    extrainfo: str = "",
    scripts: str = "",
) -> str:
    extra_attr = f' extrainfo="{extrainfo}"' if extrainfo else ""
    return f"""<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" start="1700000000" startstr="Wed Nov 15 00:00:00 2023" version="7.90" xmloutputversion="1.05">
<host><status state="up"/>
<address addr="10.0.0.9" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="{port}">
  <state state="open"/>
  <service name="{service}" product="{product}" version="{version}"{extra_attr} method="probed" conf="10"/>
  {scripts}
</port>
</ports>
</host>
</nmaprun>
"""


def test_openssh_old_raises_severity_and_shows_version(tmp_path: Path) -> None:
    dest = tmp_path / "nmap-old-ssh.xml"
    dest.write_text(
        _nmap_xml(product="OpenSSH", version="6.0p1 Debian 4", port="22", service="ssh"),
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    finds = [r for r in recs if r.get("kind") == "finding"]
    assert finds
    ssh = next(r for r in finds if (r.get("extra") or {}).get("port") == "22")
    assert ssh["severity"] == "medium"  # low → medium
    blob = f"{ssh.get('name')} {ssh.get('description')}"
    assert "OpenSSH" in blob
    assert "6.0p1" in blob
    assert (ssh.get("extra") or {}).get("check_id") == "nmap-port-22/tcp"
    assert (ssh.get("extra") or {}).get("product") == "OpenSSH"


def test_apache_old_raises_severity_and_shows_version(tmp_path: Path) -> None:
    scripts = '<script id="http-generator" output="Drupal 7 (http://drupal.org)"/>'
    dest = tmp_path / "nmap-old-http.xml"
    dest.write_text(
        _nmap_xml(
            product="Apache httpd",
            version="2.2.22",
            port="80",
            service="http",
            extrainfo="(Debian)",
            scripts=scripts,
        ),
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    finds = [r for r in recs if r.get("kind") == "finding"]
    http = next(r for r in finds if (r.get("extra") or {}).get("port") == "80")
    assert http["severity"] == "medium"
    blob = f"{http.get('name')} {http.get('description')}"
    assert "Apache" in blob
    assert "2.2.22" in blob
    # Drupal hint from script should surface in text when present
    assert "Drupal" in blob
    assert (http.get("extra") or {}).get("check_id") == "nmap-port-80/tcp"


def test_unknown_version_keeps_port_severity(tmp_path: Path) -> None:
    dest = tmp_path / "nmap-unknown.xml"
    # product present, version empty → no bump
    dest.write_text(
        _nmap_xml(product="OpenSSH", version="", port="22", service="ssh"),
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    finds = [r for r in recs if r.get("kind") == "finding"]
    ssh = next(r for r in finds if (r.get("extra") or {}).get("port") == "22")
    assert ssh["severity"] == "low"
    # product still appears when known
    assert "OpenSSH" in f"{ssh.get('name')} {ssh.get('description')}"


def test_modern_openssh_unchanged(tmp_path: Path) -> None:
    dest = tmp_path / "nmap-new-ssh.xml"
    dest.write_text(
        _nmap_xml(product="OpenSSH", version="9.6p1", port="22", service="ssh"),
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    finds = [r for r in recs if r.get("kind") == "finding"]
    ssh = next(r for r in finds if (r.get("extra") or {}).get("port") == "22")
    assert ssh["severity"] == "low"
    assert "9.6p1" in f"{ssh.get('name')} {ssh.get('description')}"


def test_rule_table_helpers_unit() -> None:
    sev, rid = nvs.apply_version_severity(
        "low", product="OpenSSH", version="6.0p1"
    )
    assert sev == "medium" and rid == "openssh-lt-7.0"
    sev2, rid2 = nvs.apply_version_severity(
        "low", product="OpenSSH", version="9.0"
    )
    assert sev2 == "low" and rid2 is None
    sev3, rid3 = nvs.apply_version_severity(
        "low", product="something-custom", version=""
    )
    assert sev3 == "low" and rid3 is None
    assert nvs.parse_version_tuple("6.0p1 Debian") == (6, 0)
    assert nvs.parse_version_tuple("") is None


def test_nikto_xml_scan_time_feeds_detection_date(tmp_path: Path) -> None:
    xml = """<?xml version="1.0" ?>
<!DOCTYPE niktoscan>
<niktoscan version="2.1.5" scanstart="Mon Oct 5 19:21:36 2026" nxmlversion="1.2">
<scandetails targetip="10.0.0.9" targethostname="10.0.0.9" targetport="80"
 starttime="2026-10-05 19:21:36" sitename="http://10.0.0.9:80">
<item id="000301" osvdbid="0" method="GET">
<description><![CDATA[/web.config: ASP config file is accessible.]]></description>
<uri><![CDATA[/web.config]]></uri>
</item>
</scandetails>
</niktoscan>
"""
    dest = tmp_path / "nikto.xml"
    dest.write_text(xml, encoding="utf-8")
    rows = parse_nikto(dest)
    assert rows and rows[0].get("scan_time")
    assert format_detection_date(rows[0]["scan_time"]) == "2026-10-05"

    # Through vuln_scan collector → finding extra.scan_time
    from collectors import vuln_scan

    recs = vuln_scan.parse_file(dest)
    finds = [r for r in recs if r.get("kind") == "finding"]
    assert finds
    assert (finds[0].get("extra") or {}).get("scan_time")
    # poam_fields uses detection_date → original_detection_date
    mapped = map_finding(finds[0])
    from datetime import date

    fields = poam_fields(finds[0], mapped, date(2026, 10, 6))
    assert fields["original_detection_date"] == "2026-10-05"
    assert fields["original_detection_date"] != NOT_RECORDED


def test_nikto_prior_out_keeps_earliest_date(tmp_path: Path) -> None:
    """merge_detection keeps the earliest date across prior-out."""
    from shared.scan_time import merge_detection

    assert merge_detection("2026-10-01", "2026-10-05") == "2026-10-01"
    assert merge_detection("not recorded", "2026-10-05") == "2026-10-05"
    assert merge_detection("2026-10-05", "not recorded") == "2026-10-05"
