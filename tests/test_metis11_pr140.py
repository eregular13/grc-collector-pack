"""Metis §11 review of PR #140: one test per requested fix."""

from __future__ import annotations

from pathlib import Path

from collectors import easm, inventory_nmap
from shared.control_map import poam_decision
from shared.schema import canon_severity

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
_TCP_ONLY_TITLES = (
    "SMB 445 exposed",
    "Telnet exposed",
    "FTP exposed",
    "RDP exposed",
    "SSH exposed",
    "HTTP exposed",
)


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r["kind"] == "finding"]


def test_httpx_status_soft404_admin_host_not_every_url(tmp_path: Path) -> None:
    dest = tmp_path / "httpx.jsonl"
    dest.write_text(
        "\n".join(
            [
                '{"host":"admin.example.com","url":"https://admin.example.com/robots.txt","path":"/robots.txt","status_code":200,"title":"Robots","content_length":40}',
                '{"host":"admin.example.com","url":"https://admin.example.com/login","path":"/login","status_code":200,"title":"Sign in","content_length":800}',
                '{"host":"admin.example.com","url":"https://admin.example.com/nonesuch","path":"/nonesuch","status_code":404,"title":"Not Found","content_length":199}',
                '{"host":"admin.example.com","url":"https://admin.example.com/soft","path":"/soft","status_code":200,"title":"Not Found","content_length":199}',
                '{"host":"www.example.com","url":"https://www.example.com/admin","path":"/admin","status_code":401,"title":"Auth","content_length":12}',
                '{"host":"www.example.com","url":"https://www.example.com/index","path":"/index","status_code":401,"title":"Auth","content_length":12}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    recs = easm.parse_file(dest)
    findings = _findings(recs)
    urls = {(r.get("extra") or {}).get("url") for r in findings}
    assert "https://admin.example.com/login" in urls
    assert "https://www.example.com/admin" in urls
    assert "https://admin.example.com/robots.txt" not in urls
    assert "https://admin.example.com/soft" not in urls
    assert "https://www.example.com/index" not in urls
    login = next(r for r in findings if (r.get("extra") or {}).get("path") == "/login")
    assert login["severity"] == canon_severity("high")
    assert login["ref_id"].startswith("EASM-")
    assert "admin.example.com" in login["assets"]


def test_udp_open_filtered_is_info(tmp_path: Path) -> None:
    dest = tmp_path / "scan.xml"
    dest.write_text(
        """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sU" start="1700000000" version="7.95">
  <host>
    <status state="up"/>
    <address addr="10.0.0.60" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open|filtered"/>
        <service name="snmp"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    findings = _findings(recs)
    udp = next(r for r in findings if (r.get("extra") or {}).get("port") == "161")
    assert udp["extra"]["protocol"] == "udp"
    assert udp["extra"].get("state") == "open|filtered"
    assert udp["severity"] == canon_severity("info")
    ssh = next(r for r in findings if (r.get("extra") or {}).get("port") == "22")
    assert ssh["severity"] == canon_severity("low")
    assert ssh["ref_id"].startswith("NMAP-")
    assert udp["assets"] == ["10.0.0.60"]


def test_smbmap_null_only_when_unauthenticated(tmp_path: Path) -> None:
    creds = tmp_path / "smbmap-auth.txt"
    creds.write_text(
        "[+] IP: 10.0.0.50:445\tName: FILESRV\tStatus: AUTHENTICATED\n"
        "        Disk                                                    Permissions\tComment\n"
        "	----                                              	-----------	-------\n"
        "	C$                                                	READ, WRITE	Default share\n"
        "	IPC$                                              	NO ACCESS	Remote IPC\n",
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(creds)
    names = [r["name"] for r in _findings(recs)]
    assert not any("NULL" in n for n in names)
    assert any("C$" in n for n in names)

    null_run = tmp_path / "smbmap-null.txt"
    null_run.write_text(
        "[+] IP: 10.0.0.50:445\tName: FILESRV\tStatus: NULL session\n"
        "        Disk                                                    Permissions\tComment\n"
        "	----                                              	-----------	-------\n"
        "	IPC$                                              	NO ACCESS	Remote IPC\n",
        encoding="utf-8",
    )
    null_recs = inventory_nmap.parse_file(null_run)
    nulls = [r for r in _findings(null_recs) if "NULL" in r["name"]]
    assert len(nulls) == 1
    assert nulls[0]["severity"] == canon_severity("high")
    assert nulls[0]["assets"] == ["FILESRV"]
    assert nulls[0]["ref_id"].startswith("NMAP-")
    assert "Guest session" not in (ROOT / "fixtures" / "samples" / "smbmap.txt").read_text(
        encoding="utf-8"
    )


def test_naabu_cdn_edge_port_is_not_a_finding(tmp_path: Path) -> None:
    dest = tmp_path / "naabu.jsonl"
    dest.write_text(
        '{"ip":"10.0.0.80","port":8080,"protocol":"tcp","cdn":true,"cdn-name":"cloudflare"}\n'
        '{"ip":"10.0.0.50","port":23,"protocol":"tcp"}\n',
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    findings = _findings(recs)
    assert not any((r.get("extra") or {}).get("port") == "8080" for r in findings)
    telnet = next(r for r in findings if (r.get("extra") or {}).get("port") == "23")
    assert telnet["severity"] == canon_severity("critical")
    cdn_asset = next(r for r in recs if r["kind"] == "asset" and r["name"] == "10.0.0.80")
    assert cdn_asset["extra"].get("cdn") is True
    assert "cloudflare" in str(cdn_asset["extra"].get("cdn_name") or "")


def test_vulners_high_cve_separate_low_rolled_up(tmp_path: Path) -> None:
    dest = tmp_path / "nmap-vulners.xml"
    dest.write_text(
        """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap --script vulners" start="1700000000" version="7.60">
  <host>
    <status state="up"/>
    <address addr="192.168.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
        <script id="vulners" output="">
          <table key="cpe:/a:openbsd:openssh:7.4">
            <table>
              <elem key="cvss">9.8</elem>
              <elem key="id">CVE-2024-99999</elem>
              <elem key="type">cve</elem>
            </table>
            <table>
              <elem key="cvss">5.0</elem>
              <elem key="id">CVE-2017-15906</elem>
              <elem key="type">cve</elem>
            </table>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    findings = _findings(recs)
    solo = [r for r in findings if r.get("extra", {}).get("cve") == "CVE-2024-99999"]
    assert len(solo) == 1
    assert solo[0]["severity"] == canon_severity("critical")
    assert solo[0]["assets"] == ["192.168.0.1"]
    assert solo[0]["ref_id"].startswith("NMAP-")
    assert solo[0]["extra"].get("check_id") == "CVE-2024-99999"
    rolled = [r for r in findings if r.get("extra", {}).get("check_id") == "vulners-rollup"]
    assert len(rolled) == 1
    assert "CVE-2017-15906" in (rolled[0]["extra"].get("cves") or [])
    assert "CVE-2024-99999" not in (rolled[0]["extra"].get("cves") or [])
    assert rolled[0]["severity"] == canon_severity("medium")
    assert rolled[0]["assets"] == ["192.168.0.1"]


def test_real_udp_scan_no_tcp_rule_on_udp_snmp_two_hosts() -> None:
    """chroniccrash/c4rtographer@b73866a udpConnect: SNMP on 2 hosts, 135 excluded."""
    dest = SAMPLES / "udpConnect_10.11.1.0-254.xml"
    recs = inventory_nmap.parse_file(dest)
    findings = _findings(recs)
    assert len(findings) == 137
    assert not any("Administrative share" in r["name"] for r in findings)
    for rec in findings:
        extra = rec.get("extra") or {}
        if extra.get("protocol") == "udp":
            assert rec["name"] not in _TCP_ONLY_TITLES
            assert "SMB 445" not in rec["name"]
            assert "Administrative share" not in rec["name"]
    included = [r for r in findings if poam_decision(r)["include"]]
    excluded = [r for r in findings if not poam_decision(r)["include"]]
    # Host-scoped per #137: one POA&M row per host (SNMP 161/udp on 2 hosts).
    assert len(included) == 2
    assert {a for r in included for a in r["assets"]} == {"10.11.1.22", "10.11.1.115"}
    assert all((r.get("extra") or {}).get("port") == "161" for r in included)
    assert all((r.get("extra") or {}).get("protocol") == "udp" for r in included)
    assert all((r.get("extra") or {}).get("state") in {None, "open"} for r in included)
    assert all(r["severity"] == canon_severity("high") for r in included)
    assert all(r["ref_id"].startswith("NMAP-") for r in included)
    assert len(excluded) == 135
    of_rows = [r for r in findings if (r.get("extra") or {}).get("state") == "open|filtered"]
    assert len(of_rows) == 101
    assert all(poam_decision(r)["include"] is False for r in of_rows)
    assert all(poam_decision(r)["reason"] == "not_a_weakness" for r in of_rows)
    udp445 = [r for r in findings if (r.get("extra") or {}).get("port") == "445"]
    assert udp445
    assert all((r.get("extra") or {}).get("protocol") == "udp" for r in udp445)
    assert all(r["severity"] == canon_severity("info") for r in udp445)
    assert all(not poam_decision(r)["include"] for r in udp445)
