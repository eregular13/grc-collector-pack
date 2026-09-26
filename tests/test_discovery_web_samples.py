"""Real-shaped discovery/web samples: no invented hostnames, no vendor-tail assets."""

from __future__ import annotations

from pathlib import Path

from collectors import easm, inventory_nmap
from shared.arp_scan import parse_arp_scan
from shared.fping import parse_fping
from shared.nbtscan import parse_nbtscan
from shared.netdiscover import parse_netdiscover
from shared.nmap_nse import vulners_cves
from shared.smbmap import parse_smbmap

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"


def _assets(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r["kind"] == "asset"]


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r["kind"] == "finding"]


def test_sources_credits_public_samples() -> None:
    text = (SAMPLES / "SOURCES.md").read_text(encoding="utf-8")
    assert "DefectDojo" in text
    assert "arp-scan.c" in text
    assert "not a client" in text.lower()


def test_arp_scan_sample_keys_by_ip_mac_keeps_vendor() -> None:
    hosts = parse_arp_scan(SAMPLES / "arp-scan.txt")
    assert hosts is not None
    names = {h["name"] for h in hosts}
    assert names == {"10.0.0.50", "10.0.0.51", "10.0.0.52"}
    assert not {n for n in names if "ltd" in n.lower()}
    vendors = {h["addr"]: h["vendor"] for h in hosts}
    assert "LTD" in vendors["10.0.0.51"].upper() or "Ltd" in vendors["10.0.0.51"]
    assert "Ltd" in vendors["10.0.0.52"] or "LTD" in vendors["10.0.0.52"].upper()
    recs = inventory_nmap.parse_file(SAMPLES / "arp-scan.txt")
    assert {r["name"] for r in _assets(recs)} == names
    assert _findings(recs) == []
    assert all((r.get("extra") or {}).get("vendor") for r in _assets(recs))


def test_arp_scan_resolve_host_first(tmp_path) -> None:
    dest = tmp_path / "arp-scan.txt"
    dest.write_text(
        "Starting arp-scan 1.10.0 with 1 hosts\n"
        "dc01.example.test\t00:11:22:33:44:55\tDell Inc.\n"
        "Ending arp-scan 1.10.0: 1 responded\n",
        encoding="utf-8",
    )
    hosts = parse_arp_scan(dest)
    assert hosts is not None
    assert len(hosts) == 1
    assert hosts[0]["hostname"] == "dc01.example.test"
    assert hosts[0]["addr"] == ""
    assert hosts[0]["vendor"] == "Dell Inc."
    assert hosts[0]["mac"] == "00:11:22:33:44:55"


def test_netdiscover_sample_does_not_collapse_ltd_vendors() -> None:
    hosts = parse_netdiscover(SAMPLES / "netdiscover.txt")
    assert hosts is not None
    names = {h["name"] for h in hosts}
    assert names == {"10.0.0.50", "10.0.0.51", "10.0.0.52"}
    assert all(not h.get("hostname") for h in hosts)
    assert parse_arp_scan(SAMPLES / "netdiscover.txt") is None


def test_fping_c_timeouts_are_not_live() -> None:
    hosts = parse_fping(SAMPLES / "fping-c.txt")
    assert hosts is not None
    names = {h["name"] for h in hosts}
    assert names == {"10.0.0.50", "10.0.0.52"}
    assert "10.0.0.51" not in names


def test_fping_e_a_and_j() -> None:
    e_hosts = parse_fping(SAMPLES / "fping-e.txt")
    assert e_hosts is not None
    assert {h["name"] for h in e_hosts} == {"10.0.0.50"}
    a_hosts = parse_fping(SAMPLES / "fping-a.txt")
    assert a_hosts is not None
    assert {h["name"] for h in a_hosts} == {"10.0.0.50", "10.0.0.52"}
    j_hosts = parse_fping(SAMPLES / "fping-j.jsonl")
    assert j_hosts is not None
    assert {h["name"] for h in j_hosts} == {"10.0.0.50", "10.0.0.52"}


def test_nbtscan_unknown_does_not_merge_and_s_v_parse() -> None:
    default = parse_nbtscan(SAMPLES / "nbtscan.txt")
    assert default is not None
    addrs = {h["addr"] for h in default}
    assert addrs == {"10.0.0.50", "10.0.0.51", "10.0.0.52"}
    assert {h["name"] for h in default} == addrs
    assert all(h["name"] != "<unknown>" for h in default)
    filesrv = next(h for h in default if h["addr"] == "10.0.0.50")
    assert filesrv["netbios"] == "FILESRV"
    sep = parse_nbtscan(SAMPLES / "nbtscan-s.txt")
    assert sep is not None
    assert {h["addr"] for h in sep} == {"10.0.0.50", "10.0.0.51"}
    assert next(h for h in sep if h["addr"] == "10.0.0.50")["mac"] == "00:11:22:33:44:55"
    verbose = parse_nbtscan(SAMPLES / "nbtscan-v.txt")
    assert verbose is not None
    assert len(verbose) == 1
    row = verbose[0]
    assert row["addr"] == "10.0.0.50"
    assert row["netbios"] == "FILESRV"
    assert row["mac"] == "00:11:22:33:44:55"
    assert row["name"] != "JSMITH"


def test_httpx_sample_keeps_each_url() -> None:
    recs = easm.parse_file(SAMPLES / "httpx.jsonl")
    assets = _assets(recs)
    findings = _findings(recs)
    assert [r["name"] for r in assets] == ["172.29.0.2"]
    urls = {(r.get("extra") or {}).get("url") for r in findings}
    assert "http://172.29.0.2/.git/config" in urls
    assert "http://172.29.0.2/admin/" in urls
    assert "http://172.29.0.2/login.html" in urls
    git = next(r for r in findings if (r.get("extra") or {}).get("path") == "/.git/config")
    assert git["severity"] == "high"


def test_ffuf_sample_grades_and_keeps_backup() -> None:
    recs = easm.parse_file(SAMPLES / "ffuf.json")
    findings = _findings(recs)
    paths = {(r.get("extra") or {}).get("path"): r["severity"] for r in findings}
    assert "/.git" in paths
    assert paths["/.git"] == "high"
    assert "/backup" in paths
    assert paths["/backup"] == "low"
    assert "/admin" in paths
    assert paths["/admin"] == "high"
    assert "/robots.txt" not in paths
    assert "/index.html" not in paths


def test_smbmap_sample_anon_spaces_ansi_csv_grepable() -> None:
    recs = inventory_nmap.parse_file(SAMPLES / "smbmap.txt")
    findings = _findings(recs)
    shares = {(r.get("extra") or {}).get("share") for r in findings}
    assert "Company Data" in shares
    assert any("Guest" in r["name"] or "NULL" in r["name"] or "anonymous" in r["name"].lower() for r in findings)
    assert not any("\x1b[" in str(r) for r in recs)
    csv_recs = inventory_nmap.parse_file(SAMPLES / "smbmap.csv")
    csv_shares = {(r.get("extra") or {}).get("share") for r in _findings(csv_recs)}
    assert "Company Data" in csv_shares
    assert "C$" in csv_shares
    g_recs = inventory_nmap.parse_file(SAMPLES / "smbmap-g.txt")
    g_shares = {(r.get("extra") or {}).get("share") for r in _findings(g_recs)}
    assert "Company Data" in g_shares
    hosts = parse_smbmap(SAMPLES / "smbmap.txt")
    assert hosts and hosts[0].get("session", "").lower().startswith("guest")


def test_naabu_sample_keeps_protocol_and_cdn_flag() -> None:
    recs = inventory_nmap.parse_file(SAMPLES / "naabu.jsonl")
    findings = _findings(recs)
    by_port = {(r.get("extra") or {}).get("port"): r for r in findings}
    assert by_port["23"]["extra"]["protocol"] == "tcp"
    assert by_port["161"]["extra"]["protocol"] == "udp"
    assert "UDP/161" in by_port["161"]["description"]
    cdn = next(r for r in findings if r["extra"].get("port") == "8080")
    assert cdn["extra"].get("cdn") is True
    assert "cloudflare" in str(cdn["extra"].get("cdn_name") or "")
    assert not any((r.get("extra") or {}).get("port") == "9999" for r in findings)


def test_nmap_vulners_emits_cve_findings() -> None:
    recs = inventory_nmap.parse_file(SAMPLES / "nmap-vulners.xml")
    findings = _findings(recs)
    cves = {r["extra"].get("cve") for r in findings if r["extra"].get("cve")}
    assert "CVE-2018-15919" in cves
    assert "CVE-2017-15906" in cves
    vuln = next(r for r in findings if r["extra"].get("cve") == "CVE-2017-15906")
    assert vuln["category"] == "vulnerability"
    assert vuln["severity"] == "medium"
    parsed = vulners_cves("", [("cvss", "5.0"), ("id", "CVE-2017-15906"), ("type", "cve")])
    assert parsed[0]["cve"] == "CVE-2017-15906"


def test_nmap_open_filtered_udp_and_mac() -> None:
    recs = inventory_nmap.parse_file(SAMPLES / "nmap-open-filtered.xml")
    assets = _assets(recs)
    findings = _findings(recs)
    assert assets[0]["name"] == "10.0.0.60"
    assert assets[0]["extra"].get("mac") == "00:11:22:33:44:88"
    ports = {(r.get("extra") or {}).get("port"): r for r in findings}
    assert "161" in ports
    assert ports["161"]["extra"]["protocol"] == "udp"
    assert "22" in ports
    assert "445" not in ports
