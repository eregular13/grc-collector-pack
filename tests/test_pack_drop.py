"""Covey pack_drop on the existing inventory-nmap lane."""

from __future__ import annotations

from pathlib import Path

from collectors import inventory_nmap
from shared.control_map import map_finding
from shared.pack_drop import looks_like_pack_drop
from shared.sslscan import parse_sslscan

ROOT = Path(__file__).resolve().parents[1]
DROP = ROOT / "fixtures" / "pack_drop" / "nmap"
RUST = ROOT / "fixtures" / "pack_drop" / "rustscan"
HTTPX = ROOT / "fixtures" / "pack_drop" / "httpx"
UNI = ROOT / "fixtures" / "pack_drop" / "unicornscan"
SSL = ROOT / "fixtures" / "pack_drop" / "sslscan"
TLSX = ROOT / "fixtures" / "pack_drop" / "tlsx"
WHATWEB = ROOT / "fixtures" / "pack_drop" / "whatweb"
HPING3 = ROOT / "fixtures" / "pack_drop" / "hping3"
ONESIXTYONE = ROOT / "fixtures" / "pack_drop" / "onesixtyone"
FPING = ROOT / "fixtures" / "pack_drop" / "fping"
NAABU = ROOT / "fixtures" / "pack_drop" / "naabu"
NPING = ROOT / "fixtures" / "pack_drop" / "nping"
NBTSCAN = ROOT / "fixtures" / "pack_drop" / "nbtscan"
DEMO_NMAP = ROOT / "fixtures" / "demo" / "nmap"


def test_pack_drop_assets_reuse_emit_host() -> None:
    recs = inventory_nmap.parse_file(DROP / "assets.jsonl")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "filesrv.corp.local" in assets
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any((r.get("extra") or {}).get("port") == "445" for r in findings)
    smb = next(r for r in findings if (r.get("extra") or {}).get("port") == "445")
    assert "covey" in (smb.get("labels") or [])
    mapped = map_finding(smb)
    assert mapped["include_poam"] is True
    assert "CVE-" not in mapped["recommended_fix"]


def test_pack_drop_findings_lift() -> None:
    recs = inventory_nmap.parse_file(DROP / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert findings[0]["source"] == "inventory-nmap"
    assert findings[0]["ref_id"].startswith("NMAP-")
    assert "filesrv.corp.local" in (findings[0].get("assets") or [])


def test_pack_drop_meta_and_evidence_dir() -> None:
    meta = inventory_nmap.parse_file(DROP / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    assert "covey" in evid[0]["name"].lower() or "pack_drop" in evid[0]["description"].lower()
    note = inventory_nmap.parse_file(DROP / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(DROP / "evidence" / "note.md")


def test_pack_drop_empty_invents_nothing(tmp_path: Path) -> None:
    dest = tmp_path / "assets.jsonl"
    dest.write_text("", encoding="utf-8")
    assert inventory_nmap.parse_file(dest) == []
    dest.write_text("\n", encoding="utf-8")
    assert inventory_nmap.parse_file(dest) == []
    meta = tmp_path / "meta.json"
    meta.write_text("{}", encoding="utf-8")
    recs = inventory_nmap.parse_file(meta)
    assert recs == [] or all(r["kind"] == "evidence" for r in recs)


def test_pack_drop_does_not_steal_gnmap() -> None:
    recs = inventory_nmap.parse_file(DEMO_NMAP / "scan.gnmap")
    assert any(r["kind"] == "asset" and r["name"] == "filesrv.corp.local" for r in recs)
    assert not looks_like_pack_drop(DEMO_NMAP / "scan.gnmap", recs[0].get("name", ""))


def test_demo_nmap_fixtures_are_not_pack_drop() -> None:
    names = {p.name for p in DEMO_NMAP.iterdir() if p.is_file()}
    assert "assets.jsonl" not in names
    assert "findings.jsonl" not in names
    assert "meta.json" not in names


def test_pack_drop_rustscan_hosts_and_services() -> None:
    recs = inventory_nmap.parse_file(RUST / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    names = {r["name"] for r in assets}
    assert "10.9.8.7" in names
    assert "10.9.8.8" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    findings = [r for r in recs if r["kind"] == "finding"]
    ports = {str((r.get("extra") or {}).get("port") or "") for r in findings}
    assert {"80", "443", "22"} <= ports
    assert any("10.9.8.7" in (r.get("assets") or []) for r in findings)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_rustscan_observations_lift() -> None:
    recs = inventory_nmap.parse_file(RUST / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("80" in t for t in titles)
    assert any("443" in t for t in titles)
    assert any("22" in t for t in titles)
    claims = {(r.get("extra") or {}).get("claim") for r in findings}
    assert "open_port_observed" in claims
    assert any("10.9.8.7" in (r.get("assets") or []) for r in findings)
    assert any("rustscan" in (r.get("labels") or []) for r in findings)
    not_claimed = (findings[0].get("extra") or {}).get("not_claimed") or []
    assert "vulnerability" in not_claimed
    assert "control_operating_effectiveness" in not_claimed


def test_pack_drop_rustscan_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(RUST / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "rustscan"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(RUST / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(RUST / "evidence" / "note.md")
    sample = (RUST / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()


def test_pack_drop_rustscan_does_not_break_nmap() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert all(r["name"] != "filesrv.corp.local" for r in rust if r["kind"] == "asset")
    assert all((r.get("extra") or {}).get("port") != "445" for r in rust if r["kind"] == "finding")


def test_pack_drop_httpx_hosts_and_services() -> None:
    recs = inventory_nmap.parse_file(HTTPX / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    names = {r["name"] for r in assets}
    assert "10.9.8.20" in names
    assert "10.9.8.21" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    findings = [r for r in recs if r["kind"] == "finding"]
    ports = {str((r.get("extra") or {}).get("port") or "") for r in findings}
    assert {"80", "8080", "443"} <= ports
    assert any("10.9.8.20" in (r.get("assets") or []) for r in findings)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_httpx_observations_lift() -> None:
    recs = inventory_nmap.parse_file(HTTPX / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("80" in t for t in titles)
    assert any("8080" in t for t in titles)
    assert any("443" in t for t in titles)
    claims = {(r.get("extra") or {}).get("claim") for r in findings}
    assert "open_port_observed" in claims
    assert any("10.9.8.20" in (r.get("assets") or []) for r in findings)
    assert any("httpx" in (r.get("labels") or []) for r in findings)
    not_claimed = (findings[0].get("extra") or {}).get("not_claimed") or []
    assert "vulnerability" in not_claimed
    assert "control_operating_effectiveness" in not_claimed


def test_pack_drop_httpx_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(HTTPX / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "httpx"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(HTTPX / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(HTTPX / "evidence" / "note.md")
    sample = (HTTPX / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()


def test_pack_drop_httpx_does_not_break_nmap_or_rustscan() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    httpx = inventory_nmap.parse_file(HTTPX / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert all(r["name"] != "filesrv.corp.local" for r in httpx if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in httpx if r["kind"] == "asset")
    assert all((r.get("extra") or {}).get("port") != "445" for r in httpx if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "22" for r in httpx if r["kind"] == "finding")


def test_pack_drop_unicornscan_hosts_and_services() -> None:
    recs = inventory_nmap.parse_file(UNI / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    names = {r["name"] for r in assets}
    assert "10.9.8.40" in names
    assert "10.9.8.41" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    findings = [r for r in recs if r["kind"] == "finding"]
    ports = {str((r.get("extra") or {}).get("port") or "") for r in findings}
    assert {"21", "23", "53"} <= ports
    assert any("10.9.8.40" in (r.get("assets") or []) for r in findings)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_unicornscan_observations_lift() -> None:
    recs = inventory_nmap.parse_file(UNI / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("21" in t for t in titles)
    assert any("23" in t for t in titles)
    assert any("53" in t for t in titles)
    claims = {(r.get("extra") or {}).get("claim") for r in findings}
    assert "open_port_observed" in claims
    assert any("10.9.8.40" in (r.get("assets") or []) for r in findings)
    assert any("unicornscan" in (r.get("labels") or []) for r in findings)
    not_claimed = (findings[0].get("extra") or {}).get("not_claimed") or []
    assert "vulnerability" in not_claimed
    assert "control_operating_effectiveness" in not_claimed


def test_pack_drop_unicornscan_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(UNI / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "unicornscan"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(UNI / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(UNI / "evidence" / "note.md")
    sample = (UNI / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()


def test_pack_drop_unicornscan_does_not_break_nmap_rustscan_or_httpx() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    httpx = inventory_nmap.parse_file(HTTPX / "assets.jsonl")
    uni = inventory_nmap.parse_file(UNI / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.20" for r in httpx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8080" for r in httpx if r["kind"] == "finding")
    assert all(r["name"] != "filesrv.corp.local" for r in uni if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in uni if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.20" for r in uni if r["kind"] == "asset")
    assert all((r.get("extra") or {}).get("port") != "445" for r in uni if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "22" for r in uni if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "8080" for r in uni if r["kind"] == "finding")


def test_pack_drop_sslscan_hosts_and_services() -> None:
    recs = inventory_nmap.parse_file(SSL / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    names = {r["name"] for r in assets}
    assert "10.9.8.50" in names
    assert "10.9.8.51" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    findings = [r for r in recs if r["kind"] == "finding"]
    ports = {str((r.get("extra") or {}).get("port") or "") for r in findings}
    assert {"443", "8443"} <= ports
    assert any("10.9.8.50" in (r.get("assets") or []) for r in findings)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_sslscan_observations_lift() -> None:
    recs = inventory_nmap.parse_file(SSL / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("443" in t for t in titles)
    assert any("8443" in t for t in titles)
    claims = {(r.get("extra") or {}).get("claim") for r in findings}
    assert "open_port_observed" in claims
    assert any("10.9.8.50" in (r.get("assets") or []) for r in findings)
    assert any("sslscan" in (r.get("labels") or []) for r in findings)
    not_claimed = (findings[0].get("extra") or {}).get("not_claimed") or []
    assert "vulnerability" in not_claimed
    assert "control_operating_effectiveness" in not_claimed


def test_pack_drop_sslscan_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(SSL / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "sslscan"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(SSL / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(SSL / "evidence" / "note.md")
    xml = inventory_nmap.parse_file(SSL / "evidence" / "sslscan.xml")
    assert xml
    assert all(r["kind"] == "evidence" for r in xml)
    assert looks_like_pack_drop(SSL / "evidence" / "sslscan.xml")
    sample = (SSL / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()
    xml_text = (SSL / "evidence" / "sslscan.xml").read_text(encoding="utf-8")
    assert "10.9.8.50" in xml_text
    assert "SAMPLE/DEMO" in xml_text or "not a client" in xml_text.lower()
    parsed = parse_sslscan(SSL / "evidence" / "sslscan.xml")
    assert parsed
    assert any(
        r.get("host") == "10.9.8.50" and "TLS 1.0" in str(r.get("name") or r.get("finding") or "")
        for r in parsed
    )


def test_pack_drop_sslscan_does_not_break_nmap_rustscan_httpx_or_unicornscan() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    httpx = inventory_nmap.parse_file(HTTPX / "assets.jsonl")
    uni = inventory_nmap.parse_file(UNI / "assets.jsonl")
    ssl = inventory_nmap.parse_file(SSL / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.20" for r in httpx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8080" for r in httpx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.40" for r in uni if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "21" for r in uni if r["kind"] == "finding")
    assert all(r["name"] != "filesrv.corp.local" for r in ssl if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in ssl if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.20" for r in ssl if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.40" for r in ssl if r["kind"] == "asset")
    assert all((r.get("extra") or {}).get("port") != "445" for r in ssl if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "22" for r in ssl if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "8080" for r in ssl if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "21" for r in ssl if r["kind"] == "finding")


def test_pack_drop_tlsx_hosts_and_services() -> None:
    recs = inventory_nmap.parse_file(TLSX / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    names = {r["name"] for r in assets}
    assert "10.9.8.60" in names
    assert "10.9.8.61" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    findings = [r for r in recs if r["kind"] == "finding"]
    ports = {str((r.get("extra") or {}).get("port") or "") for r in findings}
    assert {"443", "853", "636"} <= ports
    assert any("10.9.8.60" in (r.get("assets") or []) for r in findings)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_tlsx_observations_lift() -> None:
    recs = inventory_nmap.parse_file(TLSX / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("443" in t for t in titles)
    assert any("853" in t for t in titles)
    assert any("636" in t for t in titles)
    claims = {(r.get("extra") or {}).get("claim") for r in findings}
    assert "open_port_observed" in claims
    assert any("10.9.8.60" in (r.get("assets") or []) for r in findings)
    assert any("tlsx" in (r.get("labels") or []) for r in findings)
    not_claimed = (findings[0].get("extra") or {}).get("not_claimed") or []
    assert "vulnerability" in not_claimed
    assert "control_operating_effectiveness" in not_claimed


def test_pack_drop_tlsx_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(TLSX / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "tlsx"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(TLSX / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(TLSX / "evidence" / "note.md")
    sample = (TLSX / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()


def test_pack_drop_tlsx_does_not_break_nmap_rustscan_httpx_unicornscan_or_sslscan() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    httpx = inventory_nmap.parse_file(HTTPX / "assets.jsonl")
    uni = inventory_nmap.parse_file(UNI / "assets.jsonl")
    ssl = inventory_nmap.parse_file(SSL / "assets.jsonl")
    tlsx = inventory_nmap.parse_file(TLSX / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.20" for r in httpx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8080" for r in httpx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.40" for r in uni if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "21" for r in uni if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.50" for r in ssl if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8443" for r in ssl if r["kind"] == "finding")
    assert all(r["name"] != "filesrv.corp.local" for r in tlsx if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in tlsx if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.20" for r in tlsx if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.40" for r in tlsx if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.50" for r in tlsx if r["kind"] == "asset")
    assert all((r.get("extra") or {}).get("port") != "445" for r in tlsx if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "22" for r in tlsx if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "8080" for r in tlsx if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "21" for r in tlsx if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "8443" for r in tlsx if r["kind"] == "finding")


def test_pack_drop_whatweb_hosts_and_services() -> None:
    recs = inventory_nmap.parse_file(WHATWEB / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    names = {r["name"] for r in assets}
    assert "10.9.8.70" in names
    assert "10.9.8.71" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    findings = [r for r in recs if r["kind"] == "finding"]
    ports = {str((r.get("extra") or {}).get("port") or "") for r in findings}
    assert {"8000", "8888", "9000"} <= ports
    assert any("10.9.8.70" in (r.get("assets") or []) for r in findings)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_whatweb_observations_lift() -> None:
    recs = inventory_nmap.parse_file(WHATWEB / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("8000" in t for t in titles)
    assert any("8888" in t for t in titles)
    assert any("9000" in t for t in titles)
    claims = {(r.get("extra") or {}).get("claim") for r in findings}
    assert "open_port_observed" in claims
    assert any("10.9.8.70" in (r.get("assets") or []) for r in findings)
    assert any("whatweb" in (r.get("labels") or []) for r in findings)
    not_claimed = (findings[0].get("extra") or {}).get("not_claimed") or []
    assert "vulnerability" in not_claimed
    assert "control_operating_effectiveness" in not_claimed


def test_pack_drop_whatweb_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(WHATWEB / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "whatweb"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(WHATWEB / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(WHATWEB / "evidence" / "note.md")
    sample = (WHATWEB / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()


def test_pack_drop_whatweb_does_not_break_nmap_rustscan_httpx_unicornscan_sslscan_or_tlsx() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    httpx = inventory_nmap.parse_file(HTTPX / "assets.jsonl")
    uni = inventory_nmap.parse_file(UNI / "assets.jsonl")
    ssl = inventory_nmap.parse_file(SSL / "assets.jsonl")
    tlsx = inventory_nmap.parse_file(TLSX / "assets.jsonl")
    whatweb = inventory_nmap.parse_file(WHATWEB / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.20" for r in httpx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8080" for r in httpx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.40" for r in uni if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "21" for r in uni if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.50" for r in ssl if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8443" for r in ssl if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.60" for r in tlsx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "853" for r in tlsx if r["kind"] == "finding")
    assert all(r["name"] != "filesrv.corp.local" for r in whatweb if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in whatweb if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.20" for r in whatweb if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.40" for r in whatweb if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.50" for r in whatweb if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.60" for r in whatweb if r["kind"] == "asset")
    assert all((r.get("extra") or {}).get("port") != "445" for r in whatweb if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "22" for r in whatweb if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "8080" for r in whatweb if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "21" for r in whatweb if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "8443" for r in whatweb if r["kind"] == "finding")
    assert all((r.get("extra") or {}).get("port") != "853" for r in whatweb if r["kind"] == "finding")


def test_pack_drop_hping3_hosts_only() -> None:
    recs = inventory_nmap.parse_file(HPING3 / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    names = {r["name"] for r in assets}
    assert "10.9.8.80" in names
    assert "10.9.8.81" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    assert all("hping3" in (r.get("labels") or []) for r in assets)
    assert findings == []
    assert all(not (r.get("extra") or {}).get("port") for r in recs)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_hping3_observations_lift() -> None:
    recs = inventory_nmap.parse_file(HPING3 / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) >= 2
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("10.9.8.80" in t and ("ICMP" in t or "host up" in t.lower()) for t in titles)
    assert any("10.9.8.81" in t and ("ICMP" in t or "host up" in t.lower()) for t in titles)
    claims = {(r.get("extra") or {}).get("claim") for r in findings}
    assert "host_up_observed" in claims
    assert "open_port_observed" not in claims
    assert all(not (r.get("extra") or {}).get("port") for r in findings)
    assert any("10.9.8.80" in (r.get("assets") or []) for r in findings)
    assert any("10.9.8.81" in (r.get("assets") or []) for r in findings)
    assert any("hping3" in (r.get("labels") or []) for r in findings)
    not_claimed = (findings[0].get("extra") or {}).get("not_claimed") or []
    assert "open_port_observed" in not_claimed
    assert "vulnerability" in not_claimed
    assert "control_operating_effectiveness" in not_claimed


def test_pack_drop_hping3_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(HPING3 / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "hping3"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("host_only") is True
    assert honesty.get("open_ports_invented") is False
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(HPING3 / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(HPING3 / "evidence" / "note.md")
    sample = (HPING3 / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()
    assert "host-only" in sample.lower() or "no invented" in sample.lower()


def test_pack_drop_hping3_does_not_break_prior_adapters() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    httpx = inventory_nmap.parse_file(HTTPX / "assets.jsonl")
    uni = inventory_nmap.parse_file(UNI / "assets.jsonl")
    ssl = inventory_nmap.parse_file(SSL / "assets.jsonl")
    tlsx = inventory_nmap.parse_file(TLSX / "assets.jsonl")
    whatweb = inventory_nmap.parse_file(WHATWEB / "assets.jsonl")
    hping3 = inventory_nmap.parse_file(HPING3 / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.20" for r in httpx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8080" for r in httpx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.40" for r in uni if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "21" for r in uni if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.50" for r in ssl if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8443" for r in ssl if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.60" for r in tlsx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "853" for r in tlsx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.70" for r in whatweb if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8000" for r in whatweb if r["kind"] == "finding")
    assert all(r["name"] != "filesrv.corp.local" for r in hping3 if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in hping3 if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.20" for r in hping3 if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.40" for r in hping3 if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.50" for r in hping3 if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.60" for r in hping3 if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.70" for r in hping3 if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in hping3)
    assert all(not (r.get("extra") or {}).get("port") for r in hping3)


def test_pack_drop_onesixtyone_hosts_only() -> None:
    recs = inventory_nmap.parse_file(ONESIXTYONE / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    names = {r["name"] for r in assets}
    assert "10.9.8.90" in names
    assert "10.9.8.91" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    assert all("onesixtyone" in (r.get("labels") or []) for r in assets)
    assert findings == []
    assert all(not (r.get("extra") or {}).get("port") for r in recs)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_onesixtyone_observations_lift() -> None:
    recs = inventory_nmap.parse_file(ONESIXTYONE / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) >= 4
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("10.9.8.90" in t and "community" in t.lower() for t in titles)
    assert any("10.9.8.90" in t and "sysdescr" in t.lower() for t in titles)
    assert any("10.9.8.91" in t and "community" in t.lower() for t in titles)
    assert any("10.9.8.91" in t and "sysdescr" in t.lower() for t in titles)
    extras = [r.get("extra") or {} for r in findings]
    claims = {e.get("claim") for e in extras}
    assert "snmp_community_observed" in claims
    assert "sysdescr_observed" in claims
    assert "open_port_observed" not in claims
    assert all(not e.get("port") for e in extras)
    communities = {e.get("community") for e in extras if e.get("community")}
    assert "public" in communities
    assert "private" in communities
    sysdescrs = {
        str(e.get("sysDescr") or e.get("sysdescr") or "")
        for e in extras
        if e.get("sysDescr") or e.get("sysdescr")
    }
    assert any("Linux demo-snmp" in s for s in sysdescrs)
    assert any("Cisco IOS" in s for s in sysdescrs)
    assert any("10.9.8.90" in (r.get("assets") or []) for r in findings)
    assert any("10.9.8.91" in (r.get("assets") or []) for r in findings)
    assert any("onesixtyone" in (r.get("labels") or []) for r in findings)
    not_claimed = extras[0].get("not_claimed") or []
    assert "open_port_observed" in not_claimed
    assert "vulnerability" in not_claimed
    assert "control_operating_effectiveness" in not_claimed


def test_pack_drop_onesixtyone_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(ONESIXTYONE / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "onesixtyone"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("host_only") is True
    assert honesty.get("snmp_community") is True
    assert honesty.get("sysdescr") is True
    assert honesty.get("open_ports_invented") is False
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(ONESIXTYONE / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(ONESIXTYONE / "evidence" / "note.md")
    sample = (ONESIXTYONE / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()
    assert "community" in sample.lower() or "sysdescr" in sample.lower()
    assert "no invented" in sample.lower() or "tcp" in sample.lower()


def test_pack_drop_onesixtyone_does_not_break_prior_adapters() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    httpx = inventory_nmap.parse_file(HTTPX / "assets.jsonl")
    uni = inventory_nmap.parse_file(UNI / "assets.jsonl")
    ssl = inventory_nmap.parse_file(SSL / "assets.jsonl")
    tlsx = inventory_nmap.parse_file(TLSX / "assets.jsonl")
    whatweb = inventory_nmap.parse_file(WHATWEB / "assets.jsonl")
    hping3 = inventory_nmap.parse_file(HPING3 / "assets.jsonl")
    onesixtyone = inventory_nmap.parse_file(ONESIXTYONE / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.20" for r in httpx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8080" for r in httpx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.40" for r in uni if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "21" for r in uni if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.50" for r in ssl if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8443" for r in ssl if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.60" for r in tlsx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "853" for r in tlsx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.70" for r in whatweb if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8000" for r in whatweb if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.80" for r in hping3 if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in hping3)
    assert all(r["name"] != "filesrv.corp.local" for r in onesixtyone if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in onesixtyone if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.20" for r in onesixtyone if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.40" for r in onesixtyone if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.50" for r in onesixtyone if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.60" for r in onesixtyone if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.70" for r in onesixtyone if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.80" for r in onesixtyone if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in onesixtyone)
    assert all(not (r.get("extra") or {}).get("port") for r in onesixtyone)


def test_pack_drop_fping_hosts_only() -> None:
    recs = inventory_nmap.parse_file(FPING / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    names = {r["name"] for r in assets}
    assert "10.9.8.10" in names
    assert "10.9.8.11" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    assert all("fping" in (r.get("labels") or []) for r in assets)
    assert findings == []
    assert all(not (r.get("extra") or {}).get("port") for r in recs)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_fping_observations_lift() -> None:
    recs = inventory_nmap.parse_file(FPING / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) >= 2
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("10.9.8.10" in t and ("ICMP" in t or "host up" in t.lower()) for t in titles)
    assert any("10.9.8.11" in t and ("ICMP" in t or "host up" in t.lower()) for t in titles)
    claims = {(r.get("extra") or {}).get("claim") for r in findings}
    assert "host_up_observed" in claims
    assert "open_port_observed" not in claims
    assert all(not (r.get("extra") or {}).get("port") for r in findings)
    assert any("10.9.8.10" in (r.get("assets") or []) for r in findings)
    assert any("10.9.8.11" in (r.get("assets") or []) for r in findings)
    assert any("fping" in (r.get("labels") or []) for r in findings)
    not_claimed = (findings[0].get("extra") or {}).get("not_claimed") or []
    assert "open_port_observed" in not_claimed
    assert "vulnerability" in not_claimed
    assert "control_operating_effectiveness" in not_claimed


def test_pack_drop_fping_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(FPING / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "fping"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("host_only") is True
    assert honesty.get("open_ports_invented") is False
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(FPING / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(FPING / "evidence" / "note.md")
    sample = (FPING / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()
    assert "host-only" in sample.lower() or "no invented" in sample.lower()


def test_pack_drop_fping_does_not_break_prior_adapters() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    httpx = inventory_nmap.parse_file(HTTPX / "assets.jsonl")
    uni = inventory_nmap.parse_file(UNI / "assets.jsonl")
    ssl = inventory_nmap.parse_file(SSL / "assets.jsonl")
    tlsx = inventory_nmap.parse_file(TLSX / "assets.jsonl")
    whatweb = inventory_nmap.parse_file(WHATWEB / "assets.jsonl")
    hping3 = inventory_nmap.parse_file(HPING3 / "assets.jsonl")
    onesixtyone = inventory_nmap.parse_file(ONESIXTYONE / "assets.jsonl")
    fping = inventory_nmap.parse_file(FPING / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.20" for r in httpx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8080" for r in httpx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.40" for r in uni if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "21" for r in uni if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.50" for r in ssl if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8443" for r in ssl if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.60" for r in tlsx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "853" for r in tlsx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.70" for r in whatweb if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8000" for r in whatweb if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.80" for r in hping3 if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in hping3)
    assert any(r["name"] == "10.9.8.90" for r in onesixtyone if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in onesixtyone)
    assert all(r["name"] != "filesrv.corp.local" for r in fping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in fping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.20" for r in fping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.40" for r in fping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.50" for r in fping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.60" for r in fping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.70" for r in fping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.80" for r in fping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.90" for r in fping if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in fping)
    assert all(not (r.get("extra") or {}).get("port") for r in fping)


def test_pack_drop_naabu_hosts_and_services() -> None:
    recs = inventory_nmap.parse_file(NAABU / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    names = {r["name"] for r in assets}
    assert "10.9.8.30" in names
    assert "10.9.8.31" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    assert all("naabu" in (r.get("labels") or []) for r in assets)
    findings = [r for r in recs if r["kind"] == "finding"]
    ports = {str((r.get("extra") or {}).get("port") or "") for r in findings}
    assert {"80", "443", "22"} <= ports
    assert any("10.9.8.30" in (r.get("assets") or []) for r in findings)
    assert any("10.9.8.31" in (r.get("assets") or []) for r in findings)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_naabu_observations_lift() -> None:
    recs = inventory_nmap.parse_file(NAABU / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("80" in t for t in titles)
    assert any("443" in t for t in titles)
    assert any("22" in t for t in titles)
    claims = {(r.get("extra") or {}).get("claim") for r in findings}
    assert "open_port_observed" in claims
    assert any("10.9.8.30" in (r.get("assets") or []) for r in findings)
    assert any("naabu" in (r.get("labels") or []) for r in findings)
    not_claimed = (findings[0].get("extra") or {}).get("not_claimed") or []
    assert "vulnerability" in not_claimed
    assert "control_failure" in not_claimed
    assert "control_operating_effectiveness" in not_claimed
    assert "honeypot_validated" in not_claimed
    assert "riskready_post" in not_claimed


def test_pack_drop_naabu_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(NAABU / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "naabu"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("honeypot_validated") is False
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(NAABU / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(NAABU / "evidence" / "note.md")
    sample = (NAABU / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()
    assert "naabu" in sample.lower()


def test_pack_drop_naabu_does_not_break_prior_adapters() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    fping = inventory_nmap.parse_file(FPING / "assets.jsonl")
    naabu = inventory_nmap.parse_file(NAABU / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.10" for r in fping if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in fping)
    assert all(r["name"] != "filesrv.corp.local" for r in naabu if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in naabu if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.10" for r in naabu if r["kind"] == "asset")
    assert all((r.get("extra") or {}).get("port") != "445" for r in naabu if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.30" for r in naabu if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "80" for r in naabu if r["kind"] == "finding")


def test_pack_drop_nping_hosts_and_services() -> None:
    recs = inventory_nmap.parse_file(NPING / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    names = {r["name"] for r in assets}
    assert "10.9.8.32" in names
    assert "10.9.8.33" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    assert all("nping" in (r.get("labels") or []) for r in assets)
    findings = [r for r in recs if r["kind"] == "finding"]
    ports = {str((r.get("extra") or {}).get("port") or "") for r in findings}
    assert {"80", "443", "22"} <= ports
    assert any("10.9.8.32" in (r.get("assets") or []) for r in findings)
    assert any("10.9.8.33" in (r.get("assets") or []) for r in findings)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_nping_observations_lift() -> None:
    recs = inventory_nmap.parse_file(NPING / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("80" in t for t in titles)
    assert any("443" in t for t in titles)
    assert any("22" in t for t in titles)
    claims = {(r.get("extra") or {}).get("claim") for r in findings}
    assert "open_port_observed" in claims
    assert any("10.9.8.32" in (r.get("assets") or []) for r in findings)
    assert any("nping" in (r.get("labels") or []) for r in findings)
    not_claimed = (findings[0].get("extra") or {}).get("not_claimed") or []
    assert "vulnerability" in not_claimed
    assert "control_failure" in not_claimed
    assert "control_operating_effectiveness" in not_claimed
    assert "honeypot_validated" in not_claimed
    assert "riskready_post" in not_claimed


def test_pack_drop_nping_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(NPING / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "nping"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("honeypot_validated") is False
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    note = inventory_nmap.parse_file(NPING / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(NPING / "evidence" / "note.md")
    sample = (NPING / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()
    assert "nping" in sample.lower()


def test_pack_drop_nping_does_not_break_prior_adapters() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    fping = inventory_nmap.parse_file(FPING / "assets.jsonl")
    naabu = inventory_nmap.parse_file(NAABU / "assets.jsonl")
    nping = inventory_nmap.parse_file(NPING / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.10" for r in fping if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in fping)
    assert any(r["name"] == "10.9.8.30" for r in naabu if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "80" for r in naabu if r["kind"] == "finding")
    assert all(r["name"] != "filesrv.corp.local" for r in nping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in nping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.10" for r in nping if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.30" for r in nping if r["kind"] == "asset")
    assert all((r.get("extra") or {}).get("port") != "445" for r in nping if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.32" for r in nping if r["kind"] == "asset")
    assert any(r["name"] == "10.9.8.33" for r in nping if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "80" for r in nping if r["kind"] == "finding")


def test_pack_drop_nbtscan_hosts_only() -> None:
    recs = inventory_nmap.parse_file(NBTSCAN / "assets.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    names = {r["name"] for r in assets}
    assert "10.9.8.34" in names
    assert "10.9.8.35" in names
    assert all("covey" in (r.get("labels") or []) for r in assets)
    assert all("nbtscan" in (r.get("labels") or []) for r in assets)
    assert findings == []
    assert all(not (r.get("extra") or {}).get("port") for r in recs)
    assert all(not (r.get("extra") or {}).get("service") for r in recs)
    assert all(r["source"] == "inventory-nmap" for r in recs)
    assert all(r["ref_id"].startswith("NMAP-") for r in recs)


def test_pack_drop_nbtscan_observations_lift() -> None:
    recs = inventory_nmap.parse_file(NBTSCAN / "findings.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) >= 2
    assert all(r["source"] == "inventory-nmap" for r in findings)
    assert all(r["ref_id"].startswith("NMAP-") for r in findings)
    titles = [r["name"] for r in findings]
    assert any("10.9.8.34" in t and "SERVER" in t for t in titles)
    assert any("10.9.8.35" in t and "WORKSTATION" in t for t in titles)
    extras = [r.get("extra") or {} for r in findings]
    claims = {e.get("claim") for e in extras}
    assert "netbios_name_observed" in claims
    assert "open_port_observed" not in claims
    assert all(not e.get("port") for e in extras)
    assert all(not e.get("service") for e in extras)
    names = {e.get("netbios_name") for e in extras if e.get("netbios_name")}
    assert "SERVER" in names
    assert "WORKSTATION" in names
    assert any("10.9.8.34" in (r.get("assets") or []) for r in findings)
    assert any("10.9.8.35" in (r.get("assets") or []) for r in findings)
    assert any("nbtscan" in (r.get("labels") or []) for r in findings)
    not_claimed = extras[0].get("not_claimed") or []
    assert "open_port_observed" in not_claimed
    assert "control_failure" in not_claimed
    assert "control_operating_effectiveness" in not_claimed
    assert "honeypot_validated" in not_claimed
    assert "vulnerability" in not_claimed
    assert "riskready_post" in not_claimed


def test_pack_drop_nbtscan_meta_and_evidence() -> None:
    meta = inventory_nmap.parse_file(NBTSCAN / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    extra = evid[0].get("extra") or {}
    assert extra.get("adapter") == "nbtscan"
    assert extra.get("schema") == "evergreen.pack_drop.v1"
    honesty = extra.get("honesty") or {}
    assert honesty.get("surface_map") is True
    assert honesty.get("host_only") is True
    assert honesty.get("open_ports_invented") is False
    assert honesty.get("honeypot_validated") is False
    assert honesty.get("control_operating_effectiveness") is False
    ingest = extra.get("ingest") or {}
    assert ingest.get("riskready_post") is False
    counts = (NBTSCAN / "meta.json").read_text(encoding="utf-8")
    assert '"services": 0' in counts or '"services":0' in counts
    note = inventory_nmap.parse_file(NBTSCAN / "evidence" / "note.md")
    assert note
    assert all(r["kind"] == "evidence" for r in note)
    assert looks_like_pack_drop(NBTSCAN / "evidence" / "note.md")
    sample = (NBTSCAN / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "not a client" in sample.lower()
    assert "netbios" in sample.lower() or "nbtscan" in sample.lower()
    assert "no invented" in sample.lower() or "tcp" in sample.lower()


def test_pack_drop_nbtscan_does_not_break_prior_adapters() -> None:
    nmap = inventory_nmap.parse_file(DROP / "assets.jsonl")
    rust = inventory_nmap.parse_file(RUST / "assets.jsonl")
    httpx = inventory_nmap.parse_file(HTTPX / "assets.jsonl")
    uni = inventory_nmap.parse_file(UNI / "assets.jsonl")
    ssl = inventory_nmap.parse_file(SSL / "assets.jsonl")
    tlsx = inventory_nmap.parse_file(TLSX / "assets.jsonl")
    whatweb = inventory_nmap.parse_file(WHATWEB / "assets.jsonl")
    hping3 = inventory_nmap.parse_file(HPING3 / "assets.jsonl")
    onesixtyone = inventory_nmap.parse_file(ONESIXTYONE / "assets.jsonl")
    fping = inventory_nmap.parse_file(FPING / "assets.jsonl")
    naabu = inventory_nmap.parse_file(NAABU / "assets.jsonl")
    nping = inventory_nmap.parse_file(NPING / "assets.jsonl")
    nbtscan = inventory_nmap.parse_file(NBTSCAN / "assets.jsonl")
    assert any(r["name"] == "filesrv.corp.local" for r in nmap if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "445" for r in nmap if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.7" for r in rust if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "22" for r in rust if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.20" for r in httpx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8080" for r in httpx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.40" for r in uni if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "21" for r in uni if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.50" for r in ssl if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8443" for r in ssl if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.60" for r in tlsx if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "853" for r in tlsx if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.70" for r in whatweb if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "8000" for r in whatweb if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.80" for r in hping3 if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in hping3)
    assert any(r["name"] == "10.9.8.90" for r in onesixtyone if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in onesixtyone)
    assert any(r["name"] == "10.9.8.10" for r in fping if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in fping)
    assert any(r["name"] == "10.9.8.30" for r in naabu if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "80" for r in naabu if r["kind"] == "finding")
    assert any(r["name"] == "10.9.8.32" for r in nping if r["kind"] == "asset")
    assert any((r.get("extra") or {}).get("port") == "80" for r in nping if r["kind"] == "finding")
    assert all(r["name"] != "filesrv.corp.local" for r in nbtscan if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.7" for r in nbtscan if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.10" for r in nbtscan if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.20" for r in nbtscan if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.30" for r in nbtscan if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.32" for r in nbtscan if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.80" for r in nbtscan if r["kind"] == "asset")
    assert all(r["name"] != "10.9.8.90" for r in nbtscan if r["kind"] == "asset")
    assert all(r["kind"] != "finding" for r in nbtscan)
    assert all(not (r.get("extra") or {}).get("port") for r in nbtscan)
    assert any(r["name"] == "10.9.8.34" for r in nbtscan if r["kind"] == "asset")
    assert any(r["name"] == "10.9.8.35" for r in nbtscan if r["kind"] == "asset")


def test_pack_drop_docs_and_matrix() -> None:
    docs = (ROOT / "docs" / "COVEY_PACK_DROP.md").read_text(encoding="utf-8")
    assert "assets.jsonl" in docs
    assert "in/nmap/" in docs
    assert "CISO" in docs
    assert "PROVE_CISO.md" in docs or "prove_ciso" in docs.lower()
    assert "rustscan" in docs.lower()
    assert "httpx" in docs.lower()
    assert "unicornscan" in docs.lower()
    assert "sslscan" in docs.lower()
    assert "tlsx" in docs.lower()
    assert "whatweb" in docs.lower()
    assert "hping3" in docs.lower()
    assert "onesixtyone" in docs.lower()
    assert "fping" in docs.lower()
    assert "naabu" in docs.lower()
    assert "nping" in docs.lower()
    assert "nbtscan" in docs.lower()
    assert "evergreen.pack_drop.v1" in docs
    assert "fixtures/pack_drop/rustscan" in docs or "pack_drop/rustscan" in docs
    assert "fixtures/pack_drop/httpx" in docs or "pack_drop/httpx" in docs
    assert "fixtures/pack_drop/unicornscan" in docs or "pack_drop/unicornscan" in docs
    assert "fixtures/pack_drop/sslscan" in docs or "pack_drop/sslscan" in docs
    assert "fixtures/pack_drop/tlsx" in docs or "pack_drop/tlsx" in docs
    assert "fixtures/pack_drop/whatweb" in docs or "pack_drop/whatweb" in docs
    assert "fixtures/pack_drop/hping3" in docs or "pack_drop/hping3" in docs
    assert "fixtures/pack_drop/onesixtyone" in docs or "pack_drop/onesixtyone" in docs
    assert "fixtures/pack_drop/fping" in docs or "pack_drop/fping" in docs
    assert "fixtures/pack_drop/naabu" in docs or "pack_drop/naabu" in docs
    assert "fixtures/pack_drop/nping" in docs or "pack_drop/nping" in docs
    assert "fixtures/pack_drop/nbtscan" in docs or "pack_drop/nbtscan" in docs
    prove = (ROOT / "docs" / "PROVE_CISO.md").read_text(encoding="utf-8")
    assert "out/ciso-assistant" in prove
    assert "SAMPLE" in prove
    matrix = (ROOT / "docs" / "evidence_matrix.yaml").read_text(encoding="utf-8")
    assert "pack_in: identity" in matrix
    assert "pack_in: wazuh" in matrix
    assert "pack_in: cloud" in matrix
    assert "pack_in: easm" in matrix
    assert "pack_in: dns_email" in matrix
    assert "pack_in: nmap" in matrix
    assert "pack_in: vuln" in matrix
    assert "pack_in: honeypot" in matrix
    page = (ROOT / "docs" / "EVIDENCE_MATRIX.md").read_text(encoding="utf-8")
    assert "in/honeypot/" in page
    assert "in/dns_email/" in page
    assert "deception-sensor" in page


def test_pack_drop_no_live() -> None:
    src = (ROOT / "shared" / "pack_drop.py").read_text(encoding="utf-8")
    assert "import subprocess" not in src
    assert "socket.socket" not in src
    assert "/api/risks" not in src
