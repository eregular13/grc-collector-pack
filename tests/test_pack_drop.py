"""Covey pack_drop on the existing inventory-nmap lane."""

from __future__ import annotations

from pathlib import Path

from collectors import inventory_nmap
from shared.control_map import map_finding
from shared.pack_drop import looks_like_pack_drop

ROOT = Path(__file__).resolve().parents[1]
DROP = ROOT / "fixtures" / "pack_drop" / "nmap"
RUST = ROOT / "fixtures" / "pack_drop" / "rustscan"
HTTPX = ROOT / "fixtures" / "pack_drop" / "httpx"
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


def test_pack_drop_docs_and_matrix() -> None:
    docs = (ROOT / "docs" / "COVEY_PACK_DROP.md").read_text(encoding="utf-8")
    assert "assets.jsonl" in docs
    assert "in/nmap/" in docs
    assert "CISO" in docs
    assert "PROVE_CISO.md" in docs or "prove_ciso" in docs.lower()
    assert "rustscan" in docs.lower()
    assert "httpx" in docs.lower()
    assert "evergreen.pack_drop.v1" in docs
    assert "fixtures/pack_drop/rustscan" in docs or "pack_drop/rustscan" in docs
    assert "fixtures/pack_drop/httpx" in docs or "pack_drop/httpx" in docs
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
