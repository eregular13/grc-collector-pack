"""Covey pack_drop on the existing inventory-nmap lane."""

from __future__ import annotations

from pathlib import Path

from collectors import inventory_nmap
from shared.control_map import map_finding
from shared.pack_drop import looks_like_pack_drop

ROOT = Path(__file__).resolve().parents[1]
DROP = ROOT / "fixtures" / "pack_drop" / "nmap"
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


def test_pack_drop_docs_and_matrix() -> None:
    docs = (ROOT / "docs" / "COVEY_PACK_DROP.md").read_text(encoding="utf-8")
    assert "assets.jsonl" in docs
    assert "in/nmap/" in docs
    assert "CISO" in docs
    assert "PROVE_CISO.md" in docs or "prove_ciso" in docs.lower()
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
