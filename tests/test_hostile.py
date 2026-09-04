from __future__ import annotations

from pathlib import Path

from collectors import cloud_prowler, grc_loader, host_wazuh, inventory_nmap, vuln_scan
from shared.io_util import write_canonical

ROOT = Path(__file__).resolve().parents[1]


def test_truncated_json_falls_back(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("FIXTURES_DIR", str(ROOT / "fixtures" / "demo"))
    (tmp_path / "in" / "cloud").mkdir(parents=True)
    (tmp_path / "in" / "cloud" / "bad.json").write_text('{"findings":[{"CheckID":', encoding="utf-8")
    from shared.io_util import run_collector

    recs = run_collector("cloud-prowler", (".json",), cloud_prowler.parse_file)
    assert recs, "truncated JSON should fall back to fixtures"


def test_nuclei_blank_line(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("FIXTURES_DIR", str(ROOT / "fixtures" / "demo"))
    folder = tmp_path / "in" / "vuln"
    folder.mkdir(parents=True)
    folder.joinpath("nuclei.jsonl").write_text(
        '{"template-id":"CVE-2021-44228","info":{"name":"x","severity":"critical"},"host":"h"}\n\n{"template-id":"CVE-2023-44487","info":{"name":"y","severity":"high"},"host":"h2"}\n',
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(folder / "nuclei.jsonl")
    assert len([r for r in recs if r["kind"] == "finding"]) >= 2


def test_nmap_without_hostnames(tmp_path) -> None:
    xml = """<?xml version="1.0"?><nmaprun>
      <host><status state="up"/><address addr="10.9.9.9" addrtype="ipv4"/>
      <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
      </host></nmaprun>"""
    p = tmp_path / "scan.xml"
    p.write_text(xml, encoding="utf-8")
    recs = inventory_nmap.parse_file(p)
    names = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "10.9.9.9" in names


def test_double_loader_no_dupes(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    rec = {
        "kind": "asset",
        "source": "easm",
        "ref_id": "EASM-asset-dup",
        "name": "Dup.Host",
        "description": "d",
        "severity": "info",
        "status": "identified",
        "category": "external-host",
        "assets": ["Dup.Host"],
        "labels": ["demo"],
        "collected_at": "2026-01-01T00:00:00Z",
        "extra": {"asset_type": "PR"},
    }
    write_canonical("easm", [rec, rec])
    grc_loader.load()
    grc_loader.load()
    text = (tmp_path / "out" / "ciso-assistant" / "assets.csv").read_text(encoding="utf-8")
    assert text.count("Dup.Host") == 1


def test_fleet_host_without_hostname(tmp_path) -> None:
    p = tmp_path / "fleet.json"
    p.write_text('{"hosts":[{"status":"offline","primary_ip":"10.1.1.1"},{"hostname":"ok-host","status":"online"}]}', encoding="utf-8")
    recs = host_wazuh.parse_file(p)
    names = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "ok-host" in names
    assert "10.1.1.1" not in names
    assert all(r.get("name") for r in recs)
