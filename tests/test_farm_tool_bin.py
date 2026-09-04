"""FARM_TOOL_BIN lab stubs: will_run true, dry invoke, no network."""

from __future__ import annotations

from pathlib import Path

import pytest

from dropbox.orchestrator.byo import farm_which
from dropbox.orchestrator.pipeline import external_stage, orchestrate
from dropbox.scanner_free import LAB_STUB_DIR, is_demo_lab_stub
from dropbox.scope import load_scope
from farm.adapters.catalog import select_stage_slots
from farm.adapters.stubs import run_slot

ROOT = Path(__file__).resolve().parents[1]


def test_lab_stubs_are_demo_shell_not_scanners() -> None:
    names = {p.name for p in LAB_STUB_DIR.iterdir() if p.is_file() and p.name != "README.md"}
    assert {"nmap", "curl"} <= names
    for name in ("nmap", "curl"):
        path = LAB_STUB_DIR / name
        assert is_demo_lab_stub(path)
        text = path.read_text(encoding="utf-8")
        assert "DEMO" in text
        assert "not a real scanner" in text.lower()
        assert "apt-get" not in text
        assert "wget " not in text


def test_farm_tool_bin_makes_plan_will_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FARM_TOOL_BIN", str(LAB_STUB_DIR))
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.delenv("PATH", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent-farm-lab-path")
    assert farm_which("nmap")
    assert farm_which("nmap").endswith("/lab/nmap")
    assert farm_which("curl")
    assert farm_which("nuclei") is None
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    disc = select_stage_slots("discover", scope.allow_tools)
    nmap = next(row for row in disc["selected"] if row["slot"] == "nmap")
    assert nmap["will_run"] is True
    assert nmap["on_path"] is True
    summary = orchestrate(scope, live=False)
    plan_nmap = next(row for row in summary["slots"]["discover"]["selected"] if row["slot"] == "nmap")
    assert plan_nmap["will_run"] is True
    ext = external_stage(scope, dest_in=tmp_path / "in", live=True)
    assert ext["live"] is False
    curl = next(row for row in ext["slots"]["selected"] if row["slot"] == "curl")
    assert curl["will_run"] is False


def test_farm_tool_bin_dry_invoke_writes_work_out_no_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FARM_TOOL_BIN", str(LAB_STUB_DIR))
    monkeypatch.setenv("PATH", "/nonexistent-farm-lab-path")
    work = tmp_path / "work" / "out"
    nmap_dest = work / "discover.gnmap"
    curl_dest = work / "headers.txt"
    allow = ["nmap", "curl"]
    nmap = run_slot("nmap", nmap_dest, allow, target="10.20.30.0/24", live=True)
    assert nmap["ran"] is True
    assert nmap["subprocess"] is True
    blob = nmap_dest.read_text(encoding="utf-8")
    assert "DEMO" in blob
    assert "Host: 10.20.30.5" in blob
    assert "app-01.demo.internal" in blob
    curl = run_slot("curl", curl_dest, allow, target="https://vpn.example.com", live=True)
    assert curl["ran"] is True
    headers = curl_dest.read_text(encoding="utf-8")
    assert "DEMO" in headers
    assert "HTTP/1.1 200" in headers
    assert "X-GRC-Demo: true" in headers


def test_farm_which_ignores_tool_bin_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FARM_TOOL_BIN", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent-farm-lab-path")
    assert farm_which("nmap") is None
    assert farm_which("curl") is None
