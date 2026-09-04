"""FARM_TOOL_BIN lab stubs: will_run true, dry invoke, no network."""

from __future__ import annotations

from pathlib import Path

import pytest

from dropbox.orchestrator.byo import farm_which
from dropbox.orchestrator.pipeline import external_stage, orchestrate
from dropbox.scanner_free import LAB_STUB_DIR, is_demo_lab_stub
from dropbox.scope import GateError, load_scope
from farm.adapters.catalog import select_stage_slots
from farm.adapters.stubs import run_slot

LAB_STUB_NAMES = ("nmap", "curl", "nessus", "nessuscli", "testssl", "testssl.sh", "lynis")
ALLOW_LAB = list(LAB_STUB_NAMES)

ROOT = Path(__file__).resolve().parents[1]


def test_lab_stubs_are_demo_shell_not_scanners() -> None:
    names = {p.name for p in LAB_STUB_DIR.iterdir() if p.is_file() and p.name != "README.md"}
    assert set(LAB_STUB_NAMES) <= names
    for name in LAB_STUB_NAMES:
        path = LAB_STUB_DIR / name
        assert is_demo_lab_stub(path)
        text = path.read_text(encoding="utf-8")
        assert "DEMO" in text
        assert "not a real scanner" in text.lower()
        assert "apt-get" not in text
        assert "wget " not in text
        raw = path.read_bytes()[:8]
        assert not raw.startswith(b"\x7fELF")
        assert not raw.startswith(b"MZ")


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
    assert farm_which("nessuscli") is None


def test_farm_tool_bin_deepen_and_external_adjacent_will_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FARM_TOOL_BIN", str(LAB_STUB_DIR))
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setenv("PATH", "/nonexistent-farm-lab-path")
    deep = select_stage_slots("deepen", ALLOW_LAB)
    nessus = next(row for row in deep["selected"] if row["slot"] == "nessus")
    nessuscli = next(row for row in deep["selected"] if row["slot"] == "nessuscli")
    assert nessus["will_run"] is True
    assert nessuscli["will_run"] is True
    ext_plan = select_stage_slots("external", ALLOW_LAB)
    testssl = next(row for row in ext_plan["selected"] if row["slot"] == "testssl.sh")
    assert testssl["will_run"] is True
    endp = select_stage_slots("endpoint", ALLOW_LAB)
    lynis = next(row for row in endp["selected"] if row["slot"] == "lynis")
    assert lynis["will_run"] is True
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    forced = external_stage(scope, dest_in=tmp_path / "in", live=True)
    assert forced["live"] is False
    curl = next(row for row in forced["slots"]["selected"] if row["slot"] == "curl")
    assert curl["will_run"] is False


def test_farm_tool_bin_dry_invoke_deepen_external_adjacent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FARM_TOOL_BIN", str(LAB_STUB_DIR))
    monkeypatch.setenv("PATH", "/nonexistent-farm-lab-path")
    work = tmp_path / "work" / "out"
    cases = (
        ("nessus", "app-01.demo.internal", "DEMO", "NessusClientData"),
        ("nessuscli", "app-01.demo.internal", "DEMO", "NessusClientData"),
        ("testssl.sh", "vpn.example.com", "DEMO", "fixture-shaped"),
        ("lynis", ".", "DEMO", "Lynis"),
    )
    for slot, target, *needles in cases:
        dest = work / f"{slot.replace('.', '_')}.out"
        result = run_slot(slot, dest, ALLOW_LAB, target=target, live=True)
        assert result["ran"] is True, slot
        assert result["subprocess"] is True, slot
        blob = dest.read_text(encoding="utf-8")
        for needle in needles:
            assert needle in blob, (slot, needle)


def test_farm_which_refuses_locked_binaries_dropped_in_tool_bin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FARM_TOOL_BIN is not a back door for refused scanners."""
    from dropbox.orchestrator.byo import run_allowed, which_allowed
    from dropbox.scope import LICENSE_LOCK_SPAWN

    tool_bin = tmp_path / "tool-bin"
    tool_bin.mkdir()
    locked = (
        "nuclei",
        "openvas",
        "wazuh",
        "osquery",
        "bloodhound",
        "pingcastle",
        "smbmap",
        "zmap",
        "hexstrike",
    )
    for name in locked:
        path = tool_bin / name
        path.write_text("#!/bin/sh\necho SHOULD-NOT-RUN\n", encoding="utf-8")
        path.chmod(0o755)
    monkeypatch.setenv("FARM_TOOL_BIN", str(tool_bin))
    monkeypatch.setenv("PATH", str(tool_bin))
    for name in locked:
        assert name in LICENSE_LOCK_SPAWN
        assert farm_which(name) is None
        exe, reason = which_allowed(name, [name])
        assert exe is None
        assert "LICENSE-LOCK" in reason
        with pytest.raises(GateError, match="LICENSE-LOCK"):
            run_allowed([str(tool_bin / name), "--help"], tmp_path / f"{name}.out", 2, allow_tools=[name])


def test_repo_tool_bin_ships_no_scanner_binaries() -> None:
    root = ROOT / "farm" / "tool-bin"
    forbidden_ext = {".deb", ".rpm", ".exe", ".nbin", ".nasl"}
    for path in root.rglob("*"):
        if not path.is_file() or path.name == "README.md":
            continue
        assert path.suffix.lower() not in forbidden_ext, path
        raw = path.read_bytes()[:8]
        assert not raw.startswith(b"\x7fELF"), path
        assert not raw.startswith(b"MZ"), path


def test_farm_tool_bin_license_lock_still_refuses_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FARM_TOOL_BIN", str(LAB_STUB_DIR))
    monkeypatch.setenv("PATH", "/nonexistent-farm-lab-path")
    dest = tmp_path / "work" / "out" / "bad.out"
    for name in ("nuclei", "openvas"):
        with pytest.raises(GateError, match="LICENSE-LOCK"):
            run_slot(name, dest, ALLOW_LAB + [name], target="10.20.30.5", live=True)
        assert farm_which(name) is None


def test_farm_toolbin_lab_script_asserts_nmap_curl(tmp_path: Path) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "farm_toolbin_lab", ROOT / "scripts" / "farm_toolbin_lab.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    stamp = mod.farm_toolbin_lab(ROOT)
    assert stamp["status"] == "pass"
    assert stamp["live"] is False
    assert stamp["will_run"]["nmap"] is True
    assert stamp["will_run"]["curl"] is True
    assert stamp["demo"] is True
