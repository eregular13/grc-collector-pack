"""Farm ↔ orchestrator slot selection. No catalog inflation. No LICENSE-LOCK live."""

from __future__ import annotations

from pathlib import Path

import pytest

from dropbox.orchestrator.farm import Farm
from dropbox.orchestrator.pipeline import deepen_stage, discover_stage, orchestrate
from dropbox.scope import GateError, load_scope
from farm.adapters.catalog import (
    FILE_DROP_ONLY,
    LICENSE_LOCK_LIVE,
    refuse_live_slot,
    select_stage_slots,
)
from farm.adapters.stubs import argv_for, run_slot

ROOT = Path(__file__).resolve().parents[1]


def test_plan_lists_slots_per_stage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setattr("dropbox.orchestrator.pipeline._which", lambda name: None)
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    summary = orchestrate(scope, live=False)
    slots = summary["slots"]
    assert set(slots) == {"discover", "deepen", "external"}
    disc = slots["discover"]["selected"]
    names = {row["slot"] for row in disc}
    assert "nmap" in names
    assert "nuclei" not in names
    assert "nessus" not in names
    nmap = next(row for row in disc if row["slot"] == "nmap")
    assert nmap["will_run"] is False
    assert "PATH" in nmap["reason"]
    deep = {row["slot"] for row in slots["deepen"]["selected"]}
    assert "nessus" in deep
    assert "openvas" not in deep
    ext = {row["slot"] for row in slots["external"]["selected"]}
    assert "curl" in ext
    assert summary["discover"]["slots"]["stage"] == "discover"
    assert summary["deepen"]["slots"]["stage"] == "deepen"


def test_select_refuses_nuclei_openvas_even_if_named() -> None:
    plan = select_stage_slots("deepen", ["nessus", "nuclei", "openvas"], which=lambda n: f"/stub/{n}")
    selected = {row["slot"] for row in plan["selected"]}
    skipped = {row["slot"]: row for row in plan["skipped"]}
    assert "nessus" in selected
    assert "nuclei" not in selected
    assert "openvas" not in selected
    assert "LICENSE-LOCK" in skipped["nuclei"]["reason"]
    assert "LICENSE-LOCK" in skipped["openvas"]["reason"]
    assert refuse_live_slot("nuclei") 
    assert refuse_live_slot("openvas")
    for name in FILE_DROP_ONLY:
        assert refuse_live_slot(name)
    for name in ("nuclei", "openvas"):
        with pytest.raises(GateError, match="LICENSE-LOCK"):
            argv_for(name, f"/stub/{name}", "10.20.30.0/24", 8)


def test_live_discover_uses_path_invoke_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    for name in ("nmap", "nuclei", "openvas", "nikto"):
        script = bin_dir / name
        script.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "{name}" >> "{marker}"\n'
            "printf 'Host: 10.20.30.5 (app-01.demo.internal) Status: Up\\n'\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm(max_workers=scope.max_workers)
    plan = discover_stage(scope, farm, live=True)
    assert plan["mode"] == "live"
    assert plan["tool"] == "nmap"
    assert plan["slots"]["primary"] == "nmap"
    assert all(row["slot"] != "nuclei" for row in plan["slots"]["selected"])
    invoked = marker.read_text(encoding="utf-8")
    assert "nmap" in invoked
    assert "nuclei" not in invoked
    assert "openvas" not in invoked
    assert "nikto" not in invoked


def test_live_deepen_only_deepen_invoke_on_named_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    for name in ("nessus", "nuclei", "openvas"):
        script = bin_dir / name
        script.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "{name}" >> "{marker}"\n'
            "printf 'DEMO nessus stub\\n'\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm(max_workers=scope.max_workers)
    plan = deepen_stage(scope, farm, live_hosts=["app-01.demo.internal"], live=True)
    assert plan["host_source"] == "discover"
    assert plan["hosts"] == ["app-01.demo.internal"]
    assert plan["tool"] == "nessus"
    skipped = {row["slot"] for row in plan["slots"]["skipped"]}
    assert "nuclei" in skipped and "openvas" in skipped
    invoked = marker.read_text(encoding="utf-8")
    assert "nessus" in invoked
    assert "nuclei" not in invoked
    assert "openvas" not in invoked
    dest = tmp_path / "x.out"
    for name in ("nuclei", "openvas"):
        with pytest.raises(GateError, match="LICENSE-LOCK"):
            run_slot(name, dest, [name], live=True)


def test_missing_discover_slot_has_explicit_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setattr("dropbox.orchestrator.pipeline._which", lambda name: None)
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm(max_workers=1)
    plan = discover_stage(scope, farm, live=True)
    assert plan["mode"] == "plan"
    assert plan["tool_ready"] is False
    nmap = next(row for row in plan["slots"]["selected"] if row["slot"] == "nmap")
    assert nmap["will_run"] is False
    assert "PATH" in nmap["reason"]
    assert "PATH" in plan["skip_reason"]
    rust = next(row for row in plan["slots"]["skipped"] if row["slot"] == "rustscan")
    assert rust["state"] == "not-allowlisted"
    assert LICENSE_LOCK_LIVE
