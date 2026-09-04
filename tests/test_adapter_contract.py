"""BYO adapter contract: stub PATH binaries, never invoke non-allowlisted."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from dropbox.orchestrator.farm import Farm
from dropbox.orchestrator.pipeline import collect_discover_hosts, deepen_stage, discover_stage
from dropbox.scope import load_scope

ROOT = Path(__file__).resolve().parents[1]


def _stub(bin_dir: Path, name: str, marker: Path, payload: str) -> Path:
    script = bin_dir / name
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "{name}" >> "{marker}"\n'
        f"cat <<'EOF'\n{payload}\nEOF\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def test_allowlisted_live_discover_invokes_stub(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    _stub(
        bin_dir,
        "nmap",
        marker,
        "# Nmap DEMO stub\nHost: 10.20.30.5 (app-01.demo.internal) Status: Up\n",
    )
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + "/usr/bin")
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm(max_workers=scope.max_workers)
    plan = discover_stage(scope, farm, live=True)
    assert plan["mode"] == "live"
    assert marker.is_file()
    assert "nmap" in marker.read_text(encoding="utf-8")
    gnmaps = list((tmp_path / "orch" / "discover").glob("*.gnmap"))
    assert gnmaps
    hosts = collect_discover_hosts(tmp_path / "orch" / "discover")
    assert "app-01.demo.internal" in hosts
    ran = [w for w in plan["workers"] if w["status"] == "ran"]
    assert ran
    assert len(ran) <= scope.max_workers


def test_missing_binary_stays_plan_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    marker = tmp_path / "invoked.txt"
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm(max_workers=scope.max_workers)
    plan = discover_stage(scope, farm, live=True)
    assert plan["mode"] == "plan"
    assert plan["tool_ready"] is False
    assert "not on PATH" in plan["skip_reason"]
    assert not marker.exists()
    assert not any(w["status"] == "ran" for w in plan["workers"])


def test_non_allowlisted_never_invoked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    _stub(bin_dir, "nmap", marker, "SHOULD-NOT-RUN\n")
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + "/usr/bin")
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    scope.allow_tools = [t for t in scope.allow_tools if t != "nmap"]
    farm = Farm(max_workers=scope.max_workers)
    plan = discover_stage(scope, farm, live=True)
    assert plan["mode"] == "plan"
    assert plan["tool_ready"] is False
    assert not marker.exists() or "nmap" not in marker.read_text(encoding="utf-8")


def test_deepen_hosts_only_discover_or_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm(max_workers=scope.max_workers)
    scope.deepen_hosts = []
    gated = deepen_stage(scope, farm, live_hosts=[], live=False)
    assert gated["mode"] == "gated"
    assert "no discover" in gated["skip_reason"] or "no in-SCOPE" in gated["skip_reason"]
    picked = deepen_stage(scope, farm, live_hosts=["app-01.demo.internal"], live=False)
    assert picked["hosts"] == ["app-01.demo.internal"]
    assert picked["host_source"] == "discover"
    assert "127.0.0.1" not in picked["hosts"]


def test_concurrent_deepen_respects_max_workers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    _stub(bin_dir, "nessus", marker, "DEMO nessus stub\n")
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + "/usr/bin")
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    scope.max_workers = 2
    scope.deepen_batch = 2
    scope.deepen_hosts = [f"h{i}.demo.internal" for i in range(8)]
    scope.internal_hosts = list(scope.deepen_hosts)
    farm = Farm(max_workers=2)
    plan = deepen_stage(scope, farm, live=True)
    assert plan["batch_count"] == 4
    ran = [w for w in plan["workers"] if w["status"] == "ran"]
    assert len(ran) <= 2
    if marker.is_file():
        assert marker.read_text(encoding="utf-8").count("nessus") <= 2
