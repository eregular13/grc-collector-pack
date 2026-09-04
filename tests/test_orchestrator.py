"""Orchestrator sharding math and fail-closed plan-only (no Nmap/Nessus)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from dropbox.orchestrator.farm import Farm
from dropbox.orchestrator.pipeline import deepen_stage, discover_stage, ingest_stage, orchestrate
from dropbox.orchestrator.shard import batch_hosts, shard_cidrs
from dropbox.scope import GateError, load_scope

ROOT = Path(__file__).resolve().parents[1]


def test_shard_slash22_is_four_slash24() -> None:
    shards = shard_cidrs(["10.0.0.0/22"], 24)
    assert shards == ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]


def test_shard_already_slash24_is_one_job() -> None:
    assert shard_cidrs(["192.168.10.0/24"], 24) == ["192.168.10.0/24"]


def test_shard_slash16_is_256_jobs_not_one_scanner() -> None:
    shards = shard_cidrs(["10.1.0.0/16"], 24)
    assert len(shards) == 256
    assert shards[0] == "10.1.0.0/24"
    assert shards[-1] == "10.1.255.0/24"


def test_shard_slash8_count_is_65536() -> None:
    shards = shard_cidrs(["10.0.0.0/8"], 24)
    assert len(shards) == 65536
    assert shards[0] == "10.0.0.0/24"
    assert shards[256] == "10.1.0.0/24"


def test_shard_demo_scope_is_three_jobs() -> None:
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    shards = shard_cidrs(scope.internal_cidrs, scope.discover_prefix)
    assert shards == ["10.20.30.0/24", "10.20.31.0/24", "192.168.10.0/24"]


def test_batch_hosts_three() -> None:
    batches = batch_hosts(["a", "b", "c", "d", "e"], 3)
    assert batches == [["a", "b", "c"], ["d", "e"]]


def test_batch_rejects_one_host_size() -> None:
    with pytest.raises(ValueError):
        batch_hosts(["a"], 1)


def test_discover_plan_only_without_nmap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setattr("dropbox.orchestrator.pipeline._which", lambda name: None)
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm()
    plan = discover_stage(scope, farm, live=True)
    assert plan["mode"] == "plan"
    assert plan["shard_count"] == 3
    assert plan["tool_ready"] is False
    assert "not on PATH" in plan["skip_reason"]
    assert plan["discover_workers_alive"] == 0
    assert plan["discover_workers_destroyed"] == 3
    assert farm.alive("discover") == []
    assert (tmp_path / "orch" / "discover" / "plan.json").is_file()
    raw = (tmp_path / "orch" / "discover" / "plan.json").read_text(encoding="utf-8")
    assert "nmap -sn" not in raw


def test_discover_refuses_to_run_nmap_if_not_allowlisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setattr("dropbox.orchestrator.pipeline._which", lambda name: "/usr/bin/nmap")
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    scope.allow_tools = [t for t in scope.allow_tools if t != "nmap"]
    farm = Farm()
    plan = discover_stage(scope, farm, live=True)
    assert plan["mode"] == "plan"
    assert plan["tool_ready"] is False
    assert farm.alive() == []


def test_deepen_plan_only_without_nessus(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setattr("dropbox.orchestrator.pipeline._which", lambda name: None)
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm()
    plan = deepen_stage(scope, farm, live=True)
    assert plan["mode"] == "plan"
    assert plan["batch_count"] == 2
    assert plan["batches"][0] == ["127.0.0.1", "dropbox-lab.local", "app-01.demo.internal"]
    assert (tmp_path / "orch" / "deepen" / "BYO-NESSUS.placeholder").is_file()
    assert "does not download Nessus" in (tmp_path / "orch" / "deepen" / "BYO-NESSUS.placeholder").read_text()


def test_orchestrate_cli_plan_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    proc = subprocess.run(
        ["python3", "-m", "dropbox", "orchestrate", "--scope", str(ROOT / "dropbox" / "SCOPE.yaml")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(proc.stdout[proc.stdout.find("{") :])
    assert data["discover"]["mode"] == "plan"
    assert data["discover"]["alive"] == 0
    assert data["discover"]["shard_count"] == 3
    assert data["deepen"]["mode"] == "plan"


def test_orchestrate_requires_scope_gate(tmp_path: Path) -> None:
    proc = subprocess.run(
        ["python3", "-m", "dropbox", "orchestrate", "--scope", str(tmp_path / "none.yaml")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "SCOPE gate" in proc.stderr


def test_no_nessus_plugins_in_repo() -> None:
    hits = []
    for path in (ROOT / "dropbox").rglob("*"):
        if path.is_file() and path.suffix.lower() in {".nasl", ".nbin"}:
            hits.append(path)
    assert hits == []


def test_ingest_copies_gnmap_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    orch = tmp_path / "orch"
    (orch / "discover").mkdir(parents=True)
    (orch / "discover" / "shard.gnmap").write_text(
        "Host: 10.20.30.5 (app-01.demo.internal)\tPorts: 22/open/tcp//ssh///\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(orch))
    dest = tmp_path / "in"
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    marker = ingest_stage(scope, dest_in=dest)
    copied = dest / "nmap" / "dropbox-discover-shard.gnmap"
    assert copied.is_file()
    assert str(copied) in marker["copied"]
