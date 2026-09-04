from __future__ import annotations

from pathlib import Path

from dropbox.orchestrator.cli import main
from dropbox.orchestrator.plan import build_plan, deepen_batches
from dropbox.orchestrator.run import run_stages
from dropbox.orchestrator.scope import load_scope, parse_scope
from dropbox.orchestrator.workers import DESTROYED

ROOT = Path(__file__).resolve().parents[1]


def test_plan_without_binaries() -> None:
    scope = load_scope(ROOT / "dropbox" / "SCOPE.example.yaml")
    plan = build_plan(scope)
    assert plan["stages"][0] == "plan"
    assert "discover" in plan["stages"]
    assert plan["deepen_batch_size"] <= 5
    assert plan["deepen_batch_size"] >= 2
    assert plan["shard_count"] >= 1


def test_unsigned_refuses_live() -> None:
    scope = parse_scope(
        {
            "client_legal_name": "X",
            "named_contact": "Y",
            "consent_attested": True,
            "signed": False,
            "profiles": "internal",
            "internal": {"hosts": ["10.1.1.1"]},
            "allow_tools": ["nmap"],
            "integrity": {"refuse_if_unsigned": True, "refuse_if_empty_targets": True},
        }
    )
    result = run_stages(scope, stage="discover", fixture=False)
    assert result["ok"] is False
    assert result["refused"] is True
    assert "unsigned" in result["reason"]


def test_empty_targets_refuse_live() -> None:
    scope = parse_scope(
        {
            "client_legal_name": "X",
            "named_contact": "Y",
            "consent_attested": True,
            "signed": True,
            "profiles": "internal",
            "allow_tools": ["nmap"],
            "integrity": {"refuse_if_unsigned": True, "refuse_if_empty_targets": True},
        }
    )
    result = run_stages(scope, stage="all", fixture=False)
    assert result["refused"] is True


def test_deepen_batch_size_cap() -> None:
    scope = parse_scope(
        {
            "client_legal_name": "X",
            "named_contact": "Y",
            "consent_attested": True,
            "signed": True,
            "profiles": "internal",
            "internal": {"hosts": ["h1", "h2", "h3", "h4", "h5", "h6", "h7"]},
            "allow_tools": ["nmap"],
            "batch": {"deepen_batch_size": 99},
        }
    )
    batches = deepen_batches(scope.internal_hosts, scope)
    assert all(1 < len(b) <= 5 or len(b) <= 5 for b in batches)
    assert max(len(b) for b in batches) <= 5
    assert scope.batch.deepen_batch_size == 99
    assert build_plan(scope, live_hosts=scope.internal_hosts)["deepen_batch_size"] == 5


def test_fixture_run_destroys_workers(tmp_path: Path) -> None:
    DESTROYED.clear()
    scope = load_scope(ROOT / "dropbox" / "SCOPE.example.yaml")
    result = run_stages(scope, stage="all", fixture=True, out_dir=tmp_path, run_pack=False)
    assert result["ok"] is True
    assert any(e.get("stage") == "destroy_discover_workers" for e in result["log"])
    assert any(e.get("stage") == "destroy_deepen_workers" for e in result["log"])
    assert (tmp_path / "discover.json").exists()
    assert (tmp_path / "ingest-manifest.json").exists()
    manifest = (tmp_path / "ingest-manifest.json").read_text(encoding="utf-8")
    assert "not a client estate" in manifest or "demo fixtures" in manifest


def test_cli_plan_exit_0() -> None:
    assert main(["plan", "--scope", str(ROOT / "dropbox" / "SCOPE.example.yaml")]) == 0
