"""Operator MCP stub: SCOPE-gated, no Hexstrike/exploit API."""

from __future__ import annotations

from pathlib import Path

import pytest

from dropbox.mcp_stub import OPERATOR_TOOLS, dispatch, refuse_attack_name
from dropbox.scope import GateError

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "dropbox" / "SCOPE.yaml"


def test_architecture_docs_three_layers() -> None:
    text = (ROOT / "dropbox" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "Layer A" in text and "Layer B" in text and "Layer C" in text
    assert "parse-only" in text.lower()
    assert "does **not** turn Layer C" in text or "does not turn Layer C" in text.lower()
    assert "100 embedded binaries" in text or "not 100 embedded" in text.lower()
    hexstrike = (ROOT / "dropbox" / "HEXSTRIKE.md").read_text(encoding="utf-8")
    assert "Metasploit" in hexstrike
    assert "AIExploitGenerator" in hexstrike
    assert "submodule" in hexstrike.lower()
    iface = (ROOT / "dropbox" / "operator_mcp_interface.md").read_text(encoding="utf-8")
    for name in OPERATOR_TOOLS:
        assert name in iface
    assert ".cursor/mcp.json" in iface
    assert "claude_desktop_config.json" in iface
    assert "scripts/mcp_stdio.sh" in iface
    assert "will_run" in iface
    farm_op = (ROOT / "farm" / "OPERATOR.md").read_text(encoding="utf-8")
    assert ".cursor/mcp.json" in farm_op
    assert "claude_desktop_config.json" in farm_op
    assert "farm_toolbin_status" in farm_op
    assert "evergreen_assessment_mcp" in farm_op
    assert "check_scope" in farm_op
    assert "license_guard" in farm_op
    assert "TypeScript refuse" in farm_op
    assert "evergreen_assessment_mcp" in hexstrike
    assert "check_scope" in hexstrike
    assert "license_guard" in hexstrike
    assert "TypeScript refuse" in hexstrike
    assert "evergreen_assessment_mcp" in iface
    assert "check_scope" in iface
    assert "license_guard" in iface
    for folder in (ROOT, ROOT / "dropbox", ROOT / "farm", ROOT / "scripts"):
        assert not list(folder.glob("*.ts"))
        assert not list(folder.glob("*refuse*matrix*"))


def test_no_hexstrike_submodule() -> None:
    assert not (ROOT / "hexstrike-ai").exists()
    gitmodules = ROOT / ".gitmodules"
    if gitmodules.is_file():
        assert "hexstrike" not in gitmodules.read_text(encoding="utf-8").lower()
    blob = (ROOT / "dropbox" / "mcp_stub.py").read_text(encoding="utf-8")
    assert "AIExploitGenerator" in blob
    assert "Hexstrike" in blob
    assert "does not submodule hexstrike-ai" in blob


def test_refuse_attack_names() -> None:
    for name in (
        "AIExploitGenerator",
        "metasploit",
        "msfconsole",
        "exploit-chain",
        "hexstrike_run",
    ):
        with pytest.raises(GateError, match="refuses"):
            refuse_attack_name(name)
        with pytest.raises(GateError, match="refuses"):
            dispatch(name)


def test_unknown_operator_tool_refused() -> None:
    with pytest.raises(GateError, match="unknown operator tool"):
        dispatch("nuke_the_lan")


def test_mcp_cli_scope_status() -> None:
    import subprocess

    proc = subprocess.run(
        ["python3", "-m", "dropbox", "mcp", "scope_status", "--scope", str(SCOPE)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "scope_status" in proc.stdout
    assert "path_matrix" in proc.stdout


def test_scope_status_and_status_tools() -> None:
    st = dispatch("scope_status", scope_path=SCOPE)
    assert st["tool"] == "scope_status"
    assert "DEMO" in st["client"]
    assert st["max_workers"] == 2
    assert st["path_matrix"]
    assert any(row["tool"] == "nmap" for row in st["path_matrix"])
    obs = dispatch("orchestrator_status", scope_path=SCOPE)
    assert "discover (quiet)" in obs["stage_graph"]
    assert obs["tool"] == "orchestrator_status"


def test_stage_deepen_requires_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib

    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    att = tmp_path / "consent.md"
    att.write_text("ok\n", encoding="utf-8")
    digest = hashlib.sha256(att.read_bytes()).hexdigest()
    scope = tmp_path / "SCOPE.yaml"
    scope.write_text(
        "client:\n  name: X\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n"
        "orchestrator:\n  stages:\n    discover: true\n    deepen: false\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="stages.deepen"):
        dispatch("stage_deepen", scope_path=scope)


def test_mcp_serve_lists_tools_no_hexstrike() -> None:
    import subprocess

    proc = subprocess.run(
        ["python3", "-m", "dropbox.mcp_stub", "serve"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = __import__("json").loads(proc.stdout)
    names = [t["name"] for t in data["tools"]]
    assert names == list(OPERATOR_TOOLS)
    assert data["hexstrike"] is False
    assert data["exploit_api"] is False
    cli = subprocess.run(
        ["python3", "-m", "dropbox", "mcp", "serve", "--scope", str(SCOPE)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert cli.returncode == 0, cli.stderr
    assert "scope_status" in cli.stdout


def test_jsonrpc_tools_list_and_refuse_exploit() -> None:
    from dropbox.mcp_stub import handle_jsonrpc, tools_list_entries

    listed = handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [t["name"] for t in listed["result"]["tools"]]
    assert names == list(OPERATOR_TOOLS)
    again = handle_jsonrpc({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    names_again = [t["name"] for t in again["result"]["tools"]]
    assert names_again == names == list(OPERATOR_TOOLS)
    assert tools_list_entries() == listed["result"]["tools"]
    status = next(t for t in listed["result"]["tools"] if t["name"] == "farm_slot_status")
    assert "category" in status["inputSchema"]["properties"]
    bad = handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "Metasploit"}}
    )
    assert bad.get("error")
    assert "refuses" in bad["error"]["message"]


def test_jsonrpc_invokes_plan_status_and_farm_slots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dropbox.mcp_stub import handle_jsonrpc

    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))

    slots = handle_jsonrpc({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "farm_slots"}})
    result = slots["result"]
    assert result["tool"] == "farm_slots"
    assert result["count"] >= 95
    assert result["wired_count"] >= 21
    assert result["file_drop_count"] >= 70
    assert result["by_category"]["discover"]["total"] >= 1
    assert result["by_sensor"]["nmap"]["total"] >= 1
    assert sum(b["total"] for b in result["by_sensor"].values()) == result["count"]
    assert result["brakes"]["max_workers"] == "2"
    assert result["brakes"]["deepen_batch"].startswith("3")
    assert "SCOPE.yaml" in result["brakes"]["scope"]
    assert "evergreen_assessment_mcp" in result["brakes"]["pack_truth"]
    assert "nmap/nessus not default" in result["brakes"]["free_day_scope"]
    assert result["counts"]["total"] == result["count"]
    assert result["vendored_binaries"] is False
    status = handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "orchestrator_status"}}
    )
    assert status["result"]["tool"] == "orchestrator_status"
    assert "discover (quiet)" in status["result"]["stage_graph"]
    plan = handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "orchestrator_plan"}}
    )
    assert plan["result"]["tool"] == "orchestrator_plan"
    assert plan["result"]["live"] is False
    assert plan["result"]["grc_export"]["posted"] is False
    will_run = plan["result"]["will_run"]
    assert set(will_run) == {"discover", "deepen", "external"}
    assert "nmap" in will_run["discover"]
    assert will_run["discover"]["nmap"] is False
    assert will_run["external"]
    assert all(value is False for value in will_run["external"].values())
    assert plan["result"]["slots"]["discover"]["selected"]
    matrix = handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "farm_slot_status"}}
    )
    assert matrix["result"]["tool"] == "farm_slot_status"
    assert matrix["result"]["plan_only"] is True
    assert matrix["result"]["live"] is False
    assert matrix["result"]["count"] >= 40
    names = {row["slot"] for row in matrix["result"]["matrix"]}
    assert "nmap" in names and "nuclei" in names
    nuclei = next(row for row in matrix["result"]["matrix"] if row["slot"] == "nuclei")
    assert nuclei["invoke"] is False
    assert nuclei["state"] == "file_drop"
    assert result["invoke_count"] >= 28
    assert result["wired_count"] >= 28
    discover = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "farm_slot_status", "arguments": {"category": "discover"}},
        }
    )
    assert discover["result"]["tool"] == "farm_slot_status"
    assert discover["result"]["category"] == "discover"
    assert discover["result"]["count"] >= 1
    assert all(row["category"] == "discover" for row in discover["result"]["matrix"])
    assert {row["slot"] for row in discover["result"]["matrix"]} <= names
    for tool, tid in (("stage_discover", 9), ("stage_deepen", 10), ("stage_ingest", 11)):
        body = handle_jsonrpc(
            {"jsonrpc": "2.0", "id": tid, "method": "tools/call", "params": {"name": tool}}
        )
        assert body["result"]["tool"] == tool
        assert body["result"]["live"] is False
        assert body["result"]["plan_only"] is True
        assert body["result"]["ok"] is True


def test_farm_toolbin_status_lab_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from dropbox.mcp_stub import handle_jsonrpc
    from dropbox.scanner_free import LAB_STUB_DIR

    monkeypatch.setenv("FARM_TOOL_BIN", str(LAB_STUB_DIR))
    monkeypatch.setenv("PATH", "/nonexistent-farm-lab-path")
    data = dispatch("farm_toolbin_status", scope_path=SCOPE)
    assert data["tool"] == "farm_toolbin_status"
    assert data["live"] is False
    assert data["plan_only"] is True
    assert data["farm_tool_bin"] == str(LAB_STUB_DIR)
    assert data["count"] == data["present"] + data["missing"] + data["demo_stub"]
    by_slot = {row["slot"]: row for row in data["slots"]}
    assert "nuclei" not in by_slot
    assert "openvas" not in by_slot
    for name in ("nmap", "nessus", "nessuscli", "curl", "testssl", "lynis"):
        assert by_slot[name]["state"] == "demo_stub", name
        assert "tool-bin/lab/" in by_slot[name]["path"]
    assert data["demo_stub"] >= 6
    rpc = handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 20, "method": "tools/call", "params": {"name": "farm_toolbin_status"}}
    )
    assert rpc["result"]["tool"] == "farm_toolbin_status"
    assert rpc["result"]["demo_stub"] >= 6


def test_export_ciso_poam_does_not_post(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    (tmp_path / "out" / "poam").mkdir(parents=True)
    (tmp_path / "out" / "poam" / "poam.csv").write_text("weakness,owner,due\nsmb,,\n", encoding="utf-8")
    data = dispatch("export_ciso_poam")
    assert data["posted"] is False
    assert data["owner_due"].startswith("blank")
    assert any(p.endswith("poam.csv") for p in data["files"])
