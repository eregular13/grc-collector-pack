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
    assert '"grc-dropbox"' in iface
    assert '"evergreen-assessment"' in iface
    assert "do **not** merge" in iface or "not one merged" in iface.lower() or "do not merge" in iface.lower()
    farm_op = (ROOT / "farm" / "OPERATOR.md").read_text(encoding="utf-8")
    assert ".cursor/mcp.json" in farm_op
    assert "claude_desktop_config.json" in farm_op
    assert "farm_toolbin_status" in farm_op
    assert "evergreen_assessment_mcp" in farm_op
    assert '"grc-dropbox"' in farm_op
    assert '"evergreen-assessment"' in farm_op
    example = (ROOT / "schemas" / "mcp.example.json").read_text(encoding="utf-8")
    assert '"grc-dropbox"' in example
    assert '"evergreen-assessment"' in example
    assert "dropbox.mcp_stub" in example
    assert "evergreen_assessment_mcp" in example
    assert "grc-dropbox-evergreen" not in example
    assert "grc-dropbox-evergreen" not in iface
    assert "grc-dropbox-evergreen" not in farm_op
    ciso_md = (ROOT / "schemas" / "ciso-assistant.md").read_text(encoding="utf-8")
    assert "push_ciso" in ciso_md
    assert "clica" in ciso_md
    assert "export_ciso_poam" in ciso_md
    assert "CISO_PUSH=1" in ciso_md
    assert "python3 -m dropbox ciso" in ciso_md
    assert "Desktop" in ciso_md or "no make" in ciso_md.lower()
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


def test_two_mcp_cross_wire_fails_closed() -> None:
    """Hephaestus: pack-truth tools are not conductor tools. Config stays unmerged."""
    import json

    from dropbox.mcp_contract import (
        CONDUCTOR_MODULE,
        PACK_TRUTH_MODULE,
        validate_two_mcp_servers,
    )
    from dropbox.mcp_stub import PACK_TRUTH_TOOLS, refuse_cross_wire, tool_catalog

    assert not (PACK_TRUTH_TOOLS & set(OPERATOR_TOOLS))
    blob = (ROOT / "dropbox" / "mcp_stub.py").read_text(encoding="utf-8")
    assert "evergreen_assessment_mcp" not in blob
    assert "check_scope" in PACK_TRUTH_TOOLS
    assert "license_guard" in PACK_TRUTH_TOOLS
    for name in PACK_TRUTH_TOOLS:
        with pytest.raises(GateError, match="cross-wire"):
            refuse_cross_wire(name)
        with pytest.raises(GateError, match="cross-wire"):
            dispatch(name, scope_path=SCOPE)
    catalog = tool_catalog()
    assert catalog["pack_truth"] is False
    assert catalog["farm_mcp_pack_truth"] is False
    assert catalog["cross_wire"] == "fail-closed"
    assert catalog["server"] == "dropbox-operator-mcp"
    status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
    assert "argus_pack_truth: evergreen_assessment_mcp only" in status
    assert "argus_farm_mcp: never pack truth" in status
    example = json.loads((ROOT / "schemas" / "mcp.example.json").read_text(encoding="utf-8"))
    ok = validate_two_mcp_servers(example)
    assert ok["merged"] is False
    assert ok["pack_truth"] == PACK_TRUTH_MODULE
    assert ok["conductor"] == CONDUCTOR_MODULE
    merged = {"mcpServers": {"grc-dropbox-evergreen": example["mcpServers"]["grc-dropbox"]}}
    with pytest.raises(GateError, match="cross-wire|merged"):
        validate_two_mcp_servers(merged)
    swapped = {
        "mcpServers": {
            "grc-dropbox": {
                "command": "python3",
                "args": ["-m", "evergreen_assessment_mcp"],
            },
            "evergreen-assessment": {
                "command": "python3",
                "args": ["-m", "dropbox.mcp_stub", "serve", "--stdio"],
            },
        }
    }
    with pytest.raises(GateError, match="cross-wired"):
        validate_two_mcp_servers(swapped)


def test_cross_wire_cli_and_jsonrpc_fail_closed() -> None:
    import subprocess

    from dropbox.mcp_stub import handle_jsonrpc

    proc = subprocess.run(
        ["python3", "-m", "dropbox", "mcp", "check_scope", "--scope", str(SCOPE)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "cross-wire" in (proc.stderr or "") + (proc.stdout or "")
    from dropbox.mcp_stub import PACK_TRUTH_TOOLS

    for idx, name in enumerate(sorted(PACK_TRUTH_TOOLS), start=90):
        body = handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": name, "arguments": {}},
            }
        )
        assert body.get("error"), name
        assert "cross-wire" in body["error"]["message"], name
    listed = handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    names = [t["name"] for t in listed["result"]["tools"]]
    assert PACK_TRUTH_TOOLS.isdisjoint(names)
    assert names == list(OPERATOR_TOOLS)


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
    assert result["scope_gated"] is True
    assert "DEMO" in result["client"]
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
    assert data["count"] == data["present"] + data["missing"] + data["demo_stub"] + data["file_drop"]
    assert data["demo_scope"] is True
    assert data["live_ready_count"] == 0
    assert data["will_run_count"] >= 6
    assert data["file_drop"] >= 7
    assert "nuclei" in data["license_lock_refused"]
    by_slot = {row["slot"]: row for row in data["slots"]}
    assert "nuclei" not in by_slot
    assert "openvas" not in by_slot
    for name in ("nikto", "gobuster", "ffuf", "amass", "subfinder", "scoutsuite", "checkov"):
        assert by_slot[name]["state"] == "file_drop", name
        assert by_slot[name]["will_run"] is False, name
        assert by_slot[name]["live_ready"] is False, name
    for name in ("nmap", "nessus", "nessuscli", "curl", "testssl", "lynis"):
        assert by_slot[name]["state"] == "demo_stub", name
        assert "tool-bin/lab/" in by_slot[name]["path"]
        assert by_slot[name]["allowlisted"] is True, name
        assert by_slot[name]["will_run"] is True, name
        assert by_slot[name]["live_ready"] is False, name
        assert by_slot[name]["stage"]
    assert data["demo_stub"] >= 6
    rpc = handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 20, "method": "tools/call", "params": {"name": "farm_toolbin_status"}}
    )
    assert rpc["result"]["tool"] == "farm_toolbin_status"
    assert rpc["result"]["demo_stub"] >= 6
    assert rpc["result"]["live_ready_count"] == 0


def test_farm_toolbin_status_live_ready_needs_non_demo_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Operator signal: lab stubs never live_ready; a real binary can be on a signed SCOPE."""
    import hashlib

    from dropbox.mcp_stub import farm_toolbin_status_tool

    tool_bin = tmp_path / "tool-bin"
    tool_bin.mkdir()
    nmap = tool_bin / "nmap"
    nmap.write_text("#!/bin/sh\necho real-byo-nmap\n", encoding="utf-8")
    nmap.chmod(0o755)
    monkeypatch.setenv("FARM_TOOL_BIN", str(tool_bin))
    monkeypatch.setenv("PATH", "/nonexistent-farm-live-ready-path")

    demo = farm_toolbin_status_tool(scope_path=SCOPE)
    nmap_demo = next(row for row in demo["slots"] if row["slot"] == "nmap")
    assert nmap_demo["state"] == "present"
    assert nmap_demo["will_run"] is True
    assert nmap_demo["live_ready"] is False
    assert demo["demo_scope"] is True
    assert demo["live_ready_count"] == 0

    att = tmp_path / "consent.md"
    att.write_text("signed keep-eval farm handoff\n", encoding="utf-8")
    digest = hashlib.sha256(att.read_bytes()).hexdigest()
    scope = tmp_path / "SCOPE.yaml"
    scope.write_text(
        "client:\n  name: Contoso Labs\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n"
        "allow_tools:\n  - nmap\n  - curl\n"
        "orchestrator:\n  stages:\n    discover: true\n    deepen: false\n",
        encoding="utf-8",
    )
    live = farm_toolbin_status_tool(scope_path=scope)
    nmap_live = next(row for row in live["slots"] if row["slot"] == "nmap")
    curl_live = next(row for row in live["slots"] if row["slot"] == "curl")
    assert live["demo_scope"] is False
    assert nmap_live["state"] == "present"
    assert nmap_live["allowlisted"] is True
    assert nmap_live["will_run"] is True
    assert nmap_live["live_ready"] is True
    assert live["live_ready_count"] >= 1
    assert curl_live["allowlisted"] is True
    assert curl_live["state"] == "missing"
    assert curl_live["will_run"] is False
    assert curl_live["live_ready"] is False
    assert "nuclei" in live["license_lock_refused"]


def test_farm_toolbin_status_file_drop_only_never_live_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """file_drop-only names stay not live_ready even if dropped into FARM_TOOL_BIN."""
    import hashlib

    from dropbox.mcp_stub import farm_toolbin_status_tool

    tool_bin = tmp_path / "tool-bin"
    tool_bin.mkdir()
    for name in ("nikto", "gobuster", "nmap"):
        path = tool_bin / name
        path.write_text("#!/bin/sh\necho byo-drop\n", encoding="utf-8")
        path.chmod(0o755)
    monkeypatch.setenv("FARM_TOOL_BIN", str(tool_bin))
    monkeypatch.setenv("PATH", "/nonexistent-file-drop-only-path")

    demo = farm_toolbin_status_tool(scope_path=SCOPE)
    nikto_demo = next(row for row in demo["slots"] if row["slot"] == "nikto")
    assert nikto_demo["state"] == "file_drop"
    assert nikto_demo["path"]
    assert nikto_demo["will_run"] is False
    assert nikto_demo["live_ready"] is False
    assert demo["live_ready_count"] == 0

    att = tmp_path / "consent.md"
    att.write_text("signed file-drop honesty\n", encoding="utf-8")
    digest = hashlib.sha256(att.read_bytes()).hexdigest()
    scope = tmp_path / "SCOPE.yaml"
    scope.write_text(
        "client:\n  name: Contoso Labs\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n"
        "allow_tools:\n  - nmap\n  - nikto\n  - gobuster\n"
        "orchestrator:\n  stages:\n    discover: true\n    deepen: false\n",
        encoding="utf-8",
    )
    live = farm_toolbin_status_tool(scope_path=scope)
    nikto = next(row for row in live["slots"] if row["slot"] == "nikto")
    gobuster = next(row for row in live["slots"] if row["slot"] == "gobuster")
    nmap = next(row for row in live["slots"] if row["slot"] == "nmap")
    assert live["demo_scope"] is False
    assert nikto["path"] and gobuster["path"]
    assert nikto["live_ready"] is False
    assert gobuster["live_ready"] is False
    assert nikto["will_run"] is False
    assert gobuster["will_run"] is False
    assert nmap["state"] == "present"
    assert nmap["live_ready"] is True
    assert live["live_ready_count"] == 1


def test_tools_call_is_plan_only_even_if_arguments_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dropbox.mcp_stub import handle_jsonrpc

    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    for name, tid in (("orchestrator_plan", 31), ("stage_discover", 32), ("stage_ingest", 33)):
        body = handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": tid,
                "method": "tools/call",
                "params": {"name": name, "arguments": {"live": True}},
            }
        )
        assert body["result"]["live"] is False, name
        assert body["result"].get("plan_only") is True or name == "orchestrator_plan"
        if name == "orchestrator_plan":
            assert body["result"]["live"] is False


def test_export_ciso_poam_does_not_post(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("CISO_PUSH", "0")
    monkeypatch.setenv("RISKREADY_PUSH", "1")
    (tmp_path / "out" / "ciso-assistant").mkdir(parents=True)
    (tmp_path / "out" / "ciso-assistant" / "assets.csv").write_text("ref_id\nA1\n", encoding="utf-8")
    (tmp_path / "out" / "poam").mkdir(parents=True)
    (tmp_path / "out" / "poam" / "poam.csv").write_text("weakness,owner,due\nsmb,,\n", encoding="utf-8")
    (tmp_path / "out" / "simplerisk").mkdir(parents=True)
    (tmp_path / "out" / "simplerisk" / "poam.csv").write_text("weakness,owner,due\nsmb,,\n", encoding="utf-8")
    data = dispatch("export_ciso_poam", scope_path=SCOPE)
    assert data["posted"] is False
    assert data["http"] is False
    assert data["owner_due"].startswith("blank")
    assert data["scope_gated"] is True
    assert data["wrap"] == "review-only"
    assert "DEMO" in data["client"]
    assert any("ciso-assistant" in p and p.endswith("assets.csv") for p in data["files"])
    assert any(p.endswith("poam.csv") and "poam" in p for p in data["files"])
    assert any("simplerisk" in p for p in data["files"])
    assert data["sor"] == "ciso-assistant"
    assert any(p.endswith("assets.csv") for p in data["ciso_files"])
    assert "clica" in data["clica"]
    assert "Desktop" in data["clica"] or "clica" in data["clica"]


def test_export_ciso_poam_posted_only_when_ciso_push(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    (tmp_path / "out" / "poam").mkdir(parents=True)
    (tmp_path / "out" / "poam" / "poam.csv").write_text("weakness\nsmb\n", encoding="utf-8")
    monkeypatch.setenv("CISO_PUSH", "1")
    monkeypatch.setenv("DRY_RUN", "1")
    monkeypatch.setenv("RISKREADY_PUSH", "1")
    dry = dispatch("export_ciso_poam", scope_path=SCOPE)
    assert dry["posted"] is False
    assert dry["http"] is False
    monkeypatch.setenv("DRY_RUN", "0")
    armed = dispatch("export_ciso_poam", scope_path=SCOPE)
    assert armed["posted"] is True
    assert armed["http"] is False
    assert armed["ciso_push"] == "1"
    assert armed["wrap"] == "review-only"


def _rpc_once(argv: list[str], req: dict, *, cwd: Path | None = None) -> dict:
    import json
    import subprocess

    proc = subprocess.run(
        argv,
        input=json.dumps(req) + "\n",
        cwd=str(cwd or ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return json.loads(proc.stdout)


def test_stdio_once_initialize_list_and_refuse_empty_unsigned_scope(tmp_path: Path) -> None:
    """Process e2e: serve --once/--stdio initialize, stable tools/list, SCOPE refuse."""
    import json
    import subprocess

    init = _rpc_once(
        ["python3", "-m", "dropbox.mcp_stub", "serve", "--once"],
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert init["result"]["serverInfo"]["name"] == "dropbox-operator-mcp"
    assert "hexstrike" not in json.dumps(init).lower()

    listed = _rpc_once(
        ["python3", "-m", "dropbox.mcp_stub", "serve", "--once"],
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    names = [t["name"] for t in listed["result"]["tools"]]
    assert names == list(OPERATOR_TOOLS)
    for banned in (
        "AIExploitGenerator",
        "Metasploit",
        "msfconsole",
        "hexstrike_run",
        "check_scope",
        "license_guard",
    ):
        assert banned not in names

    stdio = subprocess.run(
        ["python3", "-m", "dropbox.mcp_stub", "serve", "--stdio"],
        input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n",
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert stdio.returncode == 0, stdio.stderr
    assert json.loads(stdio.stdout)["result"]["serverInfo"]["name"] == "dropbox-operator-mcp"

    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    unsigned = tmp_path / "unsigned.yaml"
    unsigned.write_text(
        "client:\n  name: X\nconsent:\n  attestation_path: missing.md\n"
        "  attestation_sha256: 00dead\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n",
        encoding="utf-8",
    )
    call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "scope_status"}}
    for scope in (empty, unsigned):
        body = _rpc_once(
            ["python3", "-m", "dropbox", "mcp", "serve", "--once", "--scope", str(scope)],
            call,
        )
        assert body.get("error"), body
        msg = body["error"]["message"]
        assert "SCOPE" in msg or "consent" in msg or "attestation" in msg

    blob = (ROOT / "dropbox" / "mcp_stub.py").read_text(encoding="utf-8")
    assert "evergreen_assessment_mcp" not in blob
    assert "does not submodule hexstrike-ai" in blob


def test_farm_slots_and_export_refuse_without_scope(tmp_path: Path) -> None:
    empty = tmp_path / "SCOPE.yaml"
    empty.write_text("", encoding="utf-8")
    for name in (
        "farm_slots",
        "export_ciso_poam",
        "orchestrator_status",
        "stage_discover",
        "keep_status",
        "keep_ciso",
    ):
        with pytest.raises(GateError, match="SCOPE"):
            dispatch(name, scope_path=empty)
    slots = dispatch("farm_slots", scope_path=SCOPE)
    assert slots["scope_gated"] is True
    assert "DEMO" in slots["client"]
    assert slots["brakes"]["wrap"].startswith("push_riskready")
    assert "evergreen_assessment_mcp" in slots["brakes"]["pack_truth"]
    assert "nmap/nessus not default" in slots["brakes"]["free_day_scope"]


def test_tools_list_includes_keep_status_and_keep_ciso() -> None:
    from dropbox.mcp_stub import handle_jsonrpc, tools_list_entries

    assert "keep_status" in OPERATOR_TOOLS
    assert "keep_ciso" in OPERATOR_TOOLS
    listed = handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [t["name"] for t in listed["result"]["tools"]]
    assert "keep_status" in names
    assert "keep_ciso" in names
    assert names == list(OPERATOR_TOOLS)
    assert names.index("keep_status") == names.index("export_ciso_poam") + 1
    assert names.index("keep_ciso") == names.index("keep_status") + 1
    entries = {row["name"]: row for row in tools_list_entries()}
    assert "SAMPLE≠client" in entries["keep_status"]["description"]
    assert "0/4" in entries["keep_status"]["description"]
    assert "fixtures/keep-samples" in entries["keep_status"]["description"]
    assert "python -m keep lab" in entries["keep_ciso"]["description"]
    assert "fixtures/keep-samples" in entries["keep_ciso"]["description"]
    assert "densify" in entries["keep_ciso"]["description"]
    assert "OpenGRC" in entries["keep_ciso"]["description"]
    assert "Probo" in entries["keep_ciso"]["description"]
    assert "sample_to_sor" in entries["keep_ciso"]["description"]
    assert "farm_drop_to_sor" in entries["keep_ciso"]["description"]
    assert "farm-drop-to-sor" in entries["keep_ciso"]["description"]
    assert "farm_drop_to_sor.ps1" in entries["keep_ciso"]["description"]
    assert "sample_to_sor" in entries["keep_status"]["description"]
    assert "farm_drop_to_sor" in entries["keep_status"]["description"]
    exporters = entries["keep_ciso"]["inputSchema"]["properties"].get("exporters") or {}
    assert exporters.get("type") == "boolean"
    assert "keep-lab" in (exporters.get("description") or "")


def test_keep_status_empty_in_is_zero_of_four(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    empty = tmp_path / "in"
    for sensor in ("identity", "saas", "vuln", "cloud"):
        (empty / sensor).mkdir(parents=True)
        (empty / sensor / ".gitkeep").write_text("", encoding="utf-8")
    monkeypatch.setenv("IN_DIR", str(empty))
    data = dispatch("keep_status", scope_path=SCOPE)
    assert data["tool"] == "keep_status"
    assert data["scope_gated"] is True
    assert data["keep_real"] == "0/4"
    assert data["keep_real_count"] == 0
    assert data["pack_in_empty"] is True
    assert data["client_keep"] is False
    assert data["sample"] is True
    assert data["demo"] is True
    assert data["lab_source"] == "fixtures/keep-samples"
    assert data["sample_path"] is True
    assert data["densify"] is False
    assert data.get("prefer_pack_in") is not True
    assert data["posted"] is False
    assert data["http"] is False
    assert data["paying_day"] == "FAIL"
    assert "SAMPLE≠client" in data["banners"]
    assert "DEMO≠client" in data["banners"]
    assert "denser" not in data["note"].lower()
    assert "fixtures/keep-samples" in data["note"]
    for name in ("hardeningkitty", "maester", "testssl", "cloud"):
        assert data["families"][name]["present"] is False
        assert data["families"][name]["real"] is False
    assert data["fixtures_keep_samples"]["present"] is True
    assert data["fixtures_keep_samples"]["lab_only"] is True
    assert data["fixtures_keep_samples"]["keep_real"] == "0/4"
    assert data["cli_twin"]["command"] in {"./scripts/sample_to_sor.sh", "make sample-to-sor"}
    assert data["farm_drop_cli_twin"]["command"] in {
        "./scripts/farm_drop_to_sor.sh",
        "make farm-drop-to-sor",
    }
    assert data["farm_drop_cli_twin"]["ps1"] == ".\\scripts\\farm_drop_to_sor.ps1"
    iface = (ROOT / "dropbox" / "operator_mcp_interface.md").read_text(encoding="utf-8")
    assert "`keep_status`" in iface
    assert "`keep_ciso`" in iface
    assert "SAMPLE≠client" in iface
    assert "DEMO≠client" in iface
    assert "0/4" in iface
    assert "fixtures/keep-samples" in iface
    assert "OpenGRC" in iface
    assert "Probo" in iface
    assert "sample_to_sor.sh" in iface
    assert "farm_drop_to_sor.sh" in iface
    assert "farm-drop-to-sor" in iface
    assert "farm_drop_to_sor.ps1" in iface
    assert "farm_drop_cli_twin" in iface
    assert "`keep_status` then `keep_ciso`" in iface
    assert "denser" not in iface.lower()
    assert "prefer pack" not in iface.lower()
    assert "self-SCOPE" in iface or "self-scope" in iface.lower()


def test_keep_status_repo_pack_in_is_sample_zero_of_four(monkeypatch: pytest.MonkeyPatch) -> None:
    """This week's slice: pack in/ stays empty. SAMPLE lab path is fixtures."""
    monkeypatch.delenv("IN_DIR", raising=False)
    data = dispatch("keep_status", scope_path=SCOPE)
    assert data["keep_real"] == "0/4"
    assert data["pack_in_empty"] is True
    assert data["lab_source"] == "fixtures/keep-samples"
    assert data["client_keep"] is False
    assert data["densify"] is False
    assert data["paying_day"] == "FAIL"


def test_keep_ciso_dry_does_not_mutate_pack_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pack_in = tmp_path / "in"
    for sensor in ("identity", "saas", "vuln", "cloud"):
        (pack_in / sensor).mkdir(parents=True)
        (pack_in / sensor / ".gitkeep").write_text("", encoding="utf-8")
    marker = pack_in / "identity" / "estate-marker.txt"
    marker.write_text("preexisting estate — do not touch\n", encoding="utf-8")
    before = {
        str(path.relative_to(pack_in)): path.read_bytes()
        for path in pack_in.rglob("*")
        if path.is_file()
    }
    work = tmp_path / "work"
    monkeypatch.setenv("IN_DIR", str(pack_in))
    monkeypatch.setenv("CISO_PUSH", "1")
    monkeypatch.setenv("RISKREADY_PUSH", "1")
    monkeypatch.setenv("GRC_LIVE_SCAN", "1")
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work)},
    )
    after = {
        str(path.relative_to(pack_in)): path.read_bytes()
        for path in pack_in.rglob("*")
        if path.is_file()
    }
    assert before == after
    assert not (pack_in / "identity" / "hardeningkitty.csv").exists()
    assert data["tool"] == "keep_ciso"
    assert data["ok"] is True
    assert data["posted"] is False
    assert data["http"] is False
    assert data["pack_in_written"] is False
    assert data["ciso_push"] == "0"
    assert data["riskready_push"] == "0"
    assert data["grc_live_scan"] == "0"
    assert data["dry_run"] is True
    assert data["sample"] is True
    assert data["demo"] is True
    assert data["client_keep"] is False
    assert data["origin"] == "keep-samples"
    assert data["lab_source"] == "fixtures/keep-samples"
    assert data["sample_path"] is True
    assert data["densify"] is False
    assert data["paying_day"] == "FAIL"
    assert "SAMPLE≠client" in data["banners"]
    assert "DEMO≠client" in data["banners"]
    assert data["estate"].startswith("SAMPLE/DEMO")
    assert "denser" not in data["note"].lower()
    assert "fixtures/keep-samples" in data["note"]
    assert data["stamp"].get("origin") == "keep-samples"
    assert data["stamp"].get("sample") is True
    assert data["ciso_files"]
    assert all(p.endswith(".csv") and "ciso-assistant" in p for p in data["ciso_files"])
    assert data["ciso_import"].endswith("IMPORT.json")
    assert Path(data["ciso_import"]).is_file()
    assert data["opengrc"]["dir"]
    assert Path(data["opengrc"]["dir"]).is_dir()
    assert data["opengrc"]["files"]
    assert any(p.endswith("risks.csv") for p in data["opengrc"]["files"])
    assert any(p.endswith("assets.csv") for p in data["opengrc"]["files"])
    assert any(p.endswith("implementations.csv") for p in data["opengrc"]["files"])
    assert all(Path(p).is_file() for p in data["opengrc"]["files"])
    assert data["probo"].endswith("probo.json")
    assert Path(data["probo"]).is_file()
    assert data["stamp"].get("opengrc")
    assert data["stamp"].get("probo")
    assert data["stamp"].get("ciso_import")
    twin = data["cli_twin"]
    assert twin["present"] is True
    assert twin["command"] == "./scripts/sample_to_sor.sh"
    assert twin["make"] == "make sample-to-sor"
    assert twin["ps1"] == ".\\scripts\\sample_to_sor.ps1"
    farm = data["farm_drop_cli_twin"]
    assert farm["present"] is True
    assert farm["name"] == "farm_drop_to_sor"
    assert farm["kind"] == "farm_pack_drop"
    assert farm["command"] == "./scripts/farm_drop_to_sor.sh"
    assert farm["make"] == "make farm-drop-to-sor"
    assert farm["ps1"] == ".\\scripts\\farm_drop_to_sor.ps1"
    assert farm["ps1_present"] is True
    assert "prove_ciso" in farm["note"]
    assert "pack in" in farm["note"].lower() or "pack in/" in farm["note"]
    assert data["exporters"] is False
    assert data["exporters_from"] == "keep-lab"
    assert data["handoff"].endswith("handoff.json")
    assert Path(data["handoff"]).is_file()
    assert all(Path(p).is_file() for p in data["ciso_files"])
    handoff = Path(data["handoff"]).read_text(encoding="utf-8")
    assert '"posted": false' in handoff or '"posted":false' in handoff
    assert "sample" in handoff.lower()


def test_keep_ciso_wipes_leftover_out_without_winerror_145(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """sample_to_sor leftovers in keep/work/out must not crash keep_ciso on wipe."""
    from keep.ciso_import import CISO_REQUIRED

    pack_in = tmp_path / "in"
    pack_in.mkdir()
    work = tmp_path / "work"
    leftover = work / "out" / "ciso-assistant" / "nested"
    leftover.mkdir(parents=True)
    (leftover / "stale.csv").write_text("stale\n", encoding="utf-8")
    (work / "out" / "summary.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("IN_DIR", str(pack_in))
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work)},
    )
    assert data["ok"] is True, data.get("stamp", {}).get("reason")
    ciso = Path(data["ciso_dir"])
    for name in CISO_REQUIRED:
        assert (ciso / name).is_file(), name
    assert not (ciso / "nested" / "stale.csv").exists()


def test_keep_ciso_sor_helpers_tolerate_missing_script(tmp_path: Path) -> None:
    from dropbox.mcp_stub import (
        farm_drop_to_sor_cli_twin,
        keep_ciso_sor_paths,
        sample_to_sor_cli_twin,
    )

    twin = sample_to_sor_cli_twin(tmp_path)
    assert twin["present"] is False
    assert twin["script"] == ""
    assert twin["command"] == "make sample-to-sor"
    assert twin["make"] == "make sample-to-sor"
    assert twin["ps1"] == ".\\scripts\\sample_to_sor.ps1"
    assert twin["ps1_present"] is False

    farm = farm_drop_to_sor_cli_twin(tmp_path)
    assert farm["present"] is False
    assert farm["script"] == ""
    assert farm["command"] == "make farm-drop-to-sor"
    assert farm["make"] == "make farm-drop-to-sor"
    assert farm["ps1"] == ".\\scripts\\farm_drop_to_sor.ps1"
    assert farm["ps1_present"] is False
    assert farm["name"] == "farm_drop_to_sor"
    assert farm["kind"] == "farm_pack_drop"

    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "sample_to_sor.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    present = sample_to_sor_cli_twin(tmp_path)
    assert present["present"] is True
    assert present["command"] == "./scripts/sample_to_sor.sh"
    (tmp_path / "scripts" / "farm_drop_to_sor.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "scripts" / "farm_drop_to_sor.ps1").write_text("# ps1\n", encoding="utf-8")
    farm_present = farm_drop_to_sor_cli_twin(tmp_path)
    assert farm_present["present"] is True
    assert farm_present["command"] == "./scripts/farm_drop_to_sor.sh"
    assert farm_present["ps1_present"] is True

    work = tmp_path / "work"
    ciso = work / "out" / "ciso-assistant"
    opengrc = work / "out" / "opengrc"
    preview = work / "out" / "import_preview"
    ciso.mkdir(parents=True)
    opengrc.mkdir()
    preview.mkdir()
    (ciso / "IMPORT.json").write_text("{}\n", encoding="utf-8")
    (ciso / "assets.csv").write_text("ref_id\n", encoding="utf-8")
    (opengrc / "risks.csv").write_text("code\n", encoding="utf-8")
    (opengrc / "assets.csv").write_text("asset_tag\n", encoding="utf-8")
    (opengrc / "implementations.csv").write_text("title\n", encoding="utf-8")
    probo = preview / "probo.json"
    probo.write_text("{}\n", encoding="utf-8")
    sor = keep_ciso_sor_paths(
        work,
        {
            "ciso_dir": str(ciso),
            "ciso_import": str(ciso / "IMPORT.json"),
            "opengrc": str(opengrc),
            "probo": str(probo),
        },
    )
    assert sor["ciso_import"].endswith("IMPORT.json")
    assert Path(sor["ciso_import"]).is_file()
    assert sor["opengrc"]["dir"] == str(opengrc)
    assert [Path(p).name for p in sor["opengrc"]["files"]] == [
        "risks.csv",
        "assets.csv",
        "implementations.csv",
    ]
    assert sor["probo"] == str(probo)


def test_keep_status_then_keep_ciso_one_session_returns_sor_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Operator one session: keep_status then keep_ciso lists every SAMPLE SoR path."""
    pack_in = tmp_path / "in"
    for sensor in ("identity", "saas", "vuln", "cloud"):
        (pack_in / sensor).mkdir(parents=True)
        (pack_in / sensor / ".gitkeep").write_text("", encoding="utf-8")
    work = tmp_path / "work"
    monkeypatch.setenv("IN_DIR", str(pack_in))
    status = dispatch("keep_status", scope_path=SCOPE, arguments={"pack_in": str(pack_in)})
    assert status["tool"] == "keep_status"
    assert status["keep_real"] == "0/4"
    assert status["lab_source"] == "fixtures/keep-samples"
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work), "exporters": True},
    )
    assert data["ok"] is True
    assert data["sample"] is True
    assert data["paying_day"] == "FAIL"
    assert data["exporters"] is True
    assert data["exporters_from"] == "keep-lab"
    assert data["ciso_dir"]
    assert data["ciso_files"]
    assert Path(data["ciso_import"]).is_file()
    assert Path(data["opengrc"]["dir"]).is_dir()
    assert any("opengrc" in p and p.endswith("risks.csv") for p in data["opengrc"]["files"])
    assert Path(data["probo"]).is_file()
    assert "probo" in data["probo"]
    assert data["cli_twin"]["command"] in {"./scripts/sample_to_sor.sh", "make sample-to-sor"}
    assert data["farm_drop_cli_twin"]["command"] in {
        "./scripts/farm_drop_to_sor.sh",
        "make farm-drop-to-sor",
    }
    assert data["farm_drop_cli_twin"]["ps1"] == ".\\scripts\\farm_drop_to_sor.ps1"
    assert status["cli_twin"]["command"] in {"./scripts/sample_to_sor.sh", "make sample-to-sor"}
    assert status["farm_drop_cli_twin"]["command"] in {
        "./scripts/farm_drop_to_sor.sh",
        "make farm-drop-to-sor",
    }
    assert "OpenGRC" in (ROOT / "dropbox" / "operator_mcp_interface.md").read_text(encoding="utf-8")


def test_keep_status_and_keep_ciso_advertise_both_operator_twins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SAMPLE keep + farm pack_drop twins; honesty fail-closed unchanged."""
    from dropbox.mcp_stub import farm_drop_to_sor_cli_twin, sample_to_sor_cli_twin

    pack_in = tmp_path / "in"
    for sensor in ("identity", "saas", "vuln", "cloud"):
        (pack_in / sensor).mkdir(parents=True)
        (pack_in / sensor / ".gitkeep").write_text("", encoding="utf-8")
    work = tmp_path / "work"
    monkeypatch.setenv("IN_DIR", str(pack_in))
    status = dispatch("keep_status", scope_path=SCOPE, arguments={"pack_in": str(pack_in)})
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work)},
    )
    sample = sample_to_sor_cli_twin(ROOT)
    farm = farm_drop_to_sor_cli_twin(ROOT)
    assert sample["name"] == "sample_to_sor"
    assert sample["kind"] == "sample_keep"
    assert farm["name"] == "farm_drop_to_sor"
    assert farm["kind"] == "farm_pack_drop"
    for payload in (status, data):
        assert payload["cli_twin"]["command"] == "./scripts/sample_to_sor.sh"
        assert payload["cli_twin"]["make"] == "make sample-to-sor"
        assert payload["cli_twin"]["ps1"] == ".\\scripts\\sample_to_sor.ps1"
        assert payload["farm_drop_cli_twin"]["command"] == "./scripts/farm_drop_to_sor.sh"
        assert payload["farm_drop_cli_twin"]["make"] == "make farm-drop-to-sor"
        assert payload["farm_drop_cli_twin"]["ps1"] == ".\\scripts\\farm_drop_to_sor.ps1"
        assert payload["sample"] is True
        assert payload["demo"] is True
        assert payload["client_keep"] is False
        assert payload["paying_day"] == "FAIL"
        assert "SAMPLE≠client" in payload["banners"]
        assert "DEMO≠client" in payload["banners"]
    assert status["keep_real"] == "0/4"
    assert status["densify"] is False
    assert data["ciso_import"].endswith("IMPORT.json")
    assert Path(data["ciso_import"]).is_file()
    assert data["opengrc"]["files"]
    assert Path(data["probo"]).is_file()
    assert data["pack_in_written"] is False
    assert data["posted"] is False
    iface = (ROOT / "dropbox" / "operator_mcp_interface.md").read_text(encoding="utf-8")
    assert "cli_twin" in iface and "farm_drop_cli_twin" in iface
    assert "./scripts/sample_to_sor.sh" in iface
    assert "./scripts/farm_drop_to_sor.sh" in iface
    assert "make farm-drop-to-sor" in iface
    assert ".\\scripts\\farm_drop_to_sor.ps1" in iface
    assert "SAMPLE≠client" in iface
    assert "paying_day FAIL" in iface
