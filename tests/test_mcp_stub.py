"""Operator MCP stub: SCOPE-gated, no Hexstrike/exploit API."""

from __future__ import annotations

from pathlib import Path

import pytest

from dropbox.mcp_stub import OPERATOR_TOOLS, dispatch, refuse_attack_name
from dropbox.scope import GateError
from tests.hermetic_path import isolate_farm_path

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
