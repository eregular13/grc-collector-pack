"""Hephaestus two-MCP contract. Conductor and pack truth stay unmerged."""

from __future__ import annotations

from typing import Any

from dropbox.scope import GateError

CONDUCTOR_SERVER = "grc-dropbox"
PACK_TRUTH_SERVER = "evergreen-assessment"
CONDUCTOR_MODULE = "dropbox.mcp_stub"
PACK_TRUTH_MODULE = "evergreen_assessment_mcp"
MERGED_SERVER = "grc-dropbox-evergreen"


def validate_two_mcp_servers(config: dict[str, Any]) -> dict[str, Any]:
    """Fail closed if the two MCP servers are merged or cross-wired."""
    servers = config.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        raise GateError("mcpServers missing — two unmerged servers required")
    if MERGED_SERVER in servers:
        raise GateError("merged MCP server refused (cross-wire)")
    names = set(servers)
    if CONDUCTOR_SERVER not in names or PACK_TRUTH_SERVER not in names:
        raise GateError(
            "two MCP servers required: grc-dropbox (conductor) + evergreen-assessment (pack truth)"
        )
    drop = servers[CONDUCTOR_SERVER] if isinstance(servers.get(CONDUCTOR_SERVER), dict) else {}
    pack = servers[PACK_TRUTH_SERVER] if isinstance(servers.get(PACK_TRUTH_SERVER), dict) else {}
    drop_args = " ".join(str(x) for x in (drop.get("args") or []))
    pack_args = " ".join(str(x) for x in (pack.get("args") or []))
    drop_cmd = str(drop.get("command") or "")
    pack_cmd = str(pack.get("command") or "")
    blob_drop = f"{drop_cmd} {drop_args}"
    blob_pack = f"{pack_cmd} {pack_args}"
    if PACK_TRUTH_MODULE in blob_drop:
        raise GateError("grc-dropbox cross-wired to pack truth")
    if CONDUCTOR_MODULE in blob_pack:
        raise GateError("evergreen-assessment cross-wired to conductor")
    if CONDUCTOR_MODULE not in blob_drop and "mcp_stdio.sh" not in blob_drop:
        raise GateError("grc-dropbox must run dropbox.mcp_stub (or mcp_stdio.sh)")
    if PACK_TRUTH_MODULE not in blob_pack:
        raise GateError("evergreen-assessment must run pack-truth module")
    return {
        "ok": True,
        "servers": [CONDUCTOR_SERVER, PACK_TRUTH_SERVER],
        "merged": False,
        "pack_truth": PACK_TRUTH_MODULE,
        "conductor": CONDUCTOR_MODULE,
        "farm_mcp_pack_truth": False,
    }
