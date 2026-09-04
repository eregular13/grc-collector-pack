# Operator MCP stub — interface (no public attack API)

Thin hooks in `mcp_stub.py`. Each tool is SCOPE-gated. No Hexstrike server. No FastMCP dependency. No exploit tools. This is conductor UX for this Python pack — not USB `evergreen_assessment_mcp` and not a TypeScript refuse matrix.

| Tool | Wraps | Notes |
|---|---|---|
| `scope_status` | `python3 -m dropbox gate` + brakes | Client, window, stages, allow_tools ∩ PATH |
| `orchestrator_plan` | `python3 -m dropbox orchestrate` (not `--live`) | Plan-only. Result includes per-stage `will_run` map |
| `orchestrator_status` | `python3 -m dropbox status` | Stage graph, last integrity stop, shard/batch counters |
| `stage_discover` | `discover_stage` | Quiet only. Live BYO nmap only if allowlisted + on PATH |
| `stage_deepen` | `deepen_stage` | **Refuses** unless `stages.deepen: true`. Hosts = discover-live or `deepen_hosts` |
| `stage_ingest` | `ingest_stage` | Copies discover/deepen artifacts into `in/`. Inventories dropped external files. Does not scan |
| `farm_slots` | `farm/SLOTS.yaml` | Catalog + wired adapters. No binaries |
| `farm_slot_status` | SLOTS ∩ PATH ∩ allow_tools | Full matrix. Optional `{ "category": "discover" }`. Plan-only |
| `farm_toolbin_status` | `FARM_TOOL_BIN` then PATH | Wired invoke resolve: `present` / `missing` / `demo_stub`. Does not invoke |
| `export_ciso_poam` | reads `out/ciso-assistant/` + `out/poam/` | Paths only. Does not invent owner/due |

Refused names (raise): Hexstrike attack tools, `AIExploitGenerator`, Metasploit, exploit-chain, unauth autonomous spray.

```bash
python3 -m dropbox.mcp_stub serve            # print the operator tools and exit
python3 -m dropbox.mcp_stub serve --stdio    # JSON-RPC loop (Claude/Cursor)
python3 -m dropbox mcp serve
python3 -m dropbox mcp farm_toolbin_status
python3 -c "from dropbox.mcp_stub import dispatch; print(dispatch('scope_status'))"
```

Must start from the **repo root**. Replace `/absolute/path/to/grc-collector-pack`
with this checkout. `scripts/mcp_stdio.sh` cds to the root so clients that
ignore `cwd` still resolve `python3 -m dropbox.mcp_stub`.

**Cursor** — project `.cursor/mcp.json` or user `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "grc-dropbox": {
      "command": "python3",
      "args": ["-m", "dropbox.mcp_stub", "serve", "--stdio"],
      "cwd": "/absolute/path/to/grc-collector-pack",
      "env": {
        "PYTHONPATH": "/absolute/path/to/grc-collector-pack",
        "DROPBOX_LIVE": "0",
        "GRC_LIVE_SCAN": "0",
        "CISO_PUSH": "0",
        "RISKREADY_PUSH": "0"
      }
    }
  }
}
```

**Claude Desktop** — macOS
`~/Library/Application Support/Claude/claude_desktop_config.json` or Linux
`~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "grc-dropbox": {
      "command": "/absolute/path/to/grc-collector-pack/scripts/mcp_stdio.sh"
    }
  }
}
```

`tools/list` order is stable (`OPERATOR_TOOLS`). `farm_slot_status` may
filter with `params.arguments.category`. `tools/call` `orchestrator_plan`
returns `will_run` (`discover` / `deepen` / `external` → slot → bool).
External entries stay `false`.

## JSON-RPC examples (stdio stub)

`serve` does not bind a port. `--once` reads one line from stdin.

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
```

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scope_status"}}
```

```json
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"farm_slot_status","arguments":{"category":"discover"}}}
```

```json
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"farm_toolbin_status"}}
```

```json
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"orchestrator_plan"}}
```

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"AIExploitGenerator"}}
```

The last call returns a SCOPE gate error. `tools/call` never implies `--live`.
