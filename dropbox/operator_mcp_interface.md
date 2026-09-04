# Operator MCP stub — interface (no public attack API)

Thin hooks in `mcp_stub.py`. Each tool is SCOPE-gated. No Hexstrike server. No FastMCP dependency. No exploit tools.

| Tool | Wraps | Notes |
|---|---|---|
| `scope_status` | `python3 -m dropbox gate` + brakes | Client, window, stages, allow_tools ∩ PATH |
| `orchestrator_plan` | `python3 -m dropbox orchestrate` (not `--live`) | Plan-only always |
| `orchestrator_status` | `python3 -m dropbox status` | Stage graph, last integrity stop, shard/batch counters |
| `stage_discover` | `discover_stage` | Quiet only. Live BYO nmap only if allowlisted + on PATH |
| `stage_deepen` | `deepen_stage` | **Refuses** unless `stages.deepen: true`. Hosts = discover-live or `deepen_hosts` |
| `stage_ingest` | `ingest_stage` | Copies artifacts into `in/`. Does not scan |
| `farm_slots` | `farm/SLOTS.yaml` | Catalog + wired adapters. No binaries |
| `farm_slot_status` | SLOTS ∩ PATH ∩ allow_tools | Full matrix. Optional `{ "category": "discover" }`. Plan-only |
| `export_ciso_poam` | reads `out/ciso-assistant/` + `out/poam/` | Paths only. Does not invent owner/due |

Refused names (raise): Hexstrike attack tools, `AIExploitGenerator`, Metasploit, exploit-chain, unauth autonomous spray.

```bash
python3 -m dropbox.mcp_stub serve            # print the operator tools and exit
python3 -m dropbox.mcp_stub serve --stdio    # JSON-RPC loop (Claude/Cursor)
python3 -m dropbox mcp serve
python3 -c "from dropbox.mcp_stub import dispatch; print(dispatch('scope_status'))"
```

Cursor `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (user). `cwd`
and `PYTHONPATH` must be the repo root. Private box, `DROPBOX_LIVE=0`:

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
        "RISKREADY_PUSH": "0"
      }
    }
  }
}
```

`tools/list` order is stable (`OPERATOR_TOOLS`). `farm_slot_status` may
filter with `params.arguments.category`.

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
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"AIExploitGenerator"}}
```

The last call returns a SCOPE gate error. `tools/call` never implies `--live`.
