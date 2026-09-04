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
| `export_ciso_poam` | reads `out/ciso-assistant/` + `out/poam/` | Paths only. Does not invent owner/due |

Refused names (raise): Hexstrike attack tools, `AIExploitGenerator`, Metasploit, exploit-chain, unauth autonomous spray.

```bash
python3 -m dropbox.mcp_stub serve          # no-op: print the 7 tools and exit
python3 -m dropbox mcp serve
python3 -c "from dropbox.mcp_stub import dispatch; print(dispatch('scope_status'))"
```

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
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"AIExploitGenerator"}}
```

The last call returns a SCOPE gate error. `tools/call` never implies `--live`.
