# Operator MCP stub — interface (no public attack API)

Thin hooks in `mcp_stub.py`. Each tool is SCOPE-gated. No Hexstrike server. No FastMCP dependency. No exploit tools. This is conductor UX for this Python pack — not USB `evergreen_assessment_mcp` (21-tool `check_scope` / `license_guard` remains pack truth) and not a TypeScript refuse matrix.

| Tool | Wraps | Notes |
|---|---|---|
| `scope_status` | `python3 -m dropbox gate` + brakes | Client, window, stages, allow_tools ∩ PATH |
| `orchestrator_plan` | `python3 -m dropbox orchestrate` (not `--live`) | Plan-only. Result includes per-stage `will_run` map |
| `orchestrator_status` | `python3 -m dropbox status` | Stage graph, last integrity stop, shard/batch counters |
| `stage_discover` | `discover_stage` | Quiet only. Live BYO nmap only if allowlisted + on PATH |
| `stage_deepen` | `deepen_stage` | **Refuses** unless `stages.deepen: true`. Hosts = discover-live or `deepen_hosts` |
| `stage_ingest` | `ingest_stage` | Copies discover/deepen artifacts into `in/`. Inventories dropped external files. Does not scan |
| `farm_slots` | `farm/SLOTS.yaml` | Catalog + wired adapters under written SCOPE. No binaries |
| `farm_slot_status` | SLOTS ∩ PATH ∩ allow_tools | Full matrix. Optional `{ "category": "discover" }`. Plan-only |
| `farm_toolbin_status` | `FARM_TOOL_BIN` then PATH | Per-slot `live_ready` plus `live_ready_count` / `slots[]`. Never `live_ready` for `demo_stub` or file_drop-only names even if a binary is under `FARM_TOOL_BIN`. DEMO stubs may `will_run` in e2e. Does not invoke |
| `export_ciso_poam` | reads `out/ciso-assistant/` + `out/poam/` + `out/simplerisk/` | SCOPE-gated paths. `posted` false unless `CISO_PUSH=1`. Conductor `http` always false. Does not invent owner/due |
| `keep_status` | `keep.adapters.scan_keep_dir` on pack `in/{identity,saas,vuln,cloud}/` | Empty pack `in/` is `keep_real` **0/4**. Lab path is `fixtures/keep-samples` (SAMPLE≠client). HardeningKitty / Maester / testssl / Prowler\|ScoutSuite detect only. Advertises both operator twins as hints only: `cli_twin` (`./scripts/sample_to_sor.sh` / `make sample-to-sor` / `.\\scripts\\sample_to_sor.ps1`) and `farm_drop_cli_twin` (`./scripts/farm_drop_to_sor.sh` / `make farm-drop-to-sor` / `.\\scripts\\farm_drop_to_sor.ps1`). **Does not densify pack `in/`.** Does not invent non-sample files. Does not require signed self-SCOPE. **SAMPLE≠client. DEMO≠client.** paying_day FAIL |
| `keep_ciso` | `keep.lab.keep_lab` SAMPLE path (`python -m keep lab`) | **SAMPLE keep-lab only:** `fixtures/keep-samples` → `keep/work/out/ciso-assistant/*.csv` + `IMPORT.json` + OpenGRC CSVs + Probo preview + `eval/handoff.json`. Return lists every SoR path (`ciso_dir` / `ciso_files` / `ciso_import` / `opengrc` / `probo`) plus `cli_twin` (`./scripts/sample_to_sor.sh` or `make sample-to-sor` or `.\\scripts\\sample_to_sor.ps1`) and `farm_drop_cli_twin` (`./scripts/farm_drop_to_sor.sh` / `make farm-drop-to-sor` / `.\\scripts\\farm_drop_to_sor.ps1` — hint only; this tool does not run prove_ciso). `arguments.exporters` is optional (script `--exporters` re-write); sinks always come from keep-lab — no second export path. `DRY_RUN=1` `GRC_LIVE_SCAN=0` `CISO_PUSH=0` `RISKREADY_PUSH=0`. Stamps demo/sample. **Never writes / densifies pack `in/`.** Never POST `/api/risks`. Never spawns scanners. No signed self-SCOPE densify. **SAMPLE≠client. DEMO≠client.** paying_day FAIL |

Refused names (raise): Hexstrike attack tools, `AIExploitGenerator`, Metasploit, exploit-chain, unauth autonomous spray.

```bash
python3 -m dropbox.mcp_stub serve            # print the operator tools and exit
python3 -m dropbox.mcp_stub serve --stdio    # JSON-RPC loop (Claude/Cursor)
python3 -m dropbox.mcp_stub serve --once     # one JSON-RPC line on stdin
python3 -m dropbox mcp serve                 # same catalog (not FastMCP / not USB pack truth)
python3 -m dropbox mcp serve --stdio         # same JSON-RPC loop
python3 -m dropbox mcp serve --once          # same one-line JSON-RPC
python3 -m dropbox mcp farm_toolbin_status
python3 -m dropbox mcp keep_status
python3 -m dropbox mcp keep_ciso
python3 -c "from dropbox.mcp_stub import dispatch; print(dispatch('scope_status'))"
```

Must start from the **repo root**. Replace `/absolute/path/to/grc-collector-pack`
with this checkout. `scripts/mcp_stdio.sh` cds to the root so clients that
ignore `cwd` still resolve `python3 -m dropbox.mcp_stub`.

**Cursor** — project `.cursor/mcp.json` or user `~/.cursor/mcp.json`:

Two servers — do **not** merge. Pack truth is USB `evergreen_assessment_mcp`.
This repo's conductor is `dropbox.mcp_stub` only. See `schemas/mcp.example.json`.
Cross-wire (`check_scope` / `license_guard` on the conductor, or one merged
server) fails closed.

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
    },
    "evergreen-assessment": {
      "command": "python3",
      "args": ["-m", "evergreen_assessment_mcp"],
      "cwd": "/absolute/path/to/usb/evergreen-assessment"
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
    },
    "evergreen-assessment": {
      "command": "python3",
      "args": ["-m", "evergreen_assessment_mcp"],
      "cwd": "/absolute/path/to/usb/evergreen-assessment"
    }
  }
}
```

`tools/list` order is stable (`OPERATOR_TOOLS`). `farm_slot_status` may
filter with `params.arguments.category`. `farm_toolbin_status` adds
per-slot `live_ready` plus `live_ready_count` / `slots[]`. DEMO stubs
and file_drop-only names are never live-ready, even if a binary is
under `FARM_TOOL_BIN`. `keep_status` reports pack `in/` KEEP four-set honesty (`keep_real`
**0/4** when empty). One session: `keep_status` then `keep_ciso`.
`keep_ciso` is the operator SAMPLE entrypoint for
`python -m keep lab` / `./scripts/sample_to_sor.sh` (or `make sample-to-sor`
or `.\\scripts\\sample_to_sor.ps1`):
`fixtures/keep-samples` → `keep/work/out/ciso-assistant/*.csv` +
`IMPORT.json` + OpenGRC (`risks.csv` / `assets.csv` / `implementations.csv`)
+ Probo (`import_preview/probo.json`) + `handoff.json`. The JSON result
returns those SoR paths so the operator does not memorize keep-lab layout.
`keep_status` and `keep_ciso` also advertise the farm pack_drop twin
(`farm_drop_cli_twin`): `./scripts/farm_drop_to_sor.sh` /
`make farm-drop-to-sor` / `.\\scripts\\farm_drop_to_sor.ps1`
(`python3 scripts/prove_ciso.py` under `prove/work/`; never pack `in/`).
That hint does not run prove_ciso and does not invent KEEP. SAMPLE keep
remains the primary KEEP path. `tools/list` `keep_ciso` may take
`arguments.exporters` (same meaning as
the script `--exporters` re-write); sinks always come from keep-lab.
This week's slice does **not** densify pack `in/` and does **not** require
signed self-SCOPE. **SAMPLE≠client. DEMO≠client.** `tools/call` is plan-only
(ignores `arguments.live`). `orchestrator_plan` returns `will_run`
(`discover` / `deepen` / `external` → slot → bool). External entries stay
`false`.

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
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"keep_status"}}
```

```json
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"keep_ciso"}}
```

Optional `arguments.exporters` is accepted and documented only — sinks
already come from `keep.lab` (`export_keep_sinks`). It does not invent a
second export path. Same optional flag as `./scripts/sample_to_sor.sh --exporters`.
`farm_drop_cli_twin` is a sibling hint for `./scripts/farm_drop_to_sor.sh`
(`make farm-drop-to-sor` / `.\\scripts\\farm_drop_to_sor.ps1`); `keep_ciso`
does not execute that path.

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"AIExploitGenerator"}}
```

The last call returns a SCOPE gate error. `tools/call` never implies `--live`.
