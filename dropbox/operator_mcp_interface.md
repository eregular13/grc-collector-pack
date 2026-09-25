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
| `keep_status` | `keep.adapters.scan_keep_dir` on pack `in/{identity,saas,vuln,cloud}/` | Empty pack `in/` is `keep_real` **0/4**. Lab path is `fixtures/keep-samples` (SAMPLE≠client). HardeningKitty / Maester / testssl / Prowler\|ScoutSuite detect only. Advertises operator twins as hints only: `cli_twin` (`./scripts/sample_to_sor.sh` / `make sample-to-sor` / `.\scripts\sample_to_sor.ps1`), `farm_drop_cli_twin` (`./scripts/farm_drop_to_sor.sh` / `make farm-drop-to-sor` / `.\scripts\farm_drop_to_sor.ps1`), and `lab_drop_cli_twin` (`./scripts/lab_drop_to_sor.sh` / MCP `lab_drop` / prove `--use-existing-in`; no Makefile first-line). **Does not densify pack `in/`.** Does not invent non-sample files. Does not require signed self-SCOPE. **LAB≠SAMPLE≠client. SAMPLE≠client. DEMO≠client.** paying_day FAIL |
| `keep_ciso` | `keep.lab.keep_lab` SAMPLE path (`python -m keep lab`) | **SAMPLE keep-lab only:** `fixtures/keep-samples` → `keep/work/out/ciso-assistant/*.csv` + `IMPORT.json` + OpenGRC CSVs + Probo preview + `eval/handoff.json`. Return lists every SoR path (`ciso_dir` / `ciso_files` / `ciso_import` / `opengrc` / `probo`) plus `cli_twin` (`./scripts/sample_to_sor.sh` or `make sample-to-sor` or `.\scripts\sample_to_sor.ps1`), `farm_drop_cli_twin` (`./scripts/farm_drop_to_sor.sh` / `make farm-drop-to-sor` / `.\scripts\farm_drop_to_sor.ps1` — hint only; this tool does not run prove_ciso), and `lab_drop_cli_twin` (`./scripts/lab_drop_to_sor.sh` / MCP `lab_drop` — hint only). `arguments.exporters` is optional (script `--exporters` re-write); sinks always come from keep-lab — no second export path. `arguments.isolate_work` is optional unique work subdirectory (default on for shared `keep/work` so overlapping ticks do not share `out/`). Fail path returns `stderr` / last error; one retry on WinError 145 / ENOTEMPTY only — never `ok` true if still failing. `DRY_RUN=1` `GRC_LIVE_SCAN=0` `CISO_PUSH=0` `RISKREADY_PUSH=0`. Stamps demo/sample. **Never writes / densifies pack `in/`.** Never POST `/api/risks`. Never spawns scanners. No signed self-SCOPE densify. **SAMPLE≠client. DEMO≠client. LAB≠SAMPLE.** paying_day FAIL |
| `lab_drop` | `scripts/prove_ciso.py --use-existing-in` (`lab_drop_to_sor`) | **LAB dest_in only:** requires populated `arguments.work`/`in` or `arguments.dest_in`. Never reseeds `fixtures/pack_drop`. Empty `in/` (or banners only) is `EXISTING_IN_FAIL`. `LAB.txt` (or nmap pack_drop `lab:true`) + DEMO seed trees (`honeypot/` / fixtures pack_drop siblings) is `LAB_SHAPE_FAIL`. Returns honesty stamps (`lab=true` `seeded=false` `sample=false` `client=false` `paying_day=FAIL`) plus `ciso_dir` / `ciso_files` / `poam` / `prove` / `out`. Operator twin = `./scripts/lab_drop_to_sor.sh` / `.\scripts\lab_drop_to_sor.ps1` (no Makefile first-line). Console twin = `console_cli_twin` / `console_hint`: `OUT_DIR=<work>/out python -m product` (Windows `set OUT_DIR=...` / `python -m product`; Active out/ picker / `PROVE_WORK_ROOT`). Bind `127.0.0.1`. Never POSTs `/api/risks`. DESKTOP one-shot scan→SoR→console (`scan-to-console.ps1`) is the same SoR rails after pack_drop lands in `work/in`. **LAB≠SAMPLE≠client.** Never writes pack `in/`. Never POST. Does not invent `client=true`. |
| `scan_to_sor` | gate → fixture `scan_and_pack` (LAB `fixtures/lab-drop`) **or** opt-in live `run_live_collectors` (`python -m dropbox run --profile all --live`) → `prove_ciso --use-existing-in` | **One-shot scan→pack→SoR** twin of the operator scan-and-sor path (DESKTOP EvergreenOps `scan-to-console.ps1` against lab-estate). Signed SCOPE + authorized targets are checked **before** any scanner/collector. Default `GRC_LIVE_SCAN` unset/0/false stages fixtures. Opt-in `GRC_LIVE_SCAN=1` runs existing dropbox collectors against gated lab-estate targets only (`estate=lab`; DESKTOP `192.168.64.0/24`). Refusal is `{ok:false, refused:true, reason, live}`. Success returns `risk_register` / `poam` / `pack_drop` / `live` plus `cli_twin`. Never writes pack `in/`. Never POSTs `/api/risks`. **LAB≠SAMPLE≠client.** |

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
python3 -m dropbox mcp lab_drop
python3 -m dropbox mcp scan_to_sor
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
or `.\scripts\sample_to_sor.ps1`):
`fixtures/keep-samples` → `keep/work/out/ciso-assistant/*.csv` +
`IMPORT.json` + OpenGRC (`risks.csv` / `assets.csv` / `implementations.csv`)
+ Probo (`import_preview/probo.json`) + `handoff.json`. The JSON result
returns those SoR paths so the operator does not memorize keep-lab layout.
`keep_status` and `keep_ciso` also advertise the farm pack_drop twin
(`farm_drop_cli_twin`): `./scripts/farm_drop_to_sor.sh` /
`make farm-drop-to-sor` / `.\scripts\farm_drop_to_sor.ps1`
(`python3 scripts/prove_ciso.py` under `prove/work/`; never pack `in/`)
and the LAB dest_in twin (`lab_drop_cli_twin`):
`./scripts/lab_drop_to_sor.sh` / MCP `lab_drop` /
`python3 scripts/prove_ciso.py --use-existing-in` (no Makefile
first-line; never reseeds). Farm/SAMPLE hints do not run prove_ciso
and do not invent KEEP. `lab_drop` is the callable LAB path.
SAMPLE keep remains the primary KEEP path. LAB≠SAMPLE≠client. `tools/list` `keep_ciso` may take
`arguments.exporters` (same meaning as
the script `--exporters` re-write); sinks always come from keep-lab.
`arguments.isolate_work` (or `KEEP_CISO_ISOLATE`) is an optional unique
work subdirectory under `keep/work` or the supplied `work` so overlapping
`keep_ciso` calls do not share `out/`. Default on when work is the shared
`keep/work`. Not a new CLI script. When `keep_status` / `keep_ciso` / `lab_drop` fail,
MCP/conductor return `stderr` (or last error text). One retry on
transient wipe / Windows directory errors only; still-nonzero stays `ok`
false and CLI/`tools/call` exit/error code 2.
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

```json
{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"lab_drop","arguments":{"work":"/abs/lab-work"}}}
```

```json
{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"lab_drop","arguments":{"lab_out":"/abs/lab-estate/out"}}}
```

Without `work`/`dest_in`, `lab_drop` auto-hints `LAST_LAB_PROVE.txt` under `lab_out` (or env `LAB_ESTATE_OUT` / `LAST_LAB_PROVE`). It returns `auto_hint=true` `ran=false` plus `console_cli_twin` pointed at that `lab-prove-*` stamp. It does **not** re-run prove and does **not** seed `fixtures/pack_drop`. Call with `arguments.work` to prove. `python -m product` with `OUT_DIR` unset prefers the same `LAST_LAB_PROVE` / `LAB_ESTATE_OUT` stamp.

Optional `arguments.exporters` is accepted and documented only — sinks
already come from `keep.lab` (`export_keep_sinks`). It does not invent a
second export path. Same optional flag as `./scripts/sample_to_sor.sh --exporters`.
`farm_drop_cli_twin` is a sibling hint for `./scripts/farm_drop_to_sor.sh`
(`make farm-drop-to-sor` / `.\scripts\farm_drop_to_sor.ps1`); `keep_ciso`
does not execute that path.
`lab_drop_cli_twin` / MCP `lab_drop` is the LAB dest_in sibling
(`./scripts/lab_drop_to_sor.sh`; prove `--use-existing-in`). Empty `in/`
is `EXISTING_IN_FAIL`. `LAB.txt` + DEMO reseed trees is `LAB_SHAPE_FAIL`.
On success, `lab_drop` also returns `console_cli_twin` / `console_hint`
so the operator console stays a twin of that prove `out/`:
`OUT_DIR=<work>/out python -m product` (Windows `set OUT_DIR=...` /
`python -m product`). Active out/ picker / `PROVE_WORK_ROOT` lists
sibling prove `out/` dirs. Bind `127.0.0.1`. Never POSTs `/api/risks`.
DESKTOP one-shot scan→SoR→console (`scan-to-console.ps1`) is the same
SoR rails after pack_drop lands in `work/in` — not a new Makefile
entrypoint, not a DEMO reseed, not `client=true`.
MCP `lab_drop` ≡ `lab_drop_to_sor` ≡ console pointed at that `out/`.

## scan_to_sor parity (operator scan-and-sor)

One MCP tool for the operator one-shot **scan → pack → risk register + POA&M**
path. Same SoR rails as `lab_drop` / `lab_drop_to_sor` after pack_drop lands.
DESKTOP operators run the twin from `C:\Users\R\Desktop\EvergreenOps` against
the lab-estate (`scan-to-console.ps1`). This stub does **not** add a new shell
entrypoint. Live collectors stay **opt-in** via `GRC_LIVE_SCAN` (default off).

| | |
|---|---|
| Tool | `scan_to_sor` |
| Args | `scope` (default `dropbox/SCOPE.yaml` / `DROPBOX_SCOPE` / `--scope`); `targets` / `target` (default `SCOPE.internal_hosts`); `out` (default `<work>/out`); `work` (isolated under `prove/work/scan-to-sor-*`; never pack `in/`); `estate` (default `lab` / `lab-estate`) |
| Flag | `GRC_LIVE_SCAN` env. Unset / `0` / `false` / `no` / `off` = fixture mode (today). `1` / `true` / `yes` / `on` = live mode after the SCOPE gate. Not default-on in CI / Makefile / scripts. |
| Return (ok) | `{ok:true, refused:false, live:true\|false, risk_register, poam, poam_md, pack_drop, out, work, dest_in, cli_twin, lab:true, sample:false, client:false, paying_day:FAIL, posted:false, http:false}` |
| Return (refusal) | `{ok:false, refused:true, live:true\|false, reason:"SCOPE gate: …", fail_code, scanned:false, wrote_out:false}` — nothing scanned, nothing written to `out/` |
| CLI twin | Fixture: `python -m dropbox run --profile all && ./scripts/lab_drop_to_sor.sh --work DIR` (Windows: `python -m dropbox run --profile all; .\scripts\lab_drop_to_sor.ps1 -Work DIR`). Live: `GRC_LIVE_SCAN=1 python -m dropbox run --profile all --live && ./scripts/lab_drop_to_sor.sh --work DIR`. No Makefile first-line. No new `scan_to_sor.sh`. |
| Refusal cases | no SCOPE file / unreadable (`SCOPE_MISSING`); unsigned or attestation hash invalid (`SCOPE_UNSIGNED`); expired engagement window (`SCOPE_EXPIRED`); requested target outside authorized SCOPE (`SCOPE_TARGET`); live + estate other than lab / lab-estate (`LIVE_ESTATE`); live + target outside DESKTOP lab-estate networks `192.168.64.0/24` (`LIVE_LAB_NET`) |

```json
{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"scan_to_sor","arguments":{"scope":"dropbox/SCOPE.yaml","targets":["127.0.0.1"],"out":"out","estate":"lab"}}}
```

Signed SCOPE is checked **before** `scan_and_pack` / `run_live_collectors`.
Default (flag off) stages `fixtures/lab-drop` (scan-shaped pack_drop, labeled
LAB — never client KEEP) then `prove_ciso --use-existing-in`. Live mode
(`GRC_LIVE_SCAN=1`) reuses existing `python -m dropbox run --profile all --live`
collectors against **only** the targets that passed the gate, then the same
prove path. Live is lab-estate only: `estate=lab` (alias `lab-estate`) and
targets must sit in the DESKTOP lab-estate network allowlist
`192.168.64.0/24` (from `fixtures/lab-drop` / `docs/PROVE_CISO.md` — not
invented client nets) **and** the signed SCOPE. `cli_twin` reflects live vs
fixture. Never reseeds `fixtures/pack_drop` as client KEEP. Never writes pack
`in/`. Never POSTs `/api/risks`. Bind stays off this tool. **LAB≠SAMPLE≠client.**

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"AIExploitGenerator"}}
```

The last call returns a SCOPE gate error. `tools/call` never implies `--live`.
