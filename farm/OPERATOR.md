# Private farm operator path

**Written SCOPE required.** Drop-box only under written SCOPE. Not a public Hub image. Layer C parses `in/<sensor>/` only.

See `dropbox/ARCHITECTURE.md` Layer A / B / C.

## Copy-paste runbook (bare Linux → CISO zip)

```bash
# 0) repo root, no scanner install from this tree
cd /path/to/grc-collector-pack
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0

# 1) written SCOPE (copy example, fill client/consent/window/CIDRs)
# cp dropbox/SCOPE.example.yaml dropbox/SCOPE.yaml
python3 -m dropbox gate
python3 -m dropbox status

# 2) optional: tools YOU install (never this Dockerfile)
# export PATH="$PATH:/opt/farm/bin"
# export FARM_TOOL_BIN=/opt/farm/bin

# 3) DEMO path (fixtures, not a client) — plan → fixture discover → ingest → Layer C
make farm-lab

# 4) real engagement: drop artifacts into in/<sensor>/ (or farm/work/in), then:
python3 -m dropbox orchestrate          # plan-only unless --live + allowlisted PATH
# IN_DIR=$PWD/in OUT_DIR=$PWD/out python3 collectors/grc_loader.py

# 5) CISO zip from localhost console (after lab outputs exist)
# bash scripts/start-product.sh
# open http://127.0.0.1:18765/  → download drop zip (CISO CSVs + poam.csv)
# owner/due stay blank. Do not POST /api/risks. RiskReady is review-only.
```

`make farm-lab` writes under `farm/work/` (not pack `in/`). Stamp is DEMO.

## License classes (`SLOTS.yaml`)

| Class | Meaning |
|---|---|
| `use_dont_ship` | LICENSE-LOCK / do not embed. File-drop or BYO nmap/nessus only. |
| `commercial_byo` | Vendor CLI you licensed. We do not ship it. |
| `oss_byo` | OSS you installed. Missing → plan-only. |

Catalog is **95+** slots (`SLOTS.md`). LICENSE-LOCK names (nuclei, openvas, gvm, pingcastle, bloodhound, …) stay **file_drop**. Adapters never subprocess them.

kube-bench / gitleaks are **file_drop stubs** (callable, no subprocess). Drop JSON into `in/k8s/` / `in/code/`.

## Orchestrator + conductor

Stage graph (quiet→loud): `plan → shard → discover → destroy → deepen (2–5) → destroy → external (plan-only) → ingest → grc_export`

Plan JSON lists `slots` per stage: `allow_tools ∩ wired invoke ∩` discover / deepen / external.
`--live` discover runs only those discover invoke slots that are on PATH; missing → `skip_reason`.
Deepen uses deepen invoke slots on discover-live hosts or `deepen_hosts`.
**External is plan-only** in this pack: slots list with `will_run=false` and
`file_drop or plan-only — operator lands artifacts in in/easm|…`.
Ingest inventories those dropped files (`dropped_external` on the ingest
marker). It does not probe. `make dropbox-external` writes DEMO fixtures
into `in/easm/`. Live BYO curl/testssl is operator-local under written
SCOPE — not orchestrate.
LICENSE-LOCK / file_drop names never subprocess.

```bash
python3 -m dropbox orchestrate
python3 -m dropbox orchestrate --live   # BYO PATH only; still SCOPE-gated
python3 -m dropbox.mcp_stub serve
python3 -m dropbox mcp farm_slot_status
python3 -m dropbox mcp stage_discover    # plan-only
```

Cursor reads **`.cursor/mcp.json`** in the project (or `~/.cursor/mcp.json`
for a user-global entry). The conductor is **`dropbox.mcp_stub`** JSON-RPC
on stdin/stdout — **not** hosted FastMCP. `cwd` **and** `PYTHONPATH` must
be the **repo root** so `python3 -m dropbox.mcp_stub` resolves.

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

`tools/list` returns the nine operator tools in **fixed** `OPERATOR_TOOLS`
order (`scope_status`, `orchestrator_plan`, `orchestrator_status`,
`stage_discover`, `stage_deepen`, `stage_ingest`, `farm_slots`,
`farm_slot_status`, `export_ciso_poam`). `farm_slot_status` accepts an
optional `{ "category": "discover" }` argument.

Live deepen stays fail-closed (`DROPBOX_LIVE=0`) unless the operator
explicitly allowlists tools. Do not point this at public Layer C.

## Do not

- Publish `farm/` images to public Hub
- Apt-install scanners in `farm/Dockerfile`
- Copy USB evergreen-assessment
- Stamp paying-day PASS
- Submodule hexstrike-ai / add Metasploit
