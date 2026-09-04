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

Stage graph (quiet→loud): `plan → shard → discover → destroy → deepen (2–5) → destroy → ingest → grc_export`

```bash
python3 -m dropbox orchestrate
python3 -m dropbox.mcp_stub serve
python3 -m dropbox mcp farm_slot_status
python3 -m dropbox mcp stage_discover    # plan-only
```

Claude / Cursor MCP snippet:

```json
{
  "mcpServers": {
    "evergreen-dropbox": {
      "command": "python3",
      "args": ["-m", "dropbox.mcp_stub", "serve", "--stdio"],
      "env": {
        "DROPBOX_LIVE": "0",
        "GRC_LIVE_SCAN": "0",
        "CISO_PUSH": "0",
        "RISKREADY_PUSH": "0"
      }
    }
  }
}
```

## Do not

- Publish `farm/` images to public Hub
- Apt-install scanners in `farm/Dockerfile`
- Copy USB evergreen-assessment
- Stamp paying-day PASS
- Submodule hexstrike-ai / add Metasploit
