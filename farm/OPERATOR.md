# Private farm operator path

**Written SCOPE required.** This is a drop-box Reid runs on a consented box under written SCOPE. Not a public Hub image. Not a scanner appliance. Layer C (the 10 public collectors) only parse files that land in `in/<sensor>/`.

See `dropbox/ARCHITECTURE.md` Layer A / B / C.

## 1. Install tools on the drop box (you, not this repo)

Install allowlisted binaries **on the host** (or a private image tag you build). This repo never apt-installs Nmap, Nessus, Nuclei, OpenVAS/GVM, or LICENSE-LOCK tools.

```bash
# examples only — you choose packages and licenses
# nmap nessus testssl lynis prowler trivy …
export PATH="$PATH:/opt/farm/bin"
export FARM_TOOL_BIN=/opt/farm/bin   # optional bind-mount source
```

Put extra wrappers in `farm/tool-bin/` **outside git** (directory is a mount point). Do not commit binaries.

License classes in `SLOTS.yaml`:

| Class | Meaning |
|---|---|
| `use_dont_ship` | LICENSE-LOCK / do not embed. Operator may already have it. File-drop or BYO nmap/nessus only. |
| `commercial_byo` | Vendor CLI you licensed (Nessus, PingCastle, …). We do not ship it. |
| `oss_byo` | OSS you installed. Missing → plan-only. |

`scope_key: file_drop` slots are **not** invoked. Drop their output files into the listed `output_glob`.

## 2. SCOPE

Copy `dropbox/SCOPE.example.yaml` → `dropbox/SCOPE.yaml`. Fill client, consent hash, window, named CIDRs/hosts. List PATH tools in `allow_tools`. Keep `orchestrator.stages.deepen` false until you intend the loud stage.

```bash
python3 -m dropbox gate
python3 -m dropbox status
```

Status prints `allow_tools ∩ PATH ∩ SLOTS` (present / missing / not-in-slots).

## 3. Orchestrator (brakes)

Stage graph:

`plan → shard → discover (quiet) → destroy → deepen (loud, gated 2–5) → destroy → ingest → grc_export`

```bash
# plan-only (default; safe when binaries are missing)
python3 -m dropbox orchestrate

# live BYO only if allowlisted AND on PATH — still SCOPE-gated, no 0.0.0.0/0
python3 -m dropbox orchestrate --live
```

Discover is quiet (`nmap -sn` + host timeout) when nmap is allowlisted and present. Deepen refuses unless `stages.deepen: true`. Workers are destroyed after each stage. Artifacts copy into `in/<sensor>/` for Layer C.

## 4. Conductor (stdio MCP)

Hexstrike-shaped UX, Evergreen rails. No exploit tools. No hexstrike-ai.

```bash
python3 -m dropbox.mcp_stub serve           # list tools
python3 -m dropbox.mcp_stub serve --stdio   # JSON-RPC loop on stdin
python3 -m dropbox mcp scope_status
python3 -m dropbox mcp farm_slots
python3 -m dropbox mcp orchestrator_plan    # never --live
```

Claude / Cursor MCP snippet (private box):

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

## 5. Layer C ingest sink

After files are in `in/`:

```bash
python3 -m pytest tests -q
# collectors + loader → out/ciso-assistant/ + out/poam/poam.csv (owner/due blank)
```

Do not turn collectors into scanners. Do not POST `/api/risks`. RiskReady stays review-only.

## Do not

- Publish `farm/` images to public Hub
- Apt-install scanners in `farm/Dockerfile`
- Copy USB evergreen-assessment
- Stamp paying-day PASS
- Submodule hexstrike-ai / add Metasploit
