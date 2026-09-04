# Private farm — operator layout only

**Not a public Docker Hub soup.** This directory is a drop-box farm Reid (or the operator) runs **under written SCOPE** on a consented box. The public pack stays parse-only (Layer C). Do not publish these compose files or private image tags as a scanner appliance.

See `dropbox/ARCHITECTURE.md` **Layer A** (BYO tool zoo). Layer B (orchestrator brakes) already schedules allowlisted PATH tools. This farm compose only documents **worker isolation volumes** and where Reid bind-mounts or tags tools he built himself.

## What lives here

| Path | Role |
|---|---|
| `SLOTS.yaml` | Allowlisted adapter slots (name, stage, sensor). **No binaries.** |
| `Dockerfile` | Orchestrator worker only (`python:3.12-slim` + COPY dropbox/shared). No `apt`. |
| `docker-compose.yml` | Isolation volumes + optional host `tool-bin` bind-mount. Demo/dry default. |
| `tool-bin/` | Empty mount point. Bind-mount host PATH tools here. Do not commit binaries. |

## How tools get onto the box

1. **Host PATH** — Reid installs nmap/nessus/testssl/… himself; SCOPE `allow_tools` names them.
2. **Bind-mount** — `FARM_TOOL_BIN=/usr/local/bin` (or `./tool-bin`) mounted read-only at `/opt/farm/bin`.
3. **Private image tags** — `FARM_ORCH_IMAGE` / optional `FARM_*_IMAGE` that **Reid builds**. Never pull a public “nmap soup” image in this file.

Missing binary → orchestrator stays **plan-only**. This repo never apt-installs, downloads, or vendors Nmap, Nessus, Nuclei, OpenVAS/GVM, or LICENSE-LOCK tools.

## Slots (adapters, not embeds)

nmap · nessus · testssl · curl · lynis · ss · ip · hardeningkitty-export · prowler · maester

Each slot maps to a Layer C **file sensor** (`in/nmap`, `in/easm`, `in/cloud`, …). The 10 public collectors stay parse-only.

## Run (private box, written SCOPE)

```bash
# static scanner-free (always):
python3 -c "from dropbox.scanner_free import assert_image_files_scanner_free; assert_image_files_scanner_free()"

# orchestrator plan-only (no Docker required):
python3 -m dropbox orchestrate

# compose skeleton — only if Docker is on this private box:
# docker compose -f farm/docker-compose.yml --profile orchestrate run --rm farm-orchestrator
```

`DROPBOX_LIVE=0` by default. Do not `--live` without SCOPE + allowlisted PATH tools.

## Do not

- Push `farm/` images to public Hub
- Apt-install scanners in `farm/Dockerfile`
- Copy USB evergreen-assessment
- POST `/api/risks` or restore RiskReady wrap
- Stamp paying-day PASS
- Submodule hexstrike-ai
