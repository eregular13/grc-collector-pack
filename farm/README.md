# Private farm — operator layout only

**Not a public Docker Hub soup.** This directory is a drop-box farm Reid (or the operator) runs **under written SCOPE** on a consented box. The public pack stays parse-only (Layer C). Do not publish these compose files or private image tags as a scanner appliance.

See `dropbox/ARCHITECTURE.md` **Layer A** (BYO tool zoo), `farm/QUICKSTART.md` (consent → e2e → CISO zip), and `farm/OPERATOR.md` for the install → mount → orchestrate path. Layer B (orchestrator brakes) already schedules allowlisted PATH tools. This farm compose documents **short-lived worker isolation** (discover / deepen / ingest volumes + internal network).

## What lives here

| Path | Role |
|---|---|
| `SLOTS.yaml` | 95+ adapter slots (id, binary, stage, SCOPE key, output glob, license). **No binaries.** |
| `SLOTS.md` | Category counts: wired vs file_drop. |
| `adapters/` | Thin callable stubs for wired slots. Plan-only if missing. |
| `QUICKSTART.md` | ≤40-line consent → SCOPE → tool-bin → e2e → CISO zip. |
| `OPERATOR.md` | How Reid installs tools, mounts `FARM_TOOL_BIN`, runs quiet→loud. |
| `INTEGRITY.md` | Brakes defaults table (SCOPE, deepen, workers, batch, timeout). |
| `Dockerfile` | Orchestrator worker only (`python:3.12-slim` + COPY). No `apt`. |
| `docker-compose.yml` | Isolation volumes + optional host `tool-bin` bind-mount. Demo/dry default. |
| `tool-bin/` | Empty mount point + `lab/` DEMO stubs (`nmap`/`curl` shell scripts). Bind-mount or copy real binaries here. |

## How tools get onto the box

1. **Host PATH** — Reid installs nmap/nessus/testssl/… himself; SCOPE `allow_tools` names them.
2. **Bind-mount** — `FARM_TOOL_BIN=/usr/local/bin` (or `./tool-bin`) mounted read-only at `/opt/farm/bin`.
3. **Private image tags** — `FARM_ORCH_IMAGE` that **Reid builds**. Never pull a public “nmap soup” image in this file.

Missing binary → orchestrator stays **plan-only**. This repo never apt-installs, downloads, or vendors Nmap, Nessus, Nuclei, OpenVAS/GVM, or LICENSE-LOCK tools.

## Slots (adapters, not embeds)

Wired invoke stubs: nmap · nessus · nessuscli · testssl · lynis · ss · ip · prowler · trivy · rustscan · naabu · httpx · dig · whois · sslscan · openssl · nslookup · ping · traceroute · tracepath · host · getent · hostname · journalctl · kubectl (client) · snmpwalk (named-host)

Also wired: hardeningkitty-export · maester · testssl.sh. File-drop stubs: kube-bench · gitleaks. nikto / gobuster / ffuf / amass / subfinder / scoutsuite / checkov stay file_drop. Header grabber is a separate wired slot.

kube-bench / gitleaks are file_drop stubs (no subprocess). LICENSE-LOCK names (nuclei, openvas, pingcastle, …) stay file-drop only. The 10 public collectors stay parse-only.

## Run (private box, written SCOPE)

```bash
# static scanner-free (always) — pack + farm + dropbox:
make dropbox-compose
make farm-compose

# orchestrator plan-only (no Docker required):
python3 -m dropbox orchestrate

# compose skeleton — only if Docker is on this private box:
# docker compose -f farm/docker-compose.yml --profile orchestrate run --rm farm-orchestrator
```

Without Docker CLI both compose labs stamp **ABSENT** after static PASS.
That is not a runtime compose pass.

`DROPBOX_LIVE=0` by default. Do not `--live` without SCOPE + allowlisted PATH tools.

## Do not

- Push `farm/` images to public Hub
- Apt-install scanners in `farm/Dockerfile`
- Copy USB evergreen-assessment
- POST `/api/risks` or restore RiskReady wrap
- Stamp paying-day PASS
- Submodule hexstrike-ai
