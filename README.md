# grc-collector-pack

[![lab](https://github.com/eregular13/grc-collector-pack/actions/workflows/lab.yml/badge.svg)](https://github.com/eregular13/grc-collector-pack/actions/workflows/lab.yml)

The product is a **local operator console** plus ten collectors that emit files **CISO Assistant Community** and **RiskReady Community Edition** already ingest. This is not CISO Assistant and not RiskReady.

Double-click `Start-GRC-Pack.cmd` or, from the clone root:

```powershell
python -m product
```

Then open **http://127.0.0.1:18765/**. You get the estate (assets, findings, vulns, proposed risks), a refresh that re-runs collectors on local files, and a drop zip for import. The console binds localhost only. It never POSTs `/api/risks`.

This is not a GRC platform and not an eleventh Docker service. Demo mode is the default: zero credentials, zero live scans. Collectors parse `in/<sensor>/` or fall back to `fixtures/demo/`. Demo fixtures only until you drop files in `in/`.

See [SECURITY.md](SECURITY.md). Stranger clone path: [docs/PUBLIC_CLONE.md](docs/PUBLIC_CLONE.md).

## Ten containers

| Service | Input | Output |
|---|---|---|
| cloud-prowler | `in/cloud/*.json` Prowler | cloud assets + misconfig findings |
| inventory-nmap | `in/nmap/*.xml` | hosts + exposure findings |
| vuln-scan | Nuclei / Trivy / Greenbone | CVE findings |
| host-wazuh | Wazuh / osquery JSON | coverage gaps + incidents |
| identity-ad | BloodHound / PingCastle | privileged identity findings |
| easm | Amass / Subfinder / httpx | external hosts |
| k8s-kubescape | Kubescape / kube-bench | cluster findings |
| code-secrets | Gitleaks / Semgrep / Trivy | secrets / SAST (redacted) |
| saas-idp | ScubaGear / Graph / Okta / Maester (file-drop; no Graph/Okta API) | SaaS posture |
| grc-loader | `out/canonical/*.jsonl` | all GRC files |

One `python:3.12-slim` image. `grc-loader` waits on the nine collectors (`condition: service_completed_successfully`).

```bash
docker compose up --build
```

Local lab (no Docker):

```bash
python -m pytest tests -q
set OUT_DIR=%CD%\out
set PYTHONPATH=%CD%
python collectors/cloud_prowler.py
python collectors/inventory_nmap.py
python collectors/vuln_scan.py
python collectors/host_wazuh.py
python collectors/identity_ad.py
python collectors/easm.py
python collectors/k8s_kubescape.py
python collectors/code_secrets.py
python collectors/saas_idp.py
python collectors/grc_loader.py
python tests/lab_outputs.py
```

Or `make lab` (`PYTHON=python` on Windows, `python3` on Linux) or `scripts/lab.sh` / `scripts/lab.ps1`.

Consented drop-box (internal + external → `in/`): `dropbox/OPERATOR.md`. `make dropbox-lab` is fixtures + demo overlays, not a client estate.

## Private drop-box farm

Consented operator path — not the public parse-only pack. Three layers
([dropbox/ARCHITECTURE.md](dropbox/ARCHITECTURE.md)): **Layer A** BYO tools
under written SCOPE, **Layer B** orchestrator brakes, **Layer C** ten
parse-only collectors.
Short runbook: [farm/QUICKSTART.md](farm/QUICKSTART.md).
`make farm-toolbin-e2e` is DEMO stubs (`demo: true`) — **not a client estate**.
Real `--live` only on a consented drop box with tools you installed.

Overnight improve ticks: `LOOP.md` (every 30 minutes until 07:00 Pacific). Each tick reads STATUS / FAULTS / CRITIC and adds one parser or test, then re-labs.

## Outputs

- `out/canonical/*.jsonl` — `asset|finding|evidence|incident`
- `out/ciso-assistant/` — `assets.csv` `applied_controls.csv` `evidences.csv` `findings.csv` `vulnerabilities.csv` `risk_scenarios.csv` (semicolon)
- `out/poam/` — `poam.csv` `poam.md` (owner/due blank; human fills). Pentera finds it; Evergreen maps it.
- `out/riskready/` — `assets.json` `incidents.json` `evidence.json` `risks_proposed.json`
- `out/ocsf/compliance_findings.json` — OCSF-like Compliance Finding (`class_uid` 2003)
- `out/summary.json` `out/evidence/lab-report.md`

## CISO Assistant

Auth: `Authorization: Token <PAT>` — API `http://localhost:8000/api`

CSV headers (exact):

- assets: `ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets` (`type` = `PR|SP`)
- applied_controls: `ref_id,name,description,domain,status,category,priority,csf_function`
- evidences: `name,description`
- findings: `ref_id,name,description,severity,status,filtering_labels` (`low|medium|high|critical`)
- vulnerabilities: `ref_id,name,description,status,severity,assets,applied_controls` (`Information|Low|Medium|High|Critical`)
- risk_scenarios: semicolon, `treatment=mitigate`

CISO Assistant is Reid-side SoR. Prefer [clica](https://github.com/intuitem/ciso-assistant-community) or the UI CSV import. Do not invent FindingsAssessment UUIDs. `push_ciso.sh` defaults to dry-run; if `CISO_PUSH=1` and `DRY_RUN!=1` it may POST `/api/assets/` and `/api/evidences/` only.

## RiskReady — LICENSE-LOCK stay-out

This pack **never wraps or runs RiskReady**. `push_riskready.sh` is review-only even if `RISKREADY_PUSH=1`: no login, no HTTP client, no POST. Humans review:

- `out/riskready/assets.json`
- `out/riskready/evidence.json`
- `out/riskready/incidents.json`
- `out/riskready/risks_proposed.json` — **never** auto-POST `/api/risks`

Do not restore wrap POSTs to `/api/auth/login`, `/itsm/assets`, `/evidence`, `/incidents`, or `/api/risks`. Tests fail if those reappear.

## Mapping

| Sensor | CISO Assistant | RiskReady |
|---|---|---|
| Cloud / K8s / SaaS failed checks | findings + OCSF + applied_controls | incidents + proposed risks |
| Nmap / Wazuh / EASM hosts | assets PR/SP + exposure findings | ITSM assets |
| High/critical + key medium (SMB/RDP) | applied_controls + `out/poam/poam.csv` (CPG/CSF) | review-only if high/crit |
| Nuclei / Trivy / Gitleaks | vulnerabilities | incidents if high/crit |
| Coverage / identity gaps | findings | incidents |
| Every run | evidences | evidence DRAFT |

## Drop real scanner output

Copy tool JSON/XML/JSONL into the matching `in/` folder (`cloud`, `nmap`, `vuln`, `wazuh`, `identity`, `easm`, `k8s`, `code`, `saas`). Empty `in/` uses `fixtures/demo/` and labels include `demo`. Parse failure falls back to fixtures.

OSS / fair-use only (Prowler, Nmap, Nuclei, Trivy, Wazuh, BloodHound CE, Amass, Kubescape, Gitleaks, ScubaGear, official cloud APIs, …). No Wiz / Orca / Prisma / CrowdStrike / Qualys / Tenable / Vanta / Drata required.

## Security

The console is localhost only (`127.0.0.1`). Non-loopback binds exit 2. Report vulnerabilities via a GitHub Security Advisory. Full policy: [SECURITY.md](SECURITY.md).

- `CISO_PUSH=0` `RISKREADY_PUSH=0` `GRC_LIVE_SCAN=0` `DRY_RUN=1`
- Never POST `/api/risks`. High/critical → `risks_proposed.json` only
- Never live-scan. Secrets redacted as `[REDACTED]`
- MIT license

Copy `.env.example` to `.env` (gitignored).

## Resume

`/next` reads `STATUS.md` and continues the agent graph. Stop hook `.cursor/hooks/keep_going.py` (via `.cursor/hooks/keep_going.cmd` on Windows) follow-ups until `DONE.md` line 1 is `GREEN`. Enable project hooks in Cursor Settings → Hooks, trust the workspace; restart Cursor if the stop hook is not listed.
