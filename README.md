# GRC collector pack

Authorized assessment (signed SCOPE) → evidence in CISO Assistant Community → POA&M + blank remediation quote. Not a GRC UI. Not Pentera.

Version `0.4.0`. Demo estate is **lab-sim**; `client_facing_ready` stays false until a real signed drop box + HITL.

```powershell
cd "C:\GRC Collector\grc-collector-pack"
$env:PYTHONPATH = (Get-Location)
python -m dropbox.product_demo --help
python -m dropbox.product_demo
# zip under engagements/
# import: docs/IMPORT_CISO.md
```

`--help` prints usage and exits. It does not hit the mock sink.

Docs: [SECURITY.md](SECURITY.md) · [NOTICE](NOTICE) (nmap use-don’t-ship, RiskReady stay-out) · [docs/HITL.md](docs/HITL.md) · [docs/LAB_WINDOW.md](docs/LAB_WINDOW.md) · [docs/IMPORT_CISO.md](docs/IMPORT_CISO.md) · [docs/IMPORT_RR.md](docs/IMPORT_RR.md) · [docs/IMPORT_PROBO.md](docs/IMPORT_PROBO.md) · [docs/OUT_DIR.md](docs/OUT_DIR.md) · [docs/PUBLISH.md](docs/PUBLISH.md)

Three layers, kept separate:

1. **Tool zoo (BYO)** — scanners live on Reid’s drop box under signed SCOPE. This pack does **not** embed Nmap, Nessus, Nuclei, or OpenVAS.
2. **Orchestrator = brakes** (`dropbox/`) — quiet discover, then louder deepen in batches of 2–5, worker tear-down, unsigned SCOPE refuses live stages. BYO nmap/nessus/testssl/curl are invoked only with signed SCOPE + `allow_live_exec` + `EVERGREEN_ORCH_LIVE=1` + binary on PATH (nmap `-sn` shards ≤256; deepen ≤5; no CIDR; curl HEAD-only). See `dropbox/OPERATOR.md`.
3. **Ingest pack** — ten demo-mode sensors parse OSS/fair-use **files** into **CISO Assistant Community** CSVs plus review-only RiskReady JSON and a POA&M/control-map export.

RiskReady wrap is **stay-out** (`push_riskready.*` never POSTs). SimpleRisk is a leave-behind import, not an API. Collectors never execute scanners (`GRC_LIVE_SCAN=1` is ignored).

License: MIT.

## Quick lab (Windows)

```powershell
cd "C:\GRC Collector\grc-collector-pack"
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File .\run_lab.ps1
```

That runs `pytest`, all collectors, the loader **twice** (idempotent count regression), then `tests\lab_outputs.py`. `run_lab.ps1` is the real lab entry on Windows; `make lab` is optional (Unix/WSL) and does not replace it.

## Safety flags

| Variable | Default | Meaning |
|---|---|---|
| `DRY_RUN` | `1` | Do not push to GRC products |
| `CISO_PUSH` | `0` | Must be `1` to upload CISO CSVs |
| `RISKREADY_PUSH` | `0` | Ignored. RiskReady wrap is WRAP_DEAD (no POST, even if set to `1`) |
| `GRC_LIVE_SCAN` | `0` | Collectors never scan; they parse `in/` or `fixtures/demo/` |

Drop sensor files in `in/<sensor>/`. If a folder is empty, the matching `fixtures/demo/<sensor>/` sample is used. If `in/<sensor>/` has any files, fixtures are not mixed in. Hostile junk (truncated JSON, blank Nuclei lines, nmap without hostnames) is skipped. `GRC_LIVE_SCAN=1` is ignored; collectors never execute scanners.

## Sensor formats

Each collector parses files already on disk. Empty `in/<sensor>/` falls back to `fixtures/demo/<sensor>/`. The loader (`grc_loader.py`) reads `out/canonical/*.jsonl` only.

| Sensor dir | Collector | Accepted files / shapes | Prefix |
|---|---|---|---|
| `in/cloud/` | `cloud_prowler.py` | Prowler JSON objects; Prowler CSV (`CHECK_ID`,`STATUS`,`SEVERITY`; PASS skipped); empty/`Status` uses `CheckStatus`; AWS ASFF `{Findings:[...]}`; finding status (`MANUAL` → `in_progress`, `WorkflowStatus`/`FindingStatus`) | `CLD-` |
| `in/nmap/` | `inventory_nmap.py` | Nmap XML (`<nmaprun>`, hostname `type=user` preferred over `PTR`; skip `<status state="down"/>`); grepable `.gnmap` / `.grep` (`# Nmap` / `Host:`) | `NMAP-` |
| `in/vuln/` | `vuln_scan.py` | Nuclei JSONL (`matched-at` URL-only → hostname; `ip` only when no `host`; `info.classification.cve-id` when template-id is not a CVE; empty `template-id` uses `template` / `template-path` CVE basename); Nuclei SARIF (`runs[].results`); OpenVAS/Greenbone XML (`<result>`, numeric CVSS `9.8` → critical; empty `<host>` text uses `ip=` attribute; `<cve>NOCVE</cve>` uses `<ref type="cve">` / `<cves>`); Nessus `.nessus` / `NessusClientData_v2` `ReportHost`/`ReportItem` (empty `host-fqdn` uses ReportHost name; plugin severity 0 skipped; CVE from `<cve>`) | `VULN-` |
| `in/wazuh/` | `host_wazuh.py` | Wazuh agents/alerts JSON (`status: Disconnected` / `Never connected`; `data.affected_items` / `alerts` with `rule.level` 0–15); Osquery `rows` / nested `columns` / `osquery` list of rows (`listening_ports`, `hostIdentifier`); SCA policy-checks JSON | `WAZ-` |
| `in/identity/` | `identity_ad.py` | BloodHound CE `data.nodes` / `data.edges` (or `data` as a node list + top-level `edges`); PingCastle XML `HealthcheckRiskRule` (empty `<Host>`/`<DomainFQDN>` text uses `DomainFQDN` attribute); PingCastle JSON `HealthcheckRisk` nodes (when XML is absent); ScubaGear `Results` and `Failed` arrays (Failed even when Results has Pass; empty CheckID uses `RelativePath` `#ms.*.*v1` fragment); BloodHound/PingCastle JSON `nodes` / `findings` | `ID-` |
| `in/easm/` | `easm.py` | Amass `.txt` / `.lst` host lines; Amass JSON/JSONL `{"name": "..."}` / `{"fqdn": "..."}`; Amass JSON `names` / `subdomains` / `domains` arrays; httpx JSONL (`host` / `url` + `status_code`; empty/`host` uses JSON `input` URL hostname); httpx URL-only strings (`https://host[:port]/path` → hostname); Subfinder JSON string lists and JSONL `{"host": "..."}` objects | `EASM-` |
| `in/k8s/` | `k8s_kubescape.py` | Kubescape `resources` / `results` / `summaryDetails` / `failedControls` (controlID, no resources array); kube-bench `Controls` (`FAIL`/`Fail`/`Failed` case-insensitive; hyphenated `test-number` / `test-result`; top-level `tests` with no wrapping Controls, PASS skipped) | `K8S-` |
| `in/code/` | `code_secrets.py` | Gitleaks JSON (`RuleID`; empty RuleID uses `Fingerprint` `file:rule:line` or `DetectorName`; empty `File` uses `Source`) and SARIF (`runs[].results` `ruleId`, snippets redacted); Trivy `Results` (Vulnerabilities + Secrets, values `[REDACTED]`; `Misconfigurations` FAIL only, PASS skipped; `package-lock.json` paths are SP only); Semgrep `results` / SARIF `runs[].results` (`ruleId` + `level`); YAML/JSONL `aws_secret_access_key` redacted in `out/raw` | `CODE-` |
| `in/saas/` | `saas_idp.py` | Combined JSON with `m365` and/or `okta` objects; Okta `/api/v1/users` list (`credentials.provider` MFA gap, no live API); Microsoft Graph `userRegistrationDetails` (`isMfaRegistered`, no live API) | `SAAS-` |

## Outputs

- `out/canonical/*.jsonl` — `kind` in `asset|finding|evidence|incident`
- `out/evidence/{sensor}.md` — one markdown evidence file per sensor after lab (nine sensors)
- `out/ciso-assistant/*.csv` — exact CISO Assistant headers (`risk_scenarios.csv` is semicolon-delimited)
- `out/riskready/*.json` — assets, incidents, evidence, plus review-only `risks_proposed.json`
- `out/ocsf/compliance_findings.json` — OCSF class_uid `2003`
- `out/summary.json` — counts
- `out/poam/poam.csv` + `MANIFEST.json` — POA&M/control-map (fixture-labeled; also `product-lab/drop/poam/`)

Asset `type` is `PR` or `SP`. Finding severity is `info|low|medium|high|critical` (CSV findings omit `info`). Finding CSV `status` is `open|closed|in_progress` (sensor aliases such as `NEW`/`RESOLVED`/`MANUAL` are normalized). Vulnerability severity uses `Information|Low|Medium|High|Critical`.

## Docker

```powershell
docker compose up --build
```

One `python:3.12-slim` image, nine collector services, loader `depends_on` `service_completed_successfully`. Optional: not required for the local Python lab.

## Push (still off by default)

```powershell
$env:CISO_PUSH = "0"
powershell -ExecutionPolicy Bypass -File .\push_ciso.ps1
$env:RISKREADY_PUSH = "0"
powershell -ExecutionPolicy Bypass -File .\push_riskready.ps1
# RISKREADY_PUSH=1 still does not POST (WRAP_DEAD, exit 2)
```

```bash
# Git Bash / WSL
CISO_PUSH=0 ./push_ciso.sh
RISKREADY_PUSH=0 ./push_riskready.sh
```

RiskReady wrap is stay-out. `push_riskready.ps1` / `.sh` never POST (assets, incidents, evidence, auth, or `/api/risks`). `out/riskready/*.json` including `risks_proposed.json` is human review only. CISO auto-push (`CISO_PUSH=1`) is **assets.csv + evidences.csv only**; findings/POA&M are HITL clica/UI. POA&M: `out/poam/poam.csv`. Quote stub: `out/quote/quote.csv` (hours/rate/total blank). SimpleRisk leave-behind: `out/simplerisk/risks_import.csv` (no API). Client-facing send stays false until `dropbox/out/HITL.json` has `"attested": true`.

Operator console (localhost only): `python -m dropbox.orchestrator console` → http://127.0.0.1:18765/

MCP hook (not a public attack API): `python -m dropbox.orchestrator mcp --action plan --scope dropbox/SCOPE.example.yaml` (exploit/spray denied).
