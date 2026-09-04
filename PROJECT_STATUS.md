# grc-collector-pack — detailed project status

**Written:** 2026-09-03 21:24 America/Los_Angeles  
**Repo:** `C:\Users\R\grc-collector-pack`  
**Authoritative live counts:** `out/summary.json` (generated 2026-09-03T05:02:06Z)

Short agent cards: `STATUS.md`, `CYCLE.md`, `CRITIC.md`, `FAULTS.md`, `DONE.md`, `DONE_CYCLE5.md`, `DONE_IMPROVE.md`, `LOOP.md`, `docs/EXCEPTIONS.md`.

---

## One-sentence status

The pack is **shipped and GREEN**. Cycle 5 was labbed and stamped. The KEEP improve window is GREEN. Cycle 7 added Graph / kube-bench / httpx coverage and wizard-safe `cpg_2_W` labels. Last verified lab: **39 pytest passed**, **62 assets / 59 findings / 15 vulns / 10 evidence**. Critic **10/10**. Overnight 30-minute loop is **stopped**. This is **not** Evergreen paying-day / LinkedIn / Origin Eval.

---

## What this project is

Sensors + normalizer only. Not a GRC UI.

Ten Docker Compose services (one `python:3.12-slim` image) parse OSS scanner artifacts from `in/<sensor>/` or, when empty, `fixtures/demo/`. They write canonical JSONL. `grc-loader` emits files that **CISO Assistant Community** and **RiskReady Community Edition** already ingest.

Defaults: no credentials, no live scans, no sockets in collectors. High/critical findings go to `out/riskready/risks_proposed.json` only. Nothing POSTs `/api/risks`. MIT. No Wiz / Orca / Prisma / CrowdStrike / Qualys / Tenable / Vanta / Drata required deps.

---

## Gate files

| File | Line 1 / state | Meaning |
|---|---|---|
| `DONE.md` | `GREEN` | Original ship gate. Counts now match cycle 7 `summary.json` (62 / 59 / 15 / 10). |
| `DONE_CYCLE5.md` | `GREEN` | Cycle 5 lab proved BloodHound edges, Fleet, SARIF (31 tests, 60 / 54). |
| `DONE_IMPROVE.md` | `GREEN` | KEEP-HK, KEEP-MAESTER, KEEP-TESTSSL, KEEP-ASFF2 each have fixture + passing parser test. |
| `STATUS.md` | cycle 7, phase STOP | Last item `README-WEAK`. `next_action`: Grype or CloudQuery if more weak formats needed. |
| `CRITIC.md` | 10/10 | Zero open P0/P1. |
| `FAULTS.md` | none open | Compose P2 closed in cycle 2. |

---

## Last verified lab

`out/summary.json`:

| Field | Count |
|---|---|
| assets | 62 |
| findings | 59 |
| vulnerabilities | 15 |
| evidences | 10 |
| applied_controls | 74 |
| risk_scenarios | 74 |
| incidents | 58 |
| risks_proposed | 57 |
| ocsf (`class_uid` 2003) | 59 |
| canonical records | 137 |
| demo | true |

pytest: **39 passed**. `tests/lab_outputs.py`: **PASS**.  
Double `scripts\lab.ps1`: 62 asset rows, 62 unique `ref_id`s.  
Compose (cycle 6 and earlier): `docker compose up --build --exit-code-from grc-loader`, loader exit 0.

Floors from the start spec (20 / 20 / 8) are exceeded. Do not regress below the last verified 62 / 59 / 10 without a critic note.

---

## Cycle history

| Cycle | What landed | pytest | Assets | Findings | Vulns | Evidence |
|---|---|---|---|---|---|---|
| 1 | Initial pack, two green labs, DONE GREEN | 11 | 42 | 39 | 10 | 10 |
| 2 | ASFF, PingCastle XML, Amass, Greenbone, osquery, Compose | 23 | 50 | 44 | 11 | 10 |
| 3 | TruffleHog JSONL, Falco | 25 | 52 | 46 | 13 | 10 |
| 4 | Cloud Custodian, Steampipe, Nmap `-oG` | 28 | 55 | 50 | 13 | 10 |
| 5 | BloodHound edges, Fleet, SARIF **labbed** | 31 | 60 | 54 | 14 | 10 |
| 6 | KEEP-HK / Maester / testssl / ScoutSuite + HOSTILE+ / EXCEPTIONS / labels / idempotent / evidence / compose | 36 | 62 | 58 | 15 | 10 |
| 7 | Microsoft Graph directoryRoles, kube-bench + httpx tests, `cpg_2_W` | 39 | 62 | 59 | 15 | 10 |

Overnight loop (PID 14860, every 30 minutes until 2026-09-02 07:00 PT) produced cycles 2–4 in-session; cycle 5 code was written on a tick but the lab was interrupted until 2026-09-02 ~21:58 PT.

---

## Architecture

```
in/{cloud,nmap,vuln,wazuh,identity,easm,k8s,code,saas}/   ← drop real tool output
fixtures/demo/<same keys>/                                 ← used when in/ is empty
collectors/*.py                                            ← parse → out/canonical/*.jsonl
collectors/grc_loader.py                                   ← GRC files
out/ciso-assistant/*.csv
out/riskready/{assets,incidents,evidence,risks_proposed}.json
out/ocsf/compliance_findings.json
out/summary.json
out/evidence/lab-report.md
```

Canonical `kind` ∈ `asset|finding|evidence|incident`. Prefixes `CLD- NMAP- VULN- WAZ- ID- EASM- K8S- CODE- SAAS-`. Asset type `PR` (hosts/clusters/cloud) or `SP` (identities/SaaS). Dedup: lowercase asset name, or `(kind, ref_id)`. Loader **overwrites** (no append). Empty `in/` → fixtures + `demo` label. Parse failure on a file falls back to fixtures only if the whole collector produced nothing.

Shared: `shared/schema.py`, `shared/io_util.py`. Windows lab: `scripts\lab.ps1` (`python`, not `python3`).

---

## Ten services (unchanged count — no eleventh container)

| Service | Module | Formats parsed |
|---|---|---|
| cloud-prowler | `cloud_prowler.py` | Prowler JSON, Prowler ASFF, Cloud Custodian, Steampipe `{rows}`, ScoutSuite `services.findings` |
| inventory-nmap | `inventory_nmap.py` | Nmap XML, Nmap greppable (`.gnmap`) |
| vuln-scan | `vuln_scan.py` | Nuclei JSONL, Trivy, Greenbone, testssl `scanResult` |
| host-wazuh | `host_wazuh.py` | Wazuh agents/alerts, osquery, Fleet `{hosts}` |
| identity-ad | `identity_ad.py` | BloodHound nodes + CE edges, PingCastle XML, HardeningKitty CSV |
| easm | `easm.py` | Subfinder text, httpx JSONL, Amass JSONL |
| k8s-kubescape | `k8s_kubescape.py` | Kubescape, kube-bench, Falco JSONL |
| code-secrets | `code_secrets.py` | Gitleaks, Semgrep JSON, Trivy FS, TruffleHog JSONL, SARIF |
| saas-idp | `saas_idp.py` | ScubaGear, Maester, Microsoft Graph directoryRoles, Okta |
| grc-loader | `grc_loader.py` | All GRC emit |

Demo stories still covered: public S3, IAM admin, DC:445, telnet, CVEs, healthy + disconnected Wazuh, Backup Operators / roastable SPN / Entra GA without PIM, `vpn.` + `dev-api.`, privileged pod + anonymous API, redacted git secret + lockfile CVE, M365 legacy auth + Okta admin MFA gap — plus later formats listed above.

33 fixture files under `fixtures/demo/`. `in/*` is `.gitkeep` only, so labs are the demo path.

---

## GRC contracts (still enforced)

### CISO Assistant (`out/ciso-assistant/`)

Exact headers. `risk_scenarios.csv` is semicolon. Finding severity `low|medium|high|critical` (`info` → `low`). Vuln severity `Information|Low|Medium|High|Critical`. Type `PR|SP` only. `filtering_labels` have no spaces-only empties and include wizard-safe `cpg_2_W`.

`push_ciso.sh` only if `CISO_PUSH=1`. REST limited to `/api/assets/` and `/api/evidences/`. Default `0`.

### RiskReady (`out/riskready/`)

`assets.json`, `incidents.json` (explicit + every high/critical finding), `evidence.json` (`TECHNICAL` / `SENSOR` / `DRAFT`), `risks_proposed.json` (**never auto-POST**). Likelihood/impact enums mapped from severity.

`push_riskready.sh` only if `RISKREADY_PUSH=1`. Default `0`.

### Evidence

`evidences.csv` names all nine collectors plus `grc-loader` (10 rows).

---

## Tests (39 `test_*` functions)

| File | Coverage |
|---|---|
| `test_loader.py` | 10 module imports, 10 Compose services, CSV header constants |
| `test_safety.py` | push flags 0, no `/api/risks` curl, no sockets, output redaction |
| `test_schema.py` | severity / RiskReady / scenario maps |
| `test_redact.py` | AKIA, PEM, nested secrets |
| `test_hostile.py` | truncated JSON fallback, blank Nuclei lines, Nmap without hostname, double loader, Fleet host without hostname |
| `test_parsers.py` | ASFF, PingCastle, Greenbone, Amass, osquery, TruffleHog, Custodian, Steampipe, gnmap, BloodHound edges, Fleet, SARIF, HardeningKitty, Maester, testssl, Graph, kube-bench, httpx, ScoutSuite, Falco |
| `lab_outputs.py` | full output contract + `cpg_2_W` |

Environmental noise: pytest Windows atexit `PermissionError` on `pytest-of-R` (`EX-PYTEST-WIN`). Tests still report passed.

---

## CONTINUE.md queue (from `CURSOR_CONTINUE.md`)

| Item | State |
|---|---|
| C5-LAB | Done |
| C5-STAMP | Done |
| KEEP-HK | Done — `hardeningkitty.csv` + `test_hardeningkitty_csv` |
| KEEP-MAESTER | Done — `maester.json` + `test_maester` |
| KEEP-TESTSSL | Done — `testssl.json` + `test_testssl` |
| KEEP-ASFF2 | Done — ASFF + ScoutSuite tests |
| HOSTILE+ | Done — Fleet without hostname |
| EXCEPTIONS | Done — `docs/EXCEPTIONS.md` |
| LABELS | Done — strip blanks + `cpg_2_W` |
| IDEMPOTENT | Done — 62 = 62 unique |
| EVIDENCE | Done — nine sensors + loader |
| COMPOSE | Done — loader exit 0 |

After the list emptied: cycle 7 covered README-weak Graph / kube-bench / httpx.

---

## Safety invariants

- `DRY_RUN=1` `CISO_PUSH=0` `RISKREADY_PUSH=0` `GRC_LIVE_SCAN=0`
- Collectors do not use `socket.socket`, `urllib.request`, `http.client`
- Push scripts never `curl` `${API}/risks`
- Secrets → `[REDACTED]` (HardeningKitty actual values, Gitleaks, TruffleHog)
- Stop hook files still present: `.cursor/hooks.json`, `.cursor/hooks/keep_going.cmd`, `.cursor/hooks/keep_going.py`

---

## Known exceptions (`docs/EXCEPTIONS.md`)

- Nmap hostname collision → one PR asset
- No Lynis parser (do not add an 11th container)
- Fleet host without a name is skipped
- Empty SARIF `runs` emits nothing
- Push dry-run never POSTs risks
- pytest Windows temp cleanup noise

---

## What is out of scope

- No GRC UI
- No live cloud / AD / k8s scans
- No auto-create of RiskReady risks
- No required commercial scanners
- Not the Evergreen Infosec paying-day / LinkedIn CTA / Origin Eval program

---

## Suggested next (optional)

`STATUS.md` `next_action`: **Grype** or **CloudQuery** if more weakly tested start-spec formats are wanted. Not required for GREEN. Do not invent an eleventh container. Do not re-arm a 30-minute host loop unless asked.

How to re-lab:

```powershell
cd C:\Users\R\grc-collector-pack
powershell -ExecutionPolicy Bypass -File .\scripts\lab.ps1
```

---

## File map

```
grc-collector-pack/
  README.md PLAN.md AGENTS.md STATUS.md CYCLE.md CRITIC.md FAULTS.md
  DONE.md DONE_CYCLE5.md DONE_IMPROVE.md LOOP.md PROJECT_STATUS.md
  docs/EXCEPTIONS.md
  .env.example LICENSE requirements.txt pytest.ini Makefile
  Dockerfile docker-compose.yml push_ciso.sh push_riskready.sh scripts/lab.ps1
  shared/{schema,io_util}.py
  collectors/{cloud_prowler,inventory_nmap,vuln_scan,host_wazuh,identity_ad,
              easm,k8s_kubescape,code_secrets,saas_idp,grc_loader}.py
  schemas/{ciso-assistant,riskready}.md
  fixtures/demo/ (33 files)   in/   out/   tests/
  .cursor/hooks.json  .cursor/hooks/keep_going.{cmd,py}
```
