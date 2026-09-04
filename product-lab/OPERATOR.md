# Operator — run the collector pack

**Written:** 2026-09-04 (Linux host lab; Windows paths still valid)  
**Product:** local operator console + nine parse-only collectors + loader  
**Bind:** `http://127.0.0.1:18765/` only. Not a Compose service.

Do not set `GRC_LIVE_SCAN=1` as a real scan. Do not POST `/api/risks`. Do not wrap or run RiskReady. Do not invent FindingsAssessment UUIDs.

## What this is

A file emitter. Collectors parse scanner artifacts already on disk. Empty `in/<sensor>/` falls back to `fixtures/demo/` and labels records `demo`. That is **not** a client estate.

## Stand up (Linux)

```bash
cd /path/to/grc-collector-pack
python3 -m pip install -r requirements.txt
bash scripts/lab.sh
# or: make lab
bash scripts/start-product.sh
```

Open **http://127.0.0.1:18765/**. Refresh re-runs collectors on local files. Download drop zip for import.

Expect: pytest green, ten collector prints, `lab_outputs: PASS`, console `/health` `ok: true`. Counts live in `out/summary.json` — do not assume a marketing number.

## Stand up (Windows)

```powershell
cd C:\Users\R\grc-collector-pack
powershell -ExecutionPolicy Bypass -File .\scripts\lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\start-product.ps1
```

Or double-click `Start-GRC-Pack.cmd`. Same console URL.

## Drop real scanner output

Copy tool JSON/XML/CSV/JSONL into the matching `in/` folder, then refresh (or re-run `scripts/lab.sh`).

| Folder | Accepts |
|---|---|
| `in/cloud/` | Prowler, Prowler ASFF, Cloud Custodian, Steampipe, ScoutSuite |
| `in/nmap/` | Nmap XML, Nmap `-oG` |
| `in/vuln/` | Nuclei JSONL, Trivy, Greenbone, testssl |
| `in/wazuh/` | Wazuh agents/alerts, osquery, Fleet |
| `in/identity/` | BloodHound CE, PingCastle XML, HardeningKitty CSV |
| `in/easm/` | Subfinder, httpx JSONL, Amass JSONL |
| `in/k8s/` | Kubescape, kube-bench, Falco JSONL |
| `in/code/` | Gitleaks, Semgrep, Trivy FS, TruffleHog, SARIF |
| `in/saas/` | ScubaGear, Maester, Graph directoryRoles, Okta |

If a folder is empty, that collector uses `fixtures/demo/<sensor>/` and marks `demo`. Parse failure on one file does not invent hosts; fixture fallback only if the whole collector produced nothing.

## Hand-off files

After a lab or Refresh:

- CISO Assistant CSVs: `out/ciso-assistant/` — import with [clica](https://github.com/intuitem/ciso-assistant-community) or the UI. Preferred. Optional `CISO_PUSH=1` + `DRY_RUN=0` may POST `/api/assets/` and `/api/evidences/` only.
- POA&M draft: `out/poam/poam.csv` — **Pentera finds it; Evergreen maps it.** High/critical (and key medium such as SMB/RDP exposure) get CISA CPG + NIST CSF stamps and a recommended fix. Owner and due stay blank for a human. Do not invent dates or CVEs.
- RiskReady JSON: `out/riskready/` — **LICENSE-LOCK stay-out**. Review on disk. `push_riskready.sh` never logs in or POSTs, even if `RISKREADY_PUSH=1`.
- Packaged copy: `product-lab/drop/` plus `/export.zip` from the console. See `product-lab/drop/MANIFEST`.

## Safety env (already in lab scripts and compose)

`DRY_RUN=1` `CISO_PUSH=0` `RISKREADY_PUSH=0` `GRC_LIVE_SCAN=0` `GRC_PRODUCT_HOST=127.0.0.1`

```bash
bash ./push_ciso.sh
bash ./push_riskready.sh
```

CISO prints the clica path and dry-run. RiskReady prints LICENSE-LOCK review files and exits 0.

## Compose (optional)

If Docker is available:

```bash
docker compose up --build --exit-code-from grc-loader
```

This VM’s product lab is **host-only** when the daemon is absent. Compose publishes no ports. The console is host-side, not an eleventh service.

## Do not

- Live-scan. Collectors have no sockets.
- POST `/api/risks`.
- Restore RiskReady wrap (`curl` / login / itsm / evidence / incidents).
- Invent FindingsAssessment UUIDs.
- Market empty `in/` as a client estate.
- Stamp paying-day PASS or copy USB evergreen-assessment.
