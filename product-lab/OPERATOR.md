# Operator — run the collector pack

**Written:** 2026-09-04 (Linux host lab; Windows paths still valid)  
**Product:** local operator console + nine parse-only collectors + loader  
**Bind:** `http://127.0.0.1:18765/` only. Not a Compose service.

Do not set `GRC_LIVE_SCAN=1` as a real scan. Do not POST `/api/risks`. Do not wrap or run RiskReady. Do not invent FindingsAssessment UUIDs.

The drop-box orchestrator is **brakes** (quiet discover → gated deepen). See `dropbox/OPERATOR.md`. Defaults prefer client-environment integrity over coverage ego.

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
| `in/cloud/` | Prowler JSON, Prowler ASFF (`Findings` / list / object), ScoutSuite `services.*.findings`, Cloud Custodian, Steampipe. Parse-only — no cloud API calls. |
| `in/nmap/` | Nmap XML, gnmap (`-oG`), thin JSON, masscan `-oX` / `-oJ` (open ports only; empty invents nothing; no nmap/masscan run), rustscan / naabu JSON/JSONL (`{ip, port}` or `{ip, ports:[int]}`; open only; empty invents nothing; no rustscan/naabu run), arp-scan text/JSON (IP + MAC + vendor; hosts become assets only; empty invents nothing; no arp-scan run / no live ARP), fping text/JSON (`host is alive`; assets only; unreachable/empty invent nothing; no fping run / no live ping), netdiscover text (IP + MAC + Count + Len + vendor; assets only; empty invents nothing; arp-scan detect does not claim tables; no netdiscover run / no live ARP), nbtscan name/IP tables (IP + NetBIOS + `<server>`; assets only; empty invents nothing; detect does not steal arp-scan/netdiscover/fping; no nbtscan run / no live NetBIOS), smbmap share tables (`[+] IP:` / Disk + Permissions; assets + READ/WRITE exposure mapped to existing SMB POA&M; empty/NO ACCESS invent nothing; detect does not steal nmap/arp/nbtscan; no smbmap/smbclient run / no live SMB / no credentials). zmap JSON/CSV/text (`saddr`/`dport`; open only; empty/RST invent nothing; no zmap run / no live scan), unicornscan text (`TCP open … from`; open only; empty invents nothing; detect does not steal nmap/smbmap; no unicornscan run). masscan stays file_drop / use_dont_ship; rustscan/naabu invoke stays BYO; arp-scan / fping / netdiscover / nbtscan / smbmap / zmap / unicornscan stay file_drop. |
| `in/vuln/` | Nuclei JSON/JSONL (`results` wrapper OK; INFO silent; no nuclei run), Nikto text/XML/JSON (interesting/high only; empty invents nothing; no nikto run / no live HTTP), Nessus `.nessus` / NessusClientData XML (`ReportHost`/`ReportItem`; High/Critical + key Medium; empty/DEMO stub invent nothing; no Nessus API / no collector invoke), Trivy, Greenbone, testssl JSON (HIGH/WARN only; no live TLS), sslscan XML/text (`ssltest`; TLS 1.0 / SSLv2/v3 / Heartbleed only; empty invents nothing; not testssl JSON; no sslscan run) |
| `in/wazuh/` | Wazuh agents/alerts, osquery inventory + failing checks, Fleet hosts/policies (fail only; disk encryption / MDM Off map to POA&M; empty invents nothing), Lynis report / `report.dat`, CIS-CAT/XCCDF JSON (fail only). Parse-only — no osqueryi / CIS-CAT binary. |
| `in/identity/` | BloodHound CE / SharpHound JSON (`data.nodes`/`data.edges` or `Properties`/`ObjectIdentifier`/`Aces`; empty data invents nothing), PingCastle XML, CIS-CAT/XCCDF XML/JSON (fail only), HardeningKitty Audit CSV (Failed/warning only; does not invent Windows findings), enum4linux-ng JSON/text (`target` + users/groups/shares; null session / writable shares / Domain Admins hints map to existing identity/SMB POA&M when shown; empty invents nothing; detect does not steal HK/BloodHound; no enum4linux run / no credentials) |
| `in/easm/` | Subfinder / Amass / httpx JSON or JSONL (arrays and wrappers; failed httpx silent; empty invents nothing; no live DNS/HTTP), ffuf JSON + gobuster text (interesting `/admin` `/login` `/.git` only), WhatWeb `--log-json` (`target`+`plugins`; admin/login only; empty invents nothing; no whatweb run), testssl JSON (same HIGH-only parse as `in/vuln/`), sslscan XML/text (same weak-only parse as `in/vuln/`; no live TLS) |
| `in/k8s/` | Kubescape JSON, kube-bench JSON (`Controls[].tests[].results[]`), Falco JSONL. Parse-only — no kubectl / live cluster. |
| `in/code/` | Gitleaks / TruffleHog / Semgrep / Checkov JSON or JSONL (wrappers OK; Checkov failed only; empty invents nothing; secrets redacted; no live tools), Trivy FS, SARIF |
| `in/saas/` | ScubaGear JSON/JSONL (`Results` or `{data\|ScubaResults}` wrap; Fail/high only; empty invents nothing), Maester (Failed only), Graph `directoryRoles` export (file-drop; no Graph API), Okta org/policy JSON (`users`/`policies`; inactive MFA only; no Okta API) |

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

This VM stamps compose **ABSENT** when Docker CLI is missing — that is a hole,
not a PASS, and never a paying-day stamp.

If Docker is available on an operator host:

```bash
docker compose config --services    # exactly 10
docker compose up --build --exit-code-from grc-loader
```

**PASS criteria:** loader exit 0; 10 services; no published ports;
`out/summary.json` present. Image must not contain nmap/nuclei/openvas/nessus/gvm/zeek.
Empty pack `in/` is DEMO fixtures. Do not stamp paying-day from this run.

Dropbox runtime (`make dropbox-compose`) is PASS only when
`dropbox/work/compose-lab.json` shows `"status": "pass"`. `"absent"` is not a pass.
Farm compose is an operator skeleton — `make farm-compose` never auto-PASS.

## Do not

- Live-scan. Collectors have no sockets.
- POST `/api/risks`.
- Restore RiskReady wrap (`curl` / login / itsm / evidence / incidents).
- Invent FindingsAssessment UUIDs.
- Market empty `in/` as a client estate.
- Stamp paying-day PASS or copy USB evergreen-assessment.
