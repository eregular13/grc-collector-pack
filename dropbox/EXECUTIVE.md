# Executive — evergreen drop-box (this slice)

Reid’s delivery is a **consented drop-box**, not a SaaS scanner and not a RiskReady wrap.

Three layers (see `ARCHITECTURE.md`): **A** BYO tool farm under SCOPE — private `farm/` catalog (**111** slots, 32 wired / 30 invoke / 81 file_drop; PATH / bind-mount / Reid-built tags; not Hub soup) · **B** orchestrator = brakes (`plan → shard → discover → destroy → deepen → destroy → external (plan-only) → ingest → grc_export`) plus stdio MCP conductor · **C** existing 10 containers parse `in/` only. Layer B feeds Layer C via `in/`; it does not turn collectors into live scanners. Cycle 20’s 105 named slots stand; this window added 6 real OS PATH stubs (not fake padding) and rewired journalctl / kubectl / snmpwalk. “100 tools” = catalog + file-drop families, not 100 compose binaries. Hexstrike is a UX pattern only (`HEXSTRIKE.md`) — no exploit-chain, no vendor submodule.

With written consent he places a VM, fills `SCOPE.yaml` (client, attestation hash, window, named internal CIDRs/hosts, named external hosts/domains/IPs), runs **internal** then **external**, and hands CISO Assistant CSVs from this pack.

**This checkout’s `dropbox/SCOPE.yaml` is DEMO.** Empty pack `in/` is still fixture theater until an operator drops real files or runs a consented box.

Labs on this Linux VM (Docker absent), 2026-09-04:

| Run | Assets | Findings | Vulns | Evidence | POA&M | `demo` |
|---|---|---|---|---|---|---|
| `make lab` (empty pack `in/` → fixtures) | 64 | 78 | 19 | 27 | 81 | true |
| `make dropbox-lab` (fixtures + demo overlays in `work/in`) | 69 | 87 | 19 | 27 | 84 | true |
| `make farm-toolbin-e2e` (DEMO stubs under `farm/work/e2e`) | 64 | 79 | 19 | 27 | 81 | true |

pytest **294 passed, 1 skipped**. `demo: true` on dropbox-lab / farm-lab / farm-toolbin-e2e is the DEMO overlay stamp, not a client estate. Orchestrator on this VM is **plan-only** unless `FARM_TOOL_BIN=lab` stubs run (no real Nmap/Nessus, no internet): 3 /24 shards, 2 deepen batches, workers destroyed on success and on timeout/failure. `make farm-lab` 64/78/27 poam 81 under `farm/work`. `make dropbox-compose` **compose_lab: absent** (`docker CLI not on PATH`) after static scanner-free assertions passed — not a compose pass. Pack + `farm/` image/compose files have no nmap/nessus/nuclei/openvas packages. `farm/SLOTS.md` is the category table. `farm/INTEGRITY.md` is the brakes defaults table. `farm/OPERATOR.md` is the copy-paste runbook from bare Linux to CISO zip, including an accurate Cursor `.cursor/mcp.json` snippet (`cwd` + `PYTHONPATH`).

LICENSE-LOCK: the image does not ship or apt-install Nmap, Nuclei, OpenVAS/GVM, Nessus, Zeek, Wazuh, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, or RiskReady wrap. Allowlisted host tools (`ss`/`ip`/`curl`/`lynis`) run only when already on PATH and named in SCOPE.

The orchestrator is **brakes**, not a coverage contest: quiet discover then a louder deepen that is **fail-closed** unless `orchestrator.stages.deepen: true`. Hosts from discover-live or explicit `deepen_hosts`, batches 2–5, `max_workers` default 2, per-host timeout, tear-down after each stage **including timeout/failure**, nothing outside SCOPE, never a /16 in one worker, never open-internet spray. External profile is named hosts only (no `*` / CIDR). BYO Nmap/Nessus/testssl/curl only if on PATH and allowlisted — adapters invoke those binaries when allowlisted; missing → plan-only; non-allowlisted never invoked.

CISO Assistant is the system of record (CSV + optional assets/evidences REST). RiskReady stays review-only JSON. SimpleRisk is leave-behind documentation only.

**Pentera finds it; Evergreen maps it.** High/critical (and key medium: RDP, SMB, TLS weak cipher, admin shares) become `applied_controls` plus wizard-safe `cpg_*` / `csf_*` labels and `out/poam/poam.csv`. Owner and due are blank.

**Delta (cycle 60):** Harden existing rails, no new parser. pytest asserts LICENSE-LOCK / file_drop-only names never appear in invoke `will_run=true` even when every slot is allowlisted and on PATH. Operator docs list exact `docker compose` commands and PASS criteria. This VM compose remains ABSENT (hole, not a PASS). Paying-day FAIL. Catalog unchanged (111 / 32 / 30 / 81). Labs unchanged vs cycle 59.

**Delta (cycle 59):** Layer C parse-only enum4linux-ng file-drop polish: JSON/text under `in/identity/` (`target` + users/groups/shares). Listed identities stay listed. Null session, writable shares, and Domain Admins hints map to existing identity/SMB POA&M only when shown. Empty invents nothing. Detect does not steal HardeningKitty or BloodHound. Demo attaches to `DC01.CORP.LOCAL`. No enum4linux run / no credentials / no live SMB/LDAP/auth. Slot stays `file_drop`. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand. Paying-day FAIL. Compose ABSENT. LICENSE-LOCK / file_drop-only names never `will_run=true`.

**Delta (cycle 58):** Layer C parse-only smbmap file-drop polish: share tables under `in/nmap/` (`[+] IP:` / Disk + Permissions). Hosts become assets. READ/WRITE shares map to existing SMB POA&M. Empty/NO ACCESS invent nothing. Detect does not steal nmap / arp-scan / nbtscan. Demo attaches writable C$ to `filesrv.corp.local`. No smbmap/smbclient / no live SMB / no credentials. Slot stays `file_drop`. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 57):** Layer C parse-only nbtscan file-drop polish: name/IP tables under `in/nmap/` (IP + NetBIOS + `<server>`). Hosts become assets only. Empty/header-only invent nothing. Detect does not steal arp-scan / netdiscover / fping. Demo attaches to `filesrv.corp.local` (no new findings). No nbtscan run / no live NetBIOS. Slot stays `file_drop`. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 56):** Layer C parse-only netdiscover file-drop polish: text under `in/nmap/` (IP + MAC + Count + Len + vendor). Hosts become assets only. Empty/header-only invent nothing. arp-scan detect does not claim netdiscover tables. Demo attaches to `filesrv.corp.local` (no new findings). No netdiscover run / no live ARP. Slot stays `file_drop`. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 55):** Layer C parse-only fping file-drop polish: text / JSON under `in/nmap/` (`host is alive`). Alive hosts become assets only. Unreachable/empty invent nothing. Demo attaches to `filesrv.corp.local` (no new findings). No fping run / no live ping. Slot stays `file_drop`. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 54):** Layer C parse-only arp-scan file-drop polish: text / JSON under `in/nmap/` (IP + MAC + vendor). Hosts become assets only. Empty/header-only invent nothing. Demo attaches to `filesrv.corp.local` (no new findings). No arp-scan run / no live ARP. Slot stays `file_drop`. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 53):** Layer C parse-only rustscan / naabu file-drop polish: JSON / JSONL under `in/nmap/`. Open ports only. Empty/closed invent nothing. Demo attaches Telnet 23 to `filesrv.corp.local`. No rustscan/naabu run. Invoke stays BYO. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 52):** Layer C parse-only masscan file-drop polish: `-oX` XML / `-oJ` JSON under `in/nmap/`. Open ports only. Empty invents nothing. Demo attaches RDP 3389 to `filesrv.corp.local`. No masscan run. Slot stays `file_drop` / `use_dont_ship`. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 51):** Layer C parse-only sslscan file-drop polish: XML (`ssltest`) or text under `in/vuln/` or `in/easm/`. Weak/failed only. Empty / TLS 1.2-only invent nothing. Not testssl JSON. Demo attaches TLS 1.0 to `vpn.example.com` (vulnerability row). No live sslscan; invoke stays BYO. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 50):** Layer C parse-only WhatWeb file-drop polish: `--log-json` (`target` + `plugins`) under `in/easm/`. Admin/login only. Empty/Home invent nothing. Demo attaches admin-login to `admin.example.com`. No live HTTP; whatweb stays file_drop. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 49):** Layer C parse-only SaaS file-drop polish: ScubaGear / Okta / Maester / Graph exports under `in/saas/`. Failed/high only. Empty/pass invent nothing. MFA and standing Global Administrator map to existing CISO/POA&M. Demo attaches MFA high to `contoso.onmicrosoft.com`. No Graph or Okta API. scuba / okta-logs stay file_drop. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 48):** Layer C parse-only Nessus `.nessus` file-drop polish: NessusClientData `ReportHost` / `ReportItem` under `in/vuln/`. High/Critical + key Medium. Empty and DEMO tool-bin `.txt` invent nothing. Demo attaches SMB High to `http://10.0.0.20`. No Nessus API; collector does not run nessuscli. nessus invoke stays BYO. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 47):** Layer C parse-only Nikto file-drop polish: text / XML / JSON under `in/vuln/`. Interesting/high only. Header noise and empty invent nothing. Demo attaches to `http://10.0.0.20`. No nikto run / no live HTTP. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 46):** Layer C parse-only ffuf / gobuster file-drop polish: ffuf JSON (`results` + status/url) and gobuster `(Status: N)` text under `in/easm/`. Interesting `/admin` `/login` `/.git` only. 404/robots/empty invent nothing. Demo attaches to `admin.example.com`. No live DNS/HTTP. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 45):** Layer C parse-only Checkov / Gitleaks / TruffleHog file-drop polish: Checkov `failed_checks`, Gitleaks `{findings|leaks|results}` wrappers, and TruffleHog `{results}` under `in/code/`. Passed/INFO/empty invent nothing. Secrets redacted. Public S3 ACL and credential rows map to existing CISO/POA&M. Demo attaches to `infra/terraform.tfvars`. No live checkov/gitleaks/semgrep. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 44):** Layer C parse-only EASM file-drop polish: httpx / Amass / Subfinder JSON, JSONL, and `{results|hosts}` wrappers under `in/easm/`. Failed httpx silent. Empty invents nothing. Perimeter / admin-UI / TLS weak map to existing CISO/POA&M. Demo attaches to `admin.example.com`. No live DNS/HTTP. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 43):** Layer C parse-only CIS-CAT / osquery file-drop polish: CIS-CAT/XCCDF JSON+XML and osquery failing `queries` under `in/wazuh/` (identity-ad also parses CIS-CAT for `in/identity/*.xml`). Failed only. Empty invents nothing. SSH PermitRootLogin and disk encryption map to existing CISO/POA&M. Demo attaches to `jump-unmanaged`. No CIS-CAT binary, no osqueryi. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 42):** Layer C parse-only Nuclei JSON file-drop harden: JSONL / object / array / `{results}` wrapper under `in/vuln/`. INFO silent. Empty results invent nothing. Log4Shell / RCE map to existing CISO/POA&M. Collector does not run nuclei. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 41):** Layer C parse-only Fleet file-drop harden: `hosts` / `data.hosts` / single `host` plus failing `policies` under `in/wazuh/`. Disk encryption off and MDM enrollment Off map to existing CISO/POA&M. Empty hosts/policies invent nothing. No Fleet API / fleetctl / osqueryi. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 40):** Layer C parse-only BloodHound CE file-drop harden: SharpHound `data[]` + `Properties` / `ObjectIdentifier` / mapped `Aces` under `in/identity/`. Empty `data` / empty `Members` invent nothing. High rows map to existing CISO/POA&M (DCSync, GenericAll, roastable SPN, AS-REP, unconstrained delegation, Backup Operators). No LDAP / BloodHound run. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 39):** Layer C parse-only nmap file-drop harden: gnmap / XML / JSON under `in/nmap/`. DEMO stub gnmap from `farm/tool-bin/lab/nmap` → assets + exposure. Open 445 / 3389 / 23 map to existing SMB / RDP / Telnet POA&M. Collector does not subprocess nmap. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 38):** Layer C parse-only k8s file-drop harden: Kubescape + kube-bench JSON under `in/k8s/` (nested results; FAIL only). High rows map to CISO/POA&M (privileged, anonymous-auth, privilege escalation, hostNetwork). No kubectl / live cluster. Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 37):** Layer C parse-only KEEP-chain file-drop harden: testssl JSON under `in/vuln/` or `in/easm/` (HIGH/WARN only; no live TLS). Maester / Entra `directoryRoles` export under `in/saas/` (Failed only; no Graph API). High rows map to CISO/POA&M (Heartbleed, TLS 1.0, phishing-resistant MFA). Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). Docs/e2e stand.

**Delta (cycle 36):** Layer C parse-only endpoint file-drop harden: HardeningKitty Audit CSV under `in/identity/` (Failed/warning only; does not invent Windows findings). Lynis report/`report.dat` under `in/wazuh/`. High rows map to CISO/POA&M when obvious (password history, LM hash, host firewall, SSH PermitRootLogin). Empty pack `in/` still loads fixtures. Catalog unchanged (111 / 32 / 30 / 81). No AD/WinRM/cloud API. Docs/e2e stand.

**Delta (cycle 35):** Layer C parse-only cloud file-drop harden: Prowler JSON/ASFF (`ProductFields`, string or dict Severity) and ScoutSuite `services.*.findings` under `in/cloud/`. High FAIL maps to CISO/POA&M when obvious (public S3 / AllUsers, IAM AdministratorAccess, root MFA, SG `0.0.0.0/0`, public RDS, unencrypted S3/EBS). Demo ASFF adds `demo-asff-open`. Empty pack `in/` still loads fixtures. ScoutSuite stays file_drop; Prowler invoke stays BYO. Catalog unchanged (111 / 32 / 30 / 81). No cloud API calls. No live tools. Docs/e2e stand.

**Delta (cycle 34):** Layer C parse-only SARIF: `in/vuln/*.sarif` and `in/code/*.sarif` → canonical findings + CISO/POA&M for high rules (`sql-injection`, `command-injection`, XSS). Demo fixture `fixtures/demo/vuln/demo.sarif`. Empty pack `in/` still falls back to fixtures. Catalog unchanged (111 / 32 / 30 / 81). No live tools. Docs/e2e stand.

**Delta (cycle 33):** `farm/QUICKSTART.md` (consent → SCOPE → tool-bin DEMO vs real → `make farm-toolbin-e2e` → CISO zip → `--live` only on drop box). Root README “Private drop-box farm” links QUICKSTART + ARCHITECTURE three layers. STATUS + product-lab/EXECUTIVE stamp **111 / 32 / 30**, pytest **180**, e2e 63/63 poam 61. DEMO ≠ client estate. Catalog unchanged. Cycles 31–32 stand.

**Delta (cycle 32):** Conductor `farm_toolbin_status` lists FARM_TOOL_BIN resolve for wired invoke slots (`present` / `missing` / `demo_stub`). `tools/call` `orchestrator_plan` returns the per-stage `will_run` map. `farm/OPERATOR.md` and `dropbox/operator_mcp_interface.md` have exact Cursor `.cursor/mcp.json` and Claude Desktop snippets; `scripts/mcp_stdio.sh` starts from repo root. Catalog unchanged (111 / 32 / 30 / 81). Cycle 31 e2e stands. No live internet. No fake compose pass.

**Delta (cycle 31):** `make farm-toolbin-e2e` is the DEMO quiet→loud path with `FARM_TOOL_BIN=farm/tool-bin/lab`. Isolated `farm/work/e2e`: plan → discover (stub nmap) → deepen small batch (stub nessus/nessuscli) → external **plan-only** → ingest → Layer C. Artifacts land in `in/nmap|vuln|…`. CISO/POA&M exist. Pack `in/` stays `.gitkeep` only. `demo` true. LICENSE-LOCK still refuses. OPERATOR.md has one command block for toolbin-e2e vs real-binaries. Catalog unchanged (111 / 32 / 30 / 81). No live internet. No fake compose pass.

**Delta (cycle 30):** DEMO tool-bin stubs now cover nmap, curl, nessus, nessuscli, testssl, testssl.sh, lynis. Deepen / external-adjacent slot plans `will_run` when `FARM_TOOL_BIN=lab`. Orchestrate external stage stays plan-only (no live probe). `make farm-toolbin-lab` asserts nmap+curl. LICENSE-LOCK names still refuse subprocess. Catalog unchanged (111 / 32 / 30 / 81).

**Delta (cycle 29):** `FARM_TOOL_BIN` is proven. DEMO shell stubs write fixture-shaped output with no network. Operator copies real binaries into `farm/tool-bin/` or uses host PATH.

**Delta (cycle 28):** Farm + dropbox compose are operator skeletons (SCOPE / work/in / work/out / tool-bin binds). Scanner-free statics fail closed on LICENSE-LOCK embeds and wrap POST. Compose runtime still ABSENT here.

**Delta (cycle 27):** Ingest inventories operator-dropped files already in `in/easm|…` (`dropped_external` on the ingest marker). `.gitkeep` and `plan.json` ignored. External stage remains **plan-only** — no live curl/testssl from orchestrate or CI. `make dropbox-external` stays DEMO fixture writer. Catalog unchanged (111 / 32 / 30 / 81). Layer C untouched.

**Delta (cycle 26):** External stage is **plan-only** in the graph (after deepen, before ingest). SCOPE refuses CIDR / wildcards / `0.0.0.0/0` in `external:`; named hosts and https URLs allowed. External SLOTS `will_run=false`.

Not a paying-day PASS. USB evergreen-assessment was not copied.
