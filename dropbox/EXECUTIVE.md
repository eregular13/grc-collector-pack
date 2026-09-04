# Executive — evergreen drop-box (this slice)

Reid’s delivery is a **consented drop-box**, not a SaaS scanner and not a RiskReady wrap.

Three layers (see `ARCHITECTURE.md`): **A** BYO tool farm under SCOPE — private `farm/` catalog (**111** slots, 32 wired / 30 invoke / 81 file_drop; PATH / bind-mount / Reid-built tags; not Hub soup) · **B** orchestrator = brakes (`plan → shard → discover → destroy → deepen → destroy → external (plan-only) → ingest → grc_export`) plus stdio MCP conductor · **C** existing 10 containers parse `in/` only. Layer B feeds Layer C via `in/`; it does not turn collectors into live scanners. Cycle 20’s 105 named slots stand; this window added 6 real OS PATH stubs (not fake padding) and rewired journalctl / kubectl / snmpwalk. “100 tools” = catalog + file-drop families, not 100 compose binaries. Hexstrike is a UX pattern only (`HEXSTRIKE.md`) — no exploit-chain, no vendor submodule.

With written consent he places a VM, fills `SCOPE.yaml` (client, attestation hash, window, named internal CIDRs/hosts, named external hosts/domains/IPs), runs **internal** then **external**, and hands CISO Assistant CSVs from this pack.

**This checkout’s `dropbox/SCOPE.yaml` is DEMO.** Empty pack `in/` is still fixture theater until an operator drops real files or runs a consented box.

Labs on this Linux VM (Docker absent), 2026-09-04:

| Run | Assets | Findings | Vulns | Evidence | POA&M | `demo` |
|---|---|---|---|---|---|---|
| `make lab` (empty pack `in/` → fixtures) | 64 | 65 | 17 | 25 | 66 | true |
| `make dropbox-lab` (fixtures + demo overlays in `work/in`) | 69 | 74 | 17 | 25 | 69 | true |
| `make farm-toolbin-e2e` (DEMO stubs under `farm/work/e2e`) | 64 | 66 | 17 | 25 | 66 | true |

pytest **216 passed, 1 skipped**. `demo: true` on dropbox-lab / farm-lab / farm-toolbin-e2e is the DEMO overlay stamp, not a client estate. Orchestrator on this VM is **plan-only** unless `FARM_TOOL_BIN=lab` stubs run (no real Nmap/Nessus, no internet): 3 /24 shards, 2 deepen batches, workers destroyed on success and on timeout/failure. `make farm-lab` 64/65/25 poam 66 under `farm/work`. `make dropbox-compose` **compose_lab: absent** (`docker CLI not on PATH`) after static scanner-free assertions passed — not a compose pass. Pack + `farm/` image/compose files have no nmap/nessus/nuclei/openvas packages. `farm/SLOTS.md` is the category table. `farm/INTEGRITY.md` is the brakes defaults table. `farm/OPERATOR.md` is the copy-paste runbook from bare Linux to CISO zip, including an accurate Cursor `.cursor/mcp.json` snippet (`cwd` + `PYTHONPATH`).

LICENSE-LOCK: the image does not ship or apt-install Nmap, Nuclei, OpenVAS/GVM, Nessus, Zeek, Wazuh, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, or RiskReady wrap. Allowlisted host tools (`ss`/`ip`/`curl`/`lynis`) run only when already on PATH and named in SCOPE.

The orchestrator is **brakes**, not a coverage contest: quiet discover then a louder deepen that is **fail-closed** unless `orchestrator.stages.deepen: true`. Hosts from discover-live or explicit `deepen_hosts`, batches 2–5, `max_workers` default 2, per-host timeout, tear-down after each stage **including timeout/failure**, nothing outside SCOPE, never a /16 in one worker, never open-internet spray. External profile is named hosts only (no `*` / CIDR). BYO Nmap/Nessus/testssl/curl only if on PATH and allowlisted — adapters invoke those binaries when allowlisted; missing → plan-only; non-allowlisted never invoked.

CISO Assistant is the system of record (CSV + optional assets/evidences REST). RiskReady stays review-only JSON. SimpleRisk is leave-behind documentation only.

**Pentera finds it; Evergreen maps it.** High/critical (and key medium: RDP, SMB, TLS weak cipher, admin shares) become `applied_controls` plus wizard-safe `cpg_*` / `csf_*` labels and `out/poam/poam.csv`. Owner and due are blank.

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
