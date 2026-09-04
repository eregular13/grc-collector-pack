# Executive — evergreen drop-box (this slice)

Reid’s delivery is a **consented drop-box**, not a SaaS scanner and not a RiskReady wrap.

Three layers (see `ARCHITECTURE.md`): **A** BYO tool farm under SCOPE — private `farm/` catalog (**111** slots, 32 wired / 30 invoke / 81 file_drop; PATH / bind-mount / Reid-built tags; not Hub soup) · **B** orchestrator = brakes (`plan → shard → discover → destroy → deepen → destroy → external (plan-only) → ingest → grc_export`) plus stdio MCP conductor · **C** existing 10 containers parse `in/` only. Layer B feeds Layer C via `in/`; it does not turn collectors into live scanners. Cycle 20’s 105 named slots stand; this window added 6 real OS PATH stubs (not fake padding) and rewired journalctl / kubectl / snmpwalk. “100 tools” = catalog + file-drop families, not 100 compose binaries. Hexstrike is a UX pattern only (`HEXSTRIKE.md`) — no exploit-chain, no vendor submodule.

With written consent he places a VM, fills `SCOPE.yaml` (client, attestation hash, window, named internal CIDRs/hosts, named external hosts/domains/IPs), runs **internal** then **external**, and hands CISO Assistant CSVs from this pack.

**This checkout’s `dropbox/SCOPE.yaml` is DEMO.** Empty pack `in/` is still fixture theater until an operator drops real files or runs a consented box.

Labs on this Linux VM (Docker absent), 2026-09-04:

| Run | Assets | Findings | Vulns | Evidence | POA&M | `demo` |
|---|---|---|---|---|---|---|
| `make lab` (empty pack `in/` → fixtures) | 62 | 62 | 15 | 24 | 61 | true |
| `make dropbox-lab` (fixtures + demo overlays in `work/in`) | 68 | 71 | 15 | 24 | 64 | true |

pytest **163 passed, 1 skipped**. `demo: true` on dropbox-lab / farm-lab is the DEMO overlay stamp, not a client estate. Orchestrator on this VM is **plan-only** (no Nmap/Nessus): 3 /24 shards, 2 deepen batches, workers destroyed on success and on timeout/failure. `make farm-lab` 62/62/24 poam 61 under `farm/work`. `make dropbox-compose` **compose_lab: absent** (`docker CLI not on PATH`) after static scanner-free assertions passed — not a compose pass. Pack + `farm/` image/compose files have no nmap/nessus/nuclei/openvas packages. `farm/SLOTS.md` is the category table. `farm/INTEGRITY.md` is the brakes defaults table. `farm/OPERATOR.md` is the copy-paste runbook from bare Linux to CISO zip, including an accurate Cursor `.cursor/mcp.json` snippet (`cwd` + `PYTHONPATH`).

LICENSE-LOCK: the image does not ship or apt-install Nmap, Nuclei, OpenVAS/GVM, Nessus, Zeek, Wazuh, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, or RiskReady wrap. Allowlisted host tools (`ss`/`ip`/`curl`/`lynis`) run only when already on PATH and named in SCOPE.

The orchestrator is **brakes**, not a coverage contest: quiet discover then a louder deepen that is **fail-closed** unless `orchestrator.stages.deepen: true`. Hosts from discover-live or explicit `deepen_hosts`, batches 2–5, `max_workers` default 2, per-host timeout, tear-down after each stage **including timeout/failure**, nothing outside SCOPE, never a /16 in one worker, never open-internet spray. External profile is named hosts only (no `*` / CIDR). BYO Nmap/Nessus/testssl/curl only if on PATH and allowlisted — adapters invoke those binaries when allowlisted; missing → plan-only; non-allowlisted never invoked.

CISO Assistant is the system of record (CSV + optional assets/evidences REST). RiskReady stays review-only JSON. SimpleRisk is leave-behind documentation only.

**Pentera finds it; Evergreen maps it.** High/critical (and key medium: RDP, SMB, TLS weak cipher, admin shares) become `applied_controls` plus wizard-safe `cpg_*` / `csf_*` labels and `out/poam/poam.csv`. Owner and due are blank.

**Delta (cycle 28):** Farm + dropbox compose are operator skeletons (SCOPE / work/in / work/out / tool-bin binds). Scanner-free statics fail closed on apt/pip/wget/FROM/COPY `.deb` / `git clone` of LICENSE-LOCK scanners and on wrap `curl … /api/risks`. `make dropbox-compose` / `make farm-compose` stamp **ABSENT** when Docker CLI is missing after static PASS — not a runtime pass. Catalog unchanged (111 / 32 / 30 / 81).

**Delta (cycle 27):** Ingest inventories operator-dropped files already in `in/easm|…` (`dropped_external` on the ingest marker). `.gitkeep` and `plan.json` ignored. External stage remains **plan-only** — no live curl/testssl from orchestrate or CI. `make dropbox-external` stays DEMO fixture writer. Catalog unchanged (111 / 32 / 30 / 81). Layer C untouched.

**Delta (cycle 26):** External stage is **plan-only** in the graph (after deepen, before ingest). SCOPE refuses CIDR / wildcards / `0.0.0.0/0` in `external:`; named hosts and https URLs allowed. External SLOTS `will_run=false`.

Not a paying-day PASS. USB evergreen-assessment was not copied.
