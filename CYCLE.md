# CYCLE log

## cycle 78 — verify-green / no-diff (2026-09-04)

Full lab suite re-run. No regression. No code change. Catalog **111 / 32 / 30 / 81**. pytest **319**. Host 64/79/19/27 poam 82. farm 64/79 poam 82. e2e 64/80 poam 82. dropbox 69/88 poam 85. Compose ABSENT (`docker CLI not on PATH`). Paying-day FAIL. Cycle 77 argv scanner-free stays locked. Cycle 74 Reid-only blockers stay locked. DEMO ≠ client. No new parsers.

```json
{"pytest": 319, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never", "scope_gap": "none"}
```

## cycle 77 — compose argv scanner-free (2026-09-04)

(e) static tighten without Docker: `scan_text` now flags compose `command`/`entrypoint` and Dockerfile `CMD`/`ENTRYPOINT` scanner tokens plus wrap POST paths as argv. Pack parse collectors (`inventory_nmap.py`) stay clean. Runtime still ABSENT (`docker CLI not on PATH`). Did not fake compose PASS. Cycle 74 Reid-only blockers stay locked. Paying-day FAIL. Catalog **111 / 32 / 30 / 81**. pytest **319** (+1). Labs no-diff vs cycle 76 counts.

```json
{"pytest": 319, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never", "scope_gap": "none"}
```

## cycle 76 — compose runtime ABSENT honesty (2026-09-04)

Backlog (a)–(d) MET. (e) statics MET; runtime still ABSENT (`docker CLI not on PATH`). Scanner-free + wrap-dead + SCOPE/brakes pytest **89 passed, 1 skipped**. Full pytest **318**. Labs no-diff vs cycle 75. No product code. Did not fake compose PASS. Cycle 74 Reid-only blockers stay locked. Paying-day FAIL. Catalog **111 / 32 / 30 / 81**.

```json
{"pytest": 318, "pytest_skipped": 1, "targeted_scanner_free_wrap_scope": "89 passed, 1 skipped", "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never", "scope_gap": "none"}
```

## cycle 75 — verify-green / no-diff (2026-09-04)

Full lab suite re-run. No regression. No code change. Catalog **111 / 32 / 30 / 81**. pytest **318**. Host 64/79/19/27 poam 82. farm 64/79 poam 82. e2e 64/80 poam 82. dropbox 69/88 poam 85. Compose ABSENT. Paying-day FAIL. Cycle 74 Reid-only blockers stay locked. Cycle 73 `scope_gap: none` + FARM_TOOL_BIN refuse stay locked. DEMO ≠ client. No new parsers.

```json
{"pytest": 318, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never", "scope_gap": "none"}
```

## cycle 74 — Reid-only blockers (2026-09-04)

STATUS `next_action` and EXECUTIVE name Reid-only work: CTA; Eval `npm start`; real KEEP `in/` drop; compose on a Docker host (this VM ABSENT, not a PASS); merge PR #1. No fake greens. Scanner-free compose/Dockerfile statics already locked (pack + farm + dropbox). Cycle 73 `scope_gap: none` + FARM_TOOL_BIN refuse stay locked. Catalog **not inflated**. pytest **318**. Labs unchanged vs cycle 73 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. DEMO ≠ client. No new parsers.

```json
{"pytest": 318, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never", "scope_gap": "none"}
```

## cycle 73 — FARM_TOOL_BIN refuse-list (2026-09-04)

SCOPE entrypoint hunt found **no remaining operator gap** after cycle 72: CLI, conductor, `run_slot`, and `orchestrate` all `load_scope`; discover/deepen use the loaded `Scope.allow_tools`. Hardened FARM_TOOL_BIN: every `LICENSE_LOCK_SPAWN` name dropped into `tool-bin` or `tool-bin/lab` fails `farm_which` / `which_allowed` / `run_allowed`. ORCH_BYO nmap/nessus stay off the refuse list. Cycle 72 run_slot intersection stays locked. Catalog **not inflated**. pytest **317**. Labs unchanged vs cycle 72 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. DEMO ≠ client. No new parsers.

```json
{"pytest": 317, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never", "scope_gap": "none"}
```

## cycle 72 — SCOPE fail-closed invoke (2026-09-04)

`run_slot` now `load_scope` and intersects caller `allow_tools` with the signed list. Empty/unsigned SCOPE refuses invoke. Host-local signed SCOPE cannot grant nmap even if the caller asks. `run_allowed` requires `allow_tools`. Conductor tests cover every `OPERATOR_TOOLS` name. CLI `gate` / `status` / `run` / `lab` / `orchestrate` / `mcp *` refuse empty/unsigned SCOPE. Cycle 71 README honesty stays locked. Catalog **not inflated**. pytest **316**. Labs unchanged vs cycle 71 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. DEMO ≠ client. No new parsers.

```json
{"pytest": 316, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```

## cycle 71 — README honesty rails (2026-09-04)

Root README now matches STATUS / EXECUTIVE: DEMO ≠ client, paying-day FAIL, compose ABSENT (hole, not a PASS), wrap review-only, catalog **111 / 32 wired / 30 invoke / 81 file_drop**, USB `evergreen_assessment_mcp` (`check_scope` / `license_guard`) = pack truth, `dropbox.mcp_stub` = conductor UX, `SCOPE.example.yaml` does not allowlist nmap/nessus. Operator compose proof (`config --services` + `up --build --exit-code-from grc-loader`) is documented; this VM still stamps ABSENT. Cycles 67–70 rails stay locked. Catalog **not inflated**. pytest **315**. Labs unchanged vs cycle 70 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. No new parsers.

```json
{"pytest": 315, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```

## cycle 70 — Brakes honesty regressions (2026-09-04)

`test_orch_brakes` now locks `free_day_scope`, `pack_truth`, wrap-dead, and conductor `load_scope` refusals for empty and unsigned SCOPE (farm_slots / export / status / stage). Cycle 69 SCOPE gate stays locked. Catalog **not inflated**. pytest **313**. Labs unchanged vs cycle 69 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. DEMO ≠ client. No new parsers.

```json
{"pytest": 313, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```

## cycle 69 — Conductor SCOPE gate (2026-09-04)

`farm_slots` and `export_ciso_poam` now load written SCOPE. Empty/unsigned SCOPE refuses catalog, export, status, and stage tools. `dropbox.mcp_stub` stays conductor UX, not USB `evergreen_assessment_mcp` pack truth. No TypeScript refuse matrix. No new invoke slots. Cycle 68 farm SOP honesty stays locked. Catalog **not inflated**. pytest **311**. Labs unchanged vs cycle 68 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. DEMO ≠ client. Hexstrike pattern-only.

```json
{"pytest": 311, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```

## cycle 68 — Farm SOP honesty (2026-09-04)

OPERATOR / QUICKSTART / INTEGRITY lock DEMO ≠ client, `SCOPE.example.yaml` does not allowlist nmap/nessus (free-day closed), RiskReady never in SOP, USB `evergreen_assessment_mcp` (`check_scope` / `license_guard`) = pack truth, `dropbox.mcp_stub` = conductor UX only. `farm_slots` brakes JSON matches (`free_day_scope`, `pack_truth`). Cycle 67 rails stay locked. Catalog **not inflated**. pytest **310**. Labs unchanged vs cycle 67 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. No new invoke slots. Hexstrike pattern-only.

```json
{"pytest": 310, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```

## cycle 67 — Hephaestus SCOPE example opt-in (2026-09-04)

`SCOPE.example.yaml` no longer default-allowlists nmap/nessus/nessuscli. Client template stays host-local (`lynis`/`ss`/`ip`/`curl`/`testssl`). nmap/nessus invoke only under signed `SCOPE.allow_tools` — never a free-day live default. DEMO `SCOPE.yaml` still allowlists nmap for stub e2e. Rail 4 pytest locks wrap-dead + FARM_TOOL_BIN refuse + USB `evergreen_assessment_mcp` (`check_scope` / `license_guard`) as pack truth; no TypeScript refuse matrix. Farm SOP never points at a RiskReady write. STATUS `wrap: review-only`. Catalog **not inflated**. pytest **310**. Labs unchanged vs cycle 66 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. DEMO ≠ client. Hexstrike pattern-only.

```json
{"pytest": 310, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```

## cycle 66 — Hephaestus FARM_TOOL_BIN lock (2026-09-04)

`farm_which` / `which_allowed` / `run_allowed` refuse LICENSE-LOCK names even if dropped into `FARM_TOOL_BIN` (nuclei / openvas / wazuh / osquery / BloodHound / PingCastle / RiskReady / hexstrike / smbmap / zmap / enum4linux-ng / …). nmap/nessus stay signed `SCOPE.allow_tools` + stage only — never default free-day live. Wrap-post statics catch evidence/incidents, not only `/api/risks`. Farm SOP never points at a RiskReady write. STATUS `wrap: review-only`. MCP stub remains conductor UX, not USB `evergreen_assessment_mcp` / not a TypeScript refuse matrix. Catalog **not inflated**. pytest **309**. Labs unchanged vs cycle 65 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. DEMO ≠ client. Hexstrike pattern-only.

```json
{"pytest": 309, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```

## cycle 65 — Argus wrap-dead (2026-09-04)

Windows/Origin RiskReady write mocks stay rehearsal-only and are not inherited into farm SOP. pytest asserts STATUS `wrap: review-only` and EXECUTIVE wrap-dead. Farm SOP / product-lab OPERATOR never point at RiskReady login/assets/incidents/evidence writes or `:18080` mock_sink. `push_riskready.sh` remains review-only forever (no login/POST). Stale 00-inventory dual-gate line removed. Catalog **not inflated**. pytest **307**. Labs unchanged vs cycle 63 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. DEMO ≠ client. Hexstrike pattern-only.

```json
{"pytest": 307, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```

## cycle 64 — Themis honesty lock (2026-09-04)

No new Layer C parsers. pytest locks STATUS honesty: `paying_day: FAIL`, `compose_lab: absent` until proven on a Docker host, DEMO ≠ client estate. Operator compose-on-Docker proof commands stay documented (`docker compose up --build --exit-code-from grc-loader` + PASS criteria). LICENSE-LOCK / BloodHound / Nuclei-class still never `will_run=true`. Catalog **not inflated**. pytest **305**. Labs unchanged vs cycle 63 (64/79/19/27 poam 82). Compose ABSENT. Paying-day FAIL. zmap/unicornscan cycle 63 stands.

```json
{"pytest": 305, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```

## cycle 63 — zmap/unicornscan file-drop polish (2026-09-04)

inventory-nmap parses operator-landed zmap JSON/CSV/text and unicornscan text under `in/nmap/`. Open ports only. Empty / closed / RST invent nothing. Detect does not steal nmap / smbmap / arp-scan / naabu. Demo `zmap.txt` + `unicornscan.txt` attach FTP/21 to existing `filesrv.corp.local` (assets unchanged; findings/poam +1, deduped). No zmap/unicornscan subprocess. No live internet scan. Slots stay `file_drop`. Catalog **not inflated**. pytest **301**. Labs green. Compose ABSENT. Paying-day FAIL. LICENSE-LOCK / file_drop-only names still never `will_run=true` (reconfirmed). enum4linux-ng cycle 59 stands.

```json
{"pytest": 301, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 79, "vulns": 19, "evidence": 27, "poam": 82}, "farm_lab": {"assets": 64, "findings": 79, "poam": 82, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 80, "vulns": 19, "poam": 82, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 88, "vulns": 19, "poam": 85, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```

## cycle 62 — MCP stub honesty (2026-09-04)

`dropbox.mcp_stub` is conductor UX for this Python pack — not USB `evergreen_assessment_mcp`, not hosted FastMCP, not a TypeScript refuse matrix, not paying-day truth. Docs + tests lock that. Catalog **not inflated**. pytest **296**. Labs unchanged vs cycle 59 (64/78/19/27 poam 81). Compose ABSENT. Paying-day FAIL. Wrap review-only. enum4linux-ng cycle 59 stands. No new Layer C parser.

```json
{"pytest": 296, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 78, "vulns": 19, "evidence": 27, "poam": 81}, "farm_lab": {"assets": 64, "findings": 78, "poam": 81, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 79, "vulns": 19, "poam": 81, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 87, "vulns": 19, "poam": 84, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL"}
```

## cycle 61 — wrap-dead farm SOP (2026-09-04)

RiskReady wrap stays dead forever: no login, no assets/evidence/incidents POST, not only `/api/risks`. Stale `docs/IMPORT_RR.md` / `SECURITY.md` dual-gate wrap language removed. Farm SOP never points at a RiskReady write (tested). `push_riskready.sh` remains review-only even if `RISKREADY_PUSH=1`. Catalog **not inflated**. pytest **296**. Labs unchanged vs cycle 59 (64/78/19/27 poam 81). Compose ABSENT. Paying-day FAIL. enum4linux-ng cycle 59 stands. No new Layer C parser.

```json
{"pytest": 296, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 78, "vulns": 19, "evidence": 27, "poam": 81}, "farm_lab": {"assets": 64, "findings": 78, "poam": 81, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 79, "vulns": 19, "poam": 81, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 87, "vulns": 19, "poam": 84, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL"}
```

## cycle 60 — LICENSE-LOCK will_run rail + compose-on-Docker docs (2026-09-04)

pytest asserts LICENSE-LOCK / file_drop-only names (BloodHound, Nuclei, OpenVAS/GVM, PingCastle, enum4linux-ng, smbmap, …) never appear in invoke `will_run=true` even when every slot is allowlisted and on PATH. Operator docs list exact `docker compose` commands and PASS criteria for a host with Docker. This VM still stamps compose **ABSENT**. Paying-day **FAIL**. Catalog **not inflated**. pytest **294**. Labs unchanged vs cycle 59 (64/78/19/27 poam 81). enum4linux-ng cycle 59 stands. No new Layer C parser.

```json
{"pytest": 294, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 78, "vulns": 19, "evidence": 27, "poam": 81}, "farm_lab": {"assets": 64, "findings": 78, "poam": 81, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 79, "vulns": 19, "poam": 81, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 87, "vulns": 19, "poam": 84, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL"}
```

## cycle 59 — enum4linux-ng file-drop polish (2026-09-04)

identity-ad parses operator-landed enum4linux-ng JSON/text under `in/identity/` (`target` + users/groups/shares, or Share Enumeration text). Listed users/groups/shares stay listed. Null session, writable shares, and Domain Admins / Backup Operators hints map to existing identity/SMB POA&M only when the export already shows them. Empty invents nothing. Detect does not steal HardeningKitty or BloodHound. Demo `enum4linux-ng.txt` attaches null session + Domain Admins to existing `DC01.CORP.LOCAL` (assets unchanged; findings/poam +2). Collector does not run enum4linux and does not store credentials. Slot stays `file_drop`. Catalog **not inflated**. pytest **293**. Labs green. Compose ABSENT. Paying-day FAIL. smbmap cycle 58 stands.

```json
{"pytest": 293, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 78, "vulns": 19, "evidence": 27, "poam": 81}, "farm_lab": {"assets": 64, "findings": 78, "poam": 81, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 79, "vulns": 19, "poam": 81, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 87, "vulns": 19, "poam": 84, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL"}
```

## cycle 58 — smbmap file-drop polish (2026-09-04)

inventory-nmap parses operator-landed smbmap share tables under `in/nmap/` (`[+] IP:` / Disk + Permissions). Hosts become assets. READ/WRITE shares become exposure findings mapped to existing SMB POA&M (C$/ADMIN$ → restrict admin shares). Empty / NO ACCESS invent nothing. Detect does not steal nmap / arp-scan / nbtscan. Demo `smbmap.txt` attaches writable C$ to existing `filesrv.corp.local` (assets unchanged; findings/poam +1). Collector does not run smbmap or smbclient, never does live SMB, and does not store credentials. Slot stays `file_drop`. Catalog **not inflated**. pytest **288**. Labs green. Compose ABSENT. nbtscan cycle 57 stands.

```json
{"pytest": 288, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 76, "vulns": 19, "evidence": 27, "poam": 79}, "farm_lab": {"assets": 64, "findings": 76, "poam": 79, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 77, "vulns": 19, "poam": 79, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 85, "vulns": 19, "poam": 82, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 57 — nbtscan file-drop polish (2026-09-04)

inventory-nmap parses operator-landed nbtscan name/IP tables under `in/nmap/` (`Doing NBT name scan` / IP + NetBIOS + `<server>`). Hosts become assets only. Empty / header-only invent nothing. Detect does not steal arp-scan / netdiscover / fping. Demo `nbtscan.txt` attaches to existing `filesrv.corp.local` (assets and findings unchanged). Collector does not run nbtscan and never does live NetBIOS. Slot stays `file_drop`. Catalog **not inflated**. pytest **284**. Labs green. Compose ABSENT. netdiscover cycle 56 stands.

```json
{"pytest": 284, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 75, "vulns": 19, "evidence": 27, "poam": 78}, "farm_lab": {"assets": 64, "findings": 75, "poam": 78, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 76, "vulns": 19, "poam": 78, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 84, "vulns": 19, "poam": 81, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 56 — netdiscover file-drop polish (2026-09-04)

inventory-nmap parses operator-landed netdiscover text under `in/nmap/` (`Currently scanning` / IP + MAC + Count + Len + vendor). Hosts become assets only. Empty / header-only invent nothing. arp-scan detect does not claim netdiscover tables. Demo `netdiscover.txt` attaches to existing `filesrv.corp.local` (assets and findings unchanged). Collector does not run netdiscover and never does live ARP. Slot stays `file_drop`. Catalog **not inflated**. pytest **280**. Labs green. Compose ABSENT. fping cycle 55 and arp-scan cycle 54 stand.

```json
{"pytest": 280, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 75, "vulns": 19, "evidence": 27, "poam": 78}, "farm_lab": {"assets": 64, "findings": 75, "poam": 78, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 76, "vulns": 19, "poam": 78, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 84, "vulns": 19, "poam": 81, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 55 — fping file-drop polish (2026-09-04)

inventory-nmap parses operator-landed fping text and JSON under `in/nmap/` (`host is alive` or `{ip, hostname, alive}`). Alive hosts become assets only. Unreachable / empty invent nothing. Demo `fping.txt` attaches to existing `filesrv.corp.local` (assets and findings unchanged). Collector does not run fping and never does live ping. Slot stays `file_drop`. Catalog **not inflated**. pytest **276**. Labs green. Compose ABSENT. arp-scan cycle 54 stands.

```json
{"pytest": 276, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 75, "vulns": 19, "evidence": 27, "poam": 78}, "farm_lab": {"assets": 64, "findings": 75, "poam": 78, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 76, "vulns": 19, "poam": 78, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 84, "vulns": 19, "poam": 81, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 54 — arp-scan file-drop polish (2026-09-04)

inventory-nmap parses operator-landed arp-scan text and JSON under `in/nmap/` (`Starting arp-scan` / IP + MAC + vendor lines, or `{ip, mac, vendor}`). Hosts become assets only. Empty / header-only / 0 responded invent nothing. Demo `arp-scan.txt` attaches to existing `filesrv.corp.local` (assets and findings unchanged). Collector does not run arp-scan and never does live ARP. Slot stays `file_drop`. Catalog **not inflated**. pytest **272**. Labs green. Compose ABSENT. rustscan/naabu cycle 53 stands.

```json
{"pytest": 272, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 75, "vulns": 19, "evidence": 27, "poam": 78}, "farm_lab": {"assets": 64, "findings": 75, "poam": 78, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 76, "vulns": 19, "poam": 78, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 84, "vulns": 19, "poam": 81, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 53 — rustscan / naabu file-drop polish (2026-09-04)

inventory-nmap parses operator-landed rustscan / naabu JSON and JSONL under `in/nmap/` (`{ip, port}` or `{ip, ports:[int]}`). Open ports only. Empty / closed invent nothing. 445 / 3389 / 23 map to existing SMB / RDP / Telnet POA&M. Demo `naabu.jsonl` attaches Telnet 23 to existing `filesrv.corp.local` (assets unchanged; findings/poam +1). Collector does not run rustscan or naabu. Invoke slots stay BYO. Catalog **not inflated**. pytest **268**. Labs green. Compose ABSENT. masscan cycle 52 stands.

```json
{"pytest": 268, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 75, "vulns": 19, "evidence": 27, "poam": 78}, "farm_lab": {"assets": 64, "findings": 75, "poam": 78, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 76, "vulns": 19, "poam": 78, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 84, "vulns": 19, "poam": 81, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 52 — masscan file-drop polish (2026-09-04)

inventory-nmap parses operator-landed masscan `-oX` XML and `-oJ` JSON under `in/nmap/`. Open ports only. Empty `ports` / empty `nmaprun` invent nothing. 445 / 3389 / 23 map to existing SMB / RDP / Telnet POA&M. Demo `masscan.xml` attaches RDP 3389 to existing `filesrv.corp.local` (assets unchanged; findings/poam +1). Collector does not run masscan. Slot stays `file_drop` / `use_dont_ship`. Catalog **not inflated**. pytest **265**. Labs green. Compose ABSENT. sslscan cycle 51 stands.

```json
{"pytest": 265, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 74, "vulns": 19, "evidence": 27, "poam": 77}, "farm_lab": {"assets": 64, "findings": 74, "poam": 77, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 75, "vulns": 19, "poam": 77, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 83, "vulns": 19, "poam": 80, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 51 — sslscan file-drop polish (2026-09-04)

vuln-scan / easm parse operator-landed sslscan XML (`ssltest` / `protocol`) or text (`SSL/TLS Protocols`) under `in/vuln/` or `in/easm/`. Weak/failed only (TLS 1.0, SSLv2/v3, Heartbleed, weak ciphers). Empty / TLS 1.2-only invent nothing. This is **not** testssl JSON (cycle 37) — a separate parse. Demo `sslscan.xml` attaches TLS 1.0 to existing `vpn.example.com` (vulnerability row, not a finding; poam +1; assets unchanged). No live sslscan. sslscan *invoke* stays BYO. Catalog **not inflated**. pytest **262**. Labs green. Compose ABSENT. WhatWeb cycle 50 and SaaS cycle 49 stand.

```json
{"pytest": 262, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 73, "vulns": 19, "evidence": 27, "poam": 76}, "farm_lab": {"assets": 64, "findings": 73, "poam": 76, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 74, "vulns": 19, "poam": 76, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 82, "vulns": 19, "poam": 79, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 50 — WhatWeb file-drop polish (2026-09-04)

easm parses operator-landed WhatWeb `--log-json` (`target` + `plugins`, `{data}` wrap, JSONL) under `in/easm/`. Admin/login titles and interesting paths only. Empty / Home / generic nginx invent nothing. Demo `whatweb.json` attaches admin-login high to existing `admin.example.com` (assets unchanged; findings/poam +1). No live HTTP; collector does not run whatweb. whatweb stays file_drop. Catalog **not inflated**. pytest **258**. Labs green. Compose ABSENT. SaaS cycle 49 and Nessus cycle 48 stand.

```json
{"pytest": 258, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 73, "vulns": 18, "evidence": 27, "poam": 75}, "farm_lab": {"assets": 64, "findings": 73, "poam": 75, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 74, "vulns": 18, "poam": 75, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 82, "vulns": 18, "poam": 78, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 49 — SaaS file-drop polish (2026-09-04)

saas-idp parses operator-landed ScubaGear / Okta / Maester / Graph exports under `in/saas/`. Failed/high only (`Results` / wrappers / JSONL). Pass / Skip / Info / empty invent nothing. Inactive Okta MFA_ENROLL maps to POA&M. Standing Global Administrator (Scuba PIM + Graph export) maps to POA&M. No Graph or Okta API. Demo `scuba-wrap.json` attaches MFA high to existing `contoso.onmicrosoft.com` (assets unchanged; findings/poam +1). scuba / okta-logs stay file_drop. Maester invoke stays BYO. Catalog **not inflated**. pytest **255**. Labs green. Compose ABSENT. Nessus cycle 48 and cycles 44–47 stand.

```json
{"pytest": 255, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 72, "vulns": 18, "evidence": 27, "poam": 74}, "farm_lab": {"assets": 64, "findings": 72, "poam": 74, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 73, "vulns": 18, "poam": 74, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 81, "vulns": 18, "poam": 77, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 48 — Nessus `.nessus` file-drop polish (2026-09-04)

vuln-scan parses operator-landed NessusClientData XML (`ReportHost` / `ReportItem`) under `in/vuln/`. High/Critical plus key Medium (SMB 445, RDP 3389, TLS). Info/Low and empty `Report` invent nothing. Farm DEMO tool-bin `.txt` stubs stay non-Nessus (no `ReportHost`; e2e assets still 64). Demo `demo.nessus` attaches an SMB High to existing `http://10.0.0.20` (counts as a vulnerability, not a finding). No Nessus API; collector does not run nessuscli. nessus invoke stays BYO. Catalog **not inflated**. pytest **247**. Labs green (assets unchanged; vulns/poam +1). Compose ABSENT. Nikto cycle 47 and cycles 44–46 stand.

```json
{"pytest": 247, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 71, "vulns": 18, "evidence": 27, "poam": 73}, "farm_lab": {"assets": 64, "findings": 71, "poam": 73, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 72, "vulns": 18, "poam": 73, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 80, "vulns": 18, "poam": 76, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 47 — Nikto file-drop polish (2026-09-04)

vuln-scan parses Nikto text, XML (`niktoscan` / `scandetails`), and JSON (`vulnerabilities` / `items`) under `in/vuln/`. Interesting/high only (`/admin`, `/login`, `/.git`, directory indexing). Missing security-header noise stays silent. Empty exports invent nothing. Deepen DEMO NessusClientData `.txt` is not Nikto. Demo `nikto.txt` attaches to existing `http://10.0.0.20`. No nikto subprocess; no live HTTP. Catalog **not inflated**. pytest **243**. Labs green (assets unchanged; findings/poam/evidence +1). Compose ABSENT. Cycles 44–46 stand.

```json
{"pytest": 243, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 71, "vulns": 17, "evidence": 27, "poam": 72}, "farm_lab": {"assets": 64, "findings": 71, "poam": 72, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 72, "poam": 72, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 80, "poam": 75, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 46 — ffuf / gobuster file-drop polish (2026-09-04)

easm parses ffuf JSON (`results` + status/url) and gobuster `(Status: N)` text under `in/easm/`. Interesting paths only (`/admin`, `/login`, `/.git`). 404 and robots invent nothing. Empty `results` invents nothing. Demo `ffuf.json` attaches to existing `admin.example.com` (robots/404 silent). No live DNS/HTTP; no ffuf/gobuster subprocess. Catalog **not inflated**. pytest **240**. Labs green (assets unchanged; findings/poam +1). Compose ABSENT. Checkov cycle 45 and EASM cycle 44 stand.

```json
{"pytest": 240, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 70, "vulns": 17, "evidence": 26, "poam": 71}, "farm_lab": {"assets": 64, "findings": 70, "poam": 71, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 71, "poam": 71, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 79, "poam": 74, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 45 — Checkov / Gitleaks / TruffleHog file-drop polish (2026-09-04)

code-secrets parses Checkov `results.failed_checks` (and a report list), Gitleaks `{findings|leaks|results}` wrappers, and TruffleHog `{results}` under `in/code/`. Passed / INFO / empty invent nothing. Secrets stay redacted. Public S3 ACL and credential rows map to existing POA&M. Demo `checkov.json` attaches to existing `infra/terraform.tfvars` (failed only; versioning PASS silent). No live checkov / gitleaks / semgrep / trufflehog. Catalog **not inflated**. pytest **237**. Labs green (assets unchanged; findings/poam/evidence +1). Compose ABSENT. EASM cycle 44 and CIS-CAT/osquery cycle 43 stand.

```json
{"pytest": 237, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 69, "vulns": 17, "evidence": 26, "poam": 70}, "farm_lab": {"assets": 64, "findings": 69, "poam": 70, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 70, "poam": 70, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 78, "poam": 73, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 44 — EASM file-drop polish (2026-09-04)

easm parses httpx / Amass / Subfinder JSON, JSONL, and `{results|hosts|data}` wrappers under `in/easm/`. httpx `failed:true` and empty arrays invent nothing. Sensitive perimeter names and admin/login titles map to existing POA&M. Demo `httpx.json` attaches to existing `admin.example.com` (failed vpn row silent). No live DNS/HTTP; no amass/httpx/subfinder subprocess. Catalog **not inflated**. pytest **229**. Labs green (assets unchanged; findings/poam +1). Compose ABSENT. CIS-CAT/osquery cycle 43 and cycles 39–42 stand.

```json
{"pytest": 229, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 68, "vulns": 17, "poam": 69}, "farm_lab": {"assets": 64, "findings": 68, "poam": 69, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 69, "poam": 69, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 77, "poam": 72, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 43 — CIS-CAT / osquery file-drop polish (2026-09-04)

host-wazuh parses CIS-CAT / XCCDF JSON+XML and osquery failing `queries` under `in/wazuh/`. identity-ad also parses CIS-CAT so the existing `cis-cat` slot glob (`in/identity/*.xml`) works. Failed only; Pass silent. Empty `results` / `queries` invent nothing. SSH PermitRootLogin and disk encryption map to existing POA&M. Demo fixtures attach to existing `jump-unmanaged` (assets unchanged; findings/poam +2). No CIS-CAT binary, no osqueryi. Catalog **not inflated**. pytest **224**. Labs green. Compose ABSENT. Cycles 39–42 stand.

```json
{"pytest": 224, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 67, "vulns": 17, "poam": 68}, "farm_lab": {"assets": 64, "findings": 67, "poam": 68, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 68, "poam": 68, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 76, "poam": 71, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 42 — Nuclei JSON file-drop harden (2026-09-04)

vuln-scan parses Nuclei JSONL / single object / array / `{results|matches|findings}` wrapper under `in/vuln/`. INFO silent. Empty `results` invents nothing. Log4Shell / RCE map to CISO/POA&M. Collector does not subprocess nuclei. Empty `in/` still loads fixtures. Catalog **not inflated**. pytest **220**. Labs green (counts unchanged vs cycle 41). Compose ABSENT. Fleet cycle 41, BloodHound CE cycle 40, and nmap cycle 39 stand.

```json
{"pytest": 220, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 65, "vulns": 17, "poam": 66}, "farm_lab": {"assets": 64, "findings": 65, "poam": 66, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 66, "poam": 66, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 74, "poam": 69, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 41 — Fleet file-drop harden (2026-09-04)

host-wazuh parses Fleet `hosts` / `data.hosts` / a single `host`, plus failing `policies` under `in/wazuh/`. Offline/MIA → coverage gap. `disk_encryption_enabled=false` and MDM enrollment Off map to CISO/POA&M. Passing policies silent. Empty `hosts` / `policies` invent nothing. No Fleet API / fleetctl / osqueryi. Empty `in/` still loads fixtures. Catalog **not inflated**. pytest **216**. Labs green (counts unchanged vs cycle 40). Compose ABSENT. BloodHound CE cycle 40 and nmap cycle 39 stand.

```json
{"pytest": 216, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 65, "vulns": 17, "poam": 66}, "farm_lab": {"assets": 64, "findings": 65, "poam": 66, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 66, "poam": 66, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 74, "poam": 69, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 40 — BloodHound CE file-drop harden (2026-09-04)

identity-ad parses SharpHound CE `data[]` + `Properties` / `ObjectIdentifier` / mapped `Aces`, plus existing `data.nodes` / `data.edges`. Empty `data` / empty `Members` invent nothing. High rows map to CISO/POA&M (DCSync, GenericAll, roastable SPN, AS-REP, unconstrained delegation, Backup Operators). No LDAP / BloodHound run. Empty `in/` still loads fixtures. Catalog **not inflated**. pytest **212**. Labs green (counts unchanged vs cycle 39). Compose ABSENT. nmap cycle 39 stands.

```json
{"pytest": 212, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 65, "vulns": 17, "poam": 66}, "farm_lab": {"assets": 64, "findings": 65, "poam": 66, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 66, "poam": 66, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 74, "poam": 69, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 39 — nmap file-drop harden (2026-09-04)

inventory-nmap parses gnmap / XML / JSON under `in/nmap/`. DEMO stub gnmap from `farm/tool-bin/lab/nmap` → assets + exposure. Open 445 / 3389 / 23 map to existing SMB / RDP / Telnet POA&M. Collector does not subprocess nmap. Empty `in/` still loads fixtures. Catalog **not inflated**. pytest **206**. Labs green (counts unchanged vs cycle 38). Compose ABSENT. k8s cycle 38 stands.

```json
{"pytest": 206, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 65, "vulns": 17, "poam": 66}, "farm_lab": {"assets": 64, "findings": 65, "poam": 66, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 66, "poam": 66, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 74, "poam": 69, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 38 — k8s file-drop harden (2026-09-04)

Kubescape (`summaryDetails` / `results`) and kube-bench (`Controls[].tests[].results[]` or flat FAIL) under `in/k8s/`. Failed/FAIL only; PASS silent. High rows map to CISO/POA&M (privileged containers, anonymous-auth, privilege escalation, hostNetwork). No kubectl / live cluster. Demo kube-bench is the same two FAILs in nested aqua shape. Empty `in/` still loads fixtures. Catalog **not inflated**. pytest **202**. Labs green (counts unchanged vs cycle 37). Compose ABSENT. testssl/Maester cycle 37 stands.

```json
{"pytest": 202, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 65, "vulns": 17, "poam": 66}, "farm_lab": {"assets": 64, "findings": 65, "poam": 66, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 66, "poam": 66, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 74, "poam": 69, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 37 — KEEP-chain file-drop harden (2026-09-04)

testssl JSON (native array or `scanResult`) under `in/vuln/` or `in/easm/`: HIGH/CRITICAL/WARN only; OK silent. No live TLS. Maester `TestResults`/`Tests`/Pester under `in/saas/`: Failed only; Passed/Skipped silent. Graph `directoryRoles` export stays file-drop — empty members invent nothing; no Graph API. High rows map to CISO/POA&M (Heartbleed, TLS 1.0, phishing-resistant MFA). Demo testssl adds TLS 1.0 on existing `dev-api.example.com`. Empty `in/` still loads fixtures. Catalog **not inflated**. pytest **198**. Labs green. Compose ABSENT. HK/Lynis cycle 36 stands.

```json
{"pytest": 198, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 65, "vulns": 17, "poam": 66}, "farm_lab": {"assets": 64, "findings": 65, "poam": 66, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 66, "poam": 66, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 74, "poam": 69, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 36 — endpoint file-drop harden (2026-09-04)

HardeningKitty Audit CSV under `in/identity/`: Failed/warning only; Passed (including Guest) silent. Does not invent Windows findings. Lynis report/`report.dat` under `in/wazuh/` (`*.txt`/`*.log`/`*.dat`). High rows map to CISO/POA&M when obvious (password history, LM hash, host firewall, SSH PermitRootLogin). Demo Lynis attaches to existing `jump-unmanaged`. Empty `in/` still loads fixtures. Catalog **not inflated**. No AD/WinRM/cloud API. pytest **192**. Labs green. Compose ABSENT. Cloud ASFF cycle 35 stands.

```json
{"pytest": 192, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 65, "vulns": 16, "poam": 65}, "farm_lab": {"assets": 64, "findings": 65, "poam": 65, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 66, "poam": 65, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 74, "poam": 68, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 35 — cloud file-drop harden (2026-09-04)

`cloud-prowler` accepts Prowler JSON/ASFF (`ProductFields`, string or dict Severity) and ScoutSuite `services.*.findings` under `in/cloud/`. Finding `ref_id` is check+resource so two buckets stay two rows. High FAIL maps to CISO/POA&M when obvious (public S3 / AllUsers, IAM AdministratorAccess, root MFA, SG `0.0.0.0/0`, public RDS, unencrypted S3/EBS). Demo ASFF adds `demo-asff-open`. Empty `in/` still loads fixtures including `prowler-asff.json` + `scoutsuite.json`. ScoutSuite stays file_drop; Prowler invoke stays BYO. Catalog **not inflated**. No cloud API calls. pytest **187**. Labs green. Compose ABSENT.

```json
{"pytest": 187, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 63, "vulns": 16, "poam": 63}, "farm_lab": {"assets": 64, "findings": 63, "poam": 63, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 64, "poam": 63, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 72, "poam": 66, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 34 — SARIF file-drop parsers (2026-09-04)

`vuln-scan` and `code-secrets` accept `in/vuln/*.sarif` / `in/code/*.sarif`. Shared `shared/sarif.py`. Demo fixture `fixtures/demo/vuln/demo.sarif` (command-injection, high). High SARIF rules map to control_map / POA&M. Empty `in/` still falls back to existing fixtures plus the new SARIF. Catalog **not inflated**. farm/SLOTS.md + OPERATOR document file_drop → these parsers. Docs/e2e stand. pytest **184**. Labs green. Compose ABSENT.

```json
{"pytest": 184, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 63, "findings": 62, "vulns": 16, "poam": 62}, "farm_toolbin_e2e": {"assets": 63, "findings": 63, "poam": 62, "demo": true}, "farm_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 33 — operator UX + honesty docs (2026-09-04)

`farm/QUICKSTART.md` (27 lines): consent → SCOPE → tool-bin DEMO vs real → `make farm-toolbin-e2e` → CISO zip → `--live` only on drop box. Root README “Private drop-box farm” links QUICKSTART + ARCHITECTURE. STATUS + product-lab/EXECUTIVE stamp **111 / 32 / 30**, pytest **180** (179 + QUICKSTART doc test), e2e 63/63 poam 61. DEMO ≠ client estate. Catalog **not inflated**. Cycles 31–32 stand. Labs green. Compose ABSENT.

```json
{"pytest": 180, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_toolbin_e2e": {"assets": 63, "findings": 63, "poam": 61, "demo": true}, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 32 — conductor farm_toolbin_status + MCP snippets (2026-09-04)

Conductor adds `farm_toolbin_status` (FARM_TOOL_BIN resolve: present/missing/demo_stub for wired invoke). `tools/call` `orchestrator_plan` returns per-stage `will_run`. OPERATOR.md + operator_mcp_interface.md have Cursor `.cursor/mcp.json` and Claude Desktop snippets; `scripts/mcp_stdio.sh` starts from repo root. Catalog **not inflated**. Cycle 31 e2e stands. No live internet. No fake compose. pytest **179**. Labs green. Compose ABSENT.

```json
{"pytest": 179, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_toolbin_e2e": "pass", "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 31 — farm-toolbin-e2e quiet→loud DEMO (2026-09-04)

`make farm-toolbin-e2e` / `scripts/farm_toolbin_e2e.py`: isolated `farm/work/e2e` with `FARM_TOOL_BIN=farm/tool-bin/lab`. Plan → discover (DEMO nmap stub) → deepen small batch (DEMO nessus/nessuscli) → external **plan-only** → ingest → Layer C. Artifacts in `in/nmap|vuln`; CISO/POA&M exist; pack `in/` untouched; `demo` true. LICENSE-LOCK still refuses nuclei/openvas. Catalog **not inflated**. No live internet. No fake compose pass. pytest **178**. Labs green. Compose ABSENT.

```json
{"pytest": 178, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_toolbin_e2e": {"assets": 63, "findings": 63, "poam": 61, "demo": true}, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 30 — deepen FARM_TOOL_BIN DEMO stubs (2026-09-04)

Lab stubs add nessus / nessuscli / testssl / testssl.sh / lynis (fixture stdout, DEMO banner, no network). Deepen + external-adjacent plan `will_run` true; `external_stage` still forces false. Dry `run_slot` writes work out. LICENSE-LOCK refuse stands. `make farm-toolbin-lab` asserts nmap+curl. Catalog **not inflated**. pytest **176**. Labs green. Compose ABSENT.

```json
{"pytest": 176, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 29 — FARM_TOOL_BIN DEMO lab stubs (2026-09-04)

`farm/tool-bin/lab/{nmap,curl}` are DEMO shell stubs (fixture gnmap / HTTP headers, no network). `farm_which` checks `FARM_TOOL_BIN` then `FARM_TOOL_BIN/lab` then PATH. Plan `will_run` true when env points at stubs; dry invoke writes work out. External stage still `will_run=false`. Catalog **not inflated**. pytest **172**. Labs green. Compose ABSENT.

```json
{"pytest": 172, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 28 — compose scanner-free skeletons (2026-09-04)

Farm + dropbox compose bind SCOPE / work/in / work/out / tool-bin. Statics catch apt/apk/yum/dnf, pip, wget, FROM/image soup, COPY `.deb`, `git clone`, and wrap `curl … /api/risks`. `make farm-compose` added. Docker absent → **ABSENT** after static PASS (not a fake runtime pass). Catalog **not inflated** (111 / 32 / 30 / 81). pytest **168**. Labs green.

```json
{"pytest": 168, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 27 — ingest dropped external files (2026-09-04)

`ingest_stage` inventories operator-landed files in `in/easm|…` (`dropped_external`). Skips `.gitkeep` / `plan.json`. Still `will_run=false` / `live=false` / `probed=false`. No curl/testssl from orchestrate. Catalog **not inflated** (111 / 32 / 30 / 81). pytest **163**. Labs green.

```json
{"pytest": 163, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 26 — external stage plan-only (2026-09-04)

Stage graph: discover → deepen → **external (plan-only)** → ingest. SCOPE external refuses CIDR, wildcards, `0.0.0.0/0`; named hosts and `https://` URLs allowed. External SLOTS all `will_run=false` (`file_drop or plan-only — operator lands artifacts in in/easm|…`). `make dropbox-external` stays DEMO fixture writer — no live probe from orchestrate/CI. Catalog **not inflated** (111 / 32 / 30 / 81). pytest **160**. Labs green.

```json
{"pytest": 160, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 25 — farm ↔ orchestrator slot selection (2026-09-04)

Plan JSON lists SLOTS per stage from `allow_tools ∩ wired invoke ∩` discover / deepen / external. `--live` discover runs only discover-stage invoke adapters on PATH; missing gets an explicit skip_reason. Deepen batches use deepen invoke slots on discover-live hosts or `deepen_hosts`. nuclei / openvas / file_drop-only never subprocess. Catalog **not inflated** (111 / 32 / 30 / 81). pytest **158**. farm-lab 62/62/24 poam 61. compose absent.

```json
{"pytest": 158, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 24 — farm_slots.brakes matches INTEGRITY.md (2026-09-04)

Conductor `farm_slots` returns structured `brakes` (SCOPE, deepen fail-closed, max_workers=2, batch 2–5, timeout 30s, wrap review-only). Catalog unchanged: **111 / 32 / 30 / 81**. pytest **153**. farm-lab 62/62/24 poam 61.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 23 — Layer C ingest map on SLOTS.md (2026-09-04)

`farm/SLOTS.md` now includes an **Ingest map (Layer C)** table: every slot lands in `in/cloud|nmap|vuln|wazuh|identity|easm|k8s|code|saas`. `ingest_map()` sums to 111. FILE_DROP_ONLY names listed. No theater parsers. Catalog unchanged: **111 / 32 / 30 / 81**.

pytest **153 passed, 1 skipped**. `make farm-lab` 62/62/24 poam 61. compose_lab absent.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "ingest_audit": [], "farm_lab": "pass", "host_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 22 — hostname PATH stub hits 30 invoke (2026-09-04)

Sixth real OS PATH stub (`hostname -f`, discover-adjacent, `in/nmap/`). Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Cycle 20’s 105 named slots stand. No fake padding. Labs unchanged.

pytest **153 passed, 1 skipped**. `make lab` / `make farm-lab` 62/62/15/24 poam 61. `make dropbox-lab` 68/71. compose_lab absent.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "assets": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 21 — quality: PATH-invoke toward 30, conductor, ingest audit (2026-09-04)

Cycle 20 **105** named slots stand. Added 5 real OS stubs (ping / traceroute / tracepath / host / getent) and rewired existing oss_byo (journalctl, kubectl client, snmpwalk named-host). **110 / 31 wired / 29 invoke / 81 file_drop**. nikto / gobuster / ffuf / amass / subfinder / scoutsuite / checkov stay file_drop. Conductor `tools/list` is stable `OPERATOR_TOOLS` order; `farm_slot_status` accepts `category`. `audit_output_globs()` empty — every glob is `in/<Layer-C-sensor>/`. `farm/INTEGRITY.md` brakes table. Cursor `.cursor/mcp.json` snippet in `farm/OPERATOR.md` has `cwd` + `PYTHONPATH`. Wrap dead. No Hexstrike. No USB. No paying-day PASS.

pytest **153 passed, 1 skipped**. `make lab` / `make farm-lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64. compose_lab absent.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 110, "wired": 31, "invoke": 29, "file_drop": 81, "assets": 62, "findings": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 20 — 105-slot catalog (95+), SLOTS.md, conductor counts (2026-09-04)

`farm/SLOTS.yaml` is **105** slots across discover/deepen/external/endpoint/identity/cloud/k8s/secrets/wifi/ot. **23 wired / 21 invoke / 84 file_drop**. openssl + nslookup added as PATH stubs. LICENSE-LOCK (nuclei, openvas, gvm, pingcastle, bloodhound, sharphound, …) stay file_drop, never subprocess. `farm/SLOTS.md` is the category table. Conductor `farm_slots` returns `counts` + `by_category`. Layer C untouched. Wrap dead.

pytest **149 passed, 1 skipped**. `make lab` / `make farm-lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64. compose_lab absent.

```json
{"pytest": 149, "pytest_skipped": 1, "farm_slots": 105, "wired": 23, "invoke": 21, "file_drop": 84, "assets": 62, "findings": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 19 — 21 wired adapters, farm-lab DEMO, farm_slot_status (2026-09-04)

Wired SLOTS **21** (19 invoke + kube-bench/gitleaks file-drop stubs). New invoke: rustscan, naabu, httpx, dig, whois, sslscan. LICENSE-LOCK (nuclei/openvas/pingcastle) never subprocess. Conductor `tools/call` returns plan-only JSON for stage_discover/deepen/ingest plus `farm_slot_status` matrix. `make farm-lab` = plan → fixture discover → ingest → Layer C under `farm/work` (DEMO, not pack `in/`). `farm/OPERATOR.md` is one copy-paste runbook to CISO zip. Wrap dead.

pytest **149 passed, 1 skipped**. `make lab` 62/62/15/24 poam 61. `make farm-lab` 62/62/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64. compose_lab absent.

```json
{"pytest": 149, "pytest_skipped": 1, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "farm_slots": 51, "wired_adapters": 21, "invoke_adapters": 19, "wrap": "review-only"}
```

## cycle 18 — private farm catalog + adapters + conductor (2026-09-04)

`farm/SLOTS.yaml` is a 48-slot tool-zoo catalog (discover/deepen/external/endpoint/identity/cloud/k8s/secrets) with binary, SCOPE key, output glob → `in/<sensor>/`, license_class, default_batch. 13 wired adapter stubs (plan-only if missing; PATH stub tests). `farm/OPERATOR.md` is the install → mount → quiet→loud path. Compose adds short-lived discover/deepen/ingest workers on an internal network. Orchestrator stage graph: plan → shard → discover → destroy → deepen → destroy → ingest → grc_export. Status prints allow_tools ∩ PATH ∩ SLOTS. Conductor lists 8 SCOPE-gated tools and invokes plan/status/farm_slots over JSON-RPC (no FastMCP, no Hexstrike). Layer C untouched. Ingest skips plan.json so pack `in/` stays gitkeep. Wrap dead.

pytest **147 passed, 1 skipped**. `make lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64 demo true. `make dropbox-compose` scanner_free true, status absent.

```json
{"pytest": 147, "pytest_skipped": 1, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "compose_lab_reason": "docker CLI not on PATH", "scanner_free": true, "farm_slots": 48, "wired_adapters": 13, "wrap": "review-only"}
```

## cycle 17 — private farm layout (Layer A) (2026-09-04)

`farm/` is a private operator drop-box: README + `SLOTS.yaml` + scanner-free Dockerfile/compose skeleton. Tools arrive via host PATH, `FARM_TOOL_BIN` bind-mount, or image tags Reid builds. Not Hub soup. Binaries not vendored. Same static apt/embed asserts cover `farm/Dockerfile` + `farm/docker-compose.yml`. Layer C 10 collectors untouched/parse-only. Integrity stop: farm is private. Wrap dead.

pytest **140 passed, 1 skipped**. `make lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64 demo true. `make dropbox-compose` scanner_free true, status absent.

```json
{"pytest": 140, "pytest_skipped": 1, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "compose_lab_reason": "docker CLI not on PATH", "scanner_free": true, "wrap": "review-only"}
```

## cycle 16 — dropbox compose scanner-free + honest ABSENT (2026-09-04)

`dropbox/scanner_free.py` + `tests/test_compose_scanner_free.py` fail if nmap/nessus/nuclei/openvas/gvm reappear as apt/pip/wget/FROM in `Dockerfile` or compose files. `make dropbox-compose` always runs those statics. This VM: **compose_lab: absent** (`docker CLI not on PATH`) — not a fake pass. Runtime path (internal+external demo/dry + image `command -v` probe) is implemented for when Docker is present. CISO `product-lab/drop/MANIFEST` refreshed to current empty-`in/` hashes (62/62/24 poam 61). Wrap dead.

pytest **136 passed, 1 skipped** (honest compose runtime skip). `make lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64 demo true. `make dropbox-compose` scanner_free true, status absent.

```json
{"pytest": 136, "pytest_skipped": 1, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "compose_lab_reason": "docker CLI not on PATH", "scanner_free": true, "wrap": "review-only"}
```

## cycle 15 — MCP serve, worker teardown, external named-only (2026-09-04)

`python3 -m dropbox.mcp_stub serve` lists the seven SCOPE-gated tools (no FastMCP, no Hexstrike). Discover/deepen destroy workers on timeout/failure; status prints timeout, batch overflow, scope miss. External SCOPE refuses wildcards and CIDRs. testssl/curl BYO adapters parallel to nmap. Telnet POA&M golden. Owner/due blank. Wrap dead.

pytest **132**. `make lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64 demo true. Plan-only 3 shards / 2 batches / destroyed=3.

```json
{"pytest": 132, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "wrap": "review-only"}
```

## cycle 14 — three layers + Hexstrike-pattern stub + DEMO E2E (2026-09-04)

Architecture documented (A BYO / B brakes / C parse-only). Hexstrike is UX pattern only — `mcp_stub.py` SCOPE-gated, no vendor submodule, no exploit API. Internal+external DEMO scripts stamp honest DEMO labels through in/ → POA&M → CISO. BYO adapters actually invoke allowlisted PATH stubs. Status CLI prints stage graph, last integrity stop, allow_tools ∩ PATH. POA&M goldens: TLS weak cipher, admin shares, open RDP (owner/due blank). Dropbox-lab `demo: true`.

pytest **126**. `make lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64 demo true. Plan-only 3 shards / 2 batches / destroyed=3. Wrap dead. Docker absent.

```json
{"pytest": 126, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "assets_dropbox_lab": 68, "findings_dropbox_lab": 71, "poam_dropbox_lab": 64, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "wrap": "review-only", "demo_dropbox_lab": true}
```

## cycle 13 — rebase master + orchestrator harden (2026-09-04)

Rebased onto `b9055eb` (CI, loopback bind, evidence floor). Wrap stayed dead. Added BYO adapters, `dropbox status`, SCOPE `--live` refuse (empty/unsigned/0.0.0.0/0), deepen `--live` exit 2 without `stages.deepen`, deepen worker tear-down tests, TLS + admin-share POA&M maps.

pytest **111**. `make lab` 62/59/15/24 poam 58 demo true. `make dropbox-lab` 68/69/15/24 plan-only 3 shards / 2 batches / destroyed=3. Wrap dead. Docker absent.

```json
{"pytest": 111, "assets": 62, "findings": 59, "evidences": 24, "poam": 58, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "wrap": "review-only"}
```

## cycle 12 — orchestrator = brakes (2026-09-04)

Quiet → loud governor. Discover defaults quiet (`nmap -sn`, host timeout, no deepen tools). Deepen fail-closed unless `orchestrator.stages.deepen: true`. Hosts from discover or explicit `deepen_hosts`. `max_workers` default 2. Never /16 in one worker. Never 0.0.0.0/0. Tear-down after each stage. SCOPE.example ships deepen false. DEMO sets true for plan-only lab.

pytest **88**. `make lab` 62/59/15/10 poam 58 demo true. `make dropbox-lab` 68/69 plan-only 3 shards / 2 batches / destroyed=3. Wrap dead. Docker absent.

```json
{"pytest": 88, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "orchestrator": "plan-only quiet→loud"}
```

## cycle 11 — Pentera wedge: finding → CPG/CSF + POA&M (2026-09-04)

Discovery is not enough. `shared/control_map.py` stamps high/critical and key medium (SMB/RDP) with wizard-safe `cpg_*` / `csf_*` (no colons). Loader writes `out/poam/poam.csv` (owner/due blank, status open) plus mapped `applied_controls`. Demo TCP/445 → restrict SMB / confirm SMBv1 disabled — not a CVE. Console `/api/poam` + drop zip. Docs: “Pentera finds it; Evergreen maps it.”

pytest **80**. `make lab` 62/59/15/10, poam **58**, demo true. `make dropbox-lab` 68/69 + orchestrator plan-only 3 shards / 2 batches / destroyed=3. Wrap still dead. Docker absent.

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 10, "applied_controls": 74, "poam": 58, "risk_scenarios": 74, "pytest": 80, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent"}
```

## cycle 10 — orchestrator shards (2026-09-04)

Intelligent chaining, not one scanner on a /16. `dropbox/orchestrator/`: discover shards CIDRs to /24, deepen batches 2–5 hosts, ingest copies artifacts. Plan-only without Nmap/Nessus. BYO if on PATH and in SCOPE.allow_tools. Workers destroyed after discover. Never download Nessus plugins. Never apt-embed.

pytest **75**. `make lab` 62/59 demo true. `make dropbox-lab` 68/69 (extra SCOPE hosts in demo inventory) + orchestrator 3 shards / 2 batches / destroyed=3. Wrap still dead.

## cycle 9 — LICENSE-LOCK + drop-box (2026-09-04)

Reid: pull/harden pack; same PR add evergreen drop-box.

Wrap: `push_riskready.sh` is review-only even if `RISKREADY_PUSH=1`. No login, no curl, no POST. Tests fail if wrap endpoints reappear. Console binds 127.0.0.1 only. CISO prefers clica; no FindingsAssessment UUIDs.

Drop-box: `dropbox/` SCOPE gate (client, consent path+sha256, window, named internal/external). Internal/external profiles. Demo runners write gnmap + httpx JSONL + osquery-shaped host JSON into existing collector formats. No forbidden scanners in the image. `make dropbox-lab` seeds `dropbox/work/in` (not pack `in/`).

Labs this VM (Docker **absent**):

- pytest **61 passed**
- `make lab` empty pack `in/` → fixtures: 62 / 59 / 15 / 10, `demo: true`
- `make dropbox-lab`: 65 / 63 / 15 / 10, `demo: false` (files in IN_DIR) — still not a client
- Wrap `RISKREADY_PUSH=1 DRY_RUN=0` → LICENSE-LOCK, no HTTP
- Console http://127.0.0.1:18765/ ready; `/api/risks` 403

Not stamped: paying-day PASS. USB evergreen-assessment not copied.

```json
{"pytest": 61, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "sink": "absent"}
```


## cycle 1 — BUILD / LAB / GREEN

Pack shipped. Two consecutive green labs. critic 9/10. DONE.md GREEN.

## cycle 2 — parsers + tests (2026-09-01 evening PT)

Overnight 30m loop armed until 07:00 PT (PID 14860).

Improvements:
- Prowler ASFF Findings parser + `fixtures/demo/cloud/prowler-asff.json`
- PingCastle XML parser + `fixtures/demo/identity/pingcastle.xml`
- Amass JSONL `name` field + `fixtures/demo/easm/amass.jsonl`
- Greenbone results fixture
- osquery host coverage in host-wazuh
- `tests/test_schema.py` `tests/test_redact.py` `tests/test_parsers.py`
- `scripts/lab.ps1` `LOOP.md`

Lab: 23 pytest passed; lab_outputs PASS; docker compose loader exit 0. P2 closed. Makefile compose now `--exit-code-from grc-loader`.

```json
{"assets": 50, "findings": 44, "vulnerabilities": 11, "evidences": 10, "applied_controls": 55, "risk_scenarios": 55, "incidents": 41, "risks_proposed": 40, "ocsf": 44, "canonical": 106, "demo": true}
```

## cycle 3 — TruffleHog + Falco (allow-all)

User: allow all requests. Added TruffleHog JSONL (redacted) and Falco runtime events. pytest 25 passed. lab_outputs PASS.

```json
{"assets": 52, "findings": 46, "vulnerabilities": 13, "evidences": 10, "applied_controls": 59, "risk_scenarios": 59, "incidents": 44, "risks_proposed": 43, "ocsf": 46, "canonical": 112, "demo": true}
```

## cycle 4 — 10:36 PM PT tick

Cloud Custodian policies, Steampipe control rows, Nmap greppable (`-oG`). pytest 28 passed. lab_outputs PASS.

```json
{"assets": 55, "findings": 50, "vulnerabilities": 13, "evidences": 10, "applied_controls": 63, "risk_scenarios": 63, "incidents": 47, "risks_proposed": 46, "ocsf": 50, "canonical": 119, "demo": true}
```

## overnight loop ended — 2026-09-02 07:00 PT

PID 14860 exited 0 after the 07:00 America/Los_Angeles cutoff (~9 hours). Not re-armed.

Completed ticks that produced labs: cycle 2–4. Cycle 5 parsers (BloodHound edges, Fleet, SARIF) were written during the 23:07 PT tick; the lab command was interrupted, so those counts were never recorded.

## cycle 5 — C5-LAB + C5-STAMP (2026-09-02 21:58 PT)

`scripts\lab.ps1`: pytest 31 passed, lab_outputs PASS.

Proved in canonical: BloodHound GenericAll/DCSync/AdminTo, Fleet `fleet-laptop-07` coverage, SARIF `python.lang.security.audit.sql-injection`.

```json
{"assets": 60, "findings": 54, "vulnerabilities": 14, "evidences": 10, "applied_controls": 68, "risk_scenarios": 68, "incidents": 52, "risks_proposed": 51, "ocsf": 54, "canonical": 129, "demo": true}
```

DONE_CYCLE5.md GREEN.

## cycle 6 — KEEP queue

KEEP-HK HardeningKitty CSV (identity, no new service). KEEP-MAESTER. KEEP-TESTSSL. KEEP-ASFF2 ScoutSuite. HOSTILE+ Fleet missing hostname. docs/EXCEPTIONS.md. filtering_labels strip blanks. Double lab.ps1 62=62 unique. Evidence names all nine sensors. Compose loader 62/58.

pytest 36. DONE_IMPROVE.md GREEN.

```json
{"assets": 62, "findings": 58, "vulnerabilities": 15, "evidences": 10, "applied_controls": 73, "risk_scenarios": 73, "incidents": 57, "risks_proposed": 56, "ocsf": 58, "canonical": 136, "demo": true}
```

## cycle 7 — README-weak formats

CONTINUE queue 1–12 already GREEN. Added Microsoft Graph directoryRoles (README Scuba/Graph/Okta), kube-bench + httpx unit tests, wizard-safe `cpg_2_W` on CISO filtering_labels.

pytest 39. lab 62 assets / 59 findings.

## cycle 8 — product lab (Docker + evidence)

No new parsers. Inventory + host lab ×2 + compose ×2 + sink truth + negatives. Reports under `product-lab/`. `DONE_PRODUCT_LAB.md` GREEN. Critic 9/10 (P2 typo `OUT_DIR` mkdir empty). Sink absent on this repo; host `:18080` is the other tree and was not contacted.

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 10, "pytest": 39, "host_lab": "pass", "compose_lab": "pass", "sink": "absent"}
```

## cycle 10 — public-repo hardening

CI workflow, SECURITY.md, loopback bind lock, evidence floor 24, import previews, VERSION 0.3.0. Two host labs + compose. `DONE_GITHUB.md` GREEN.

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 24, "pytest": 55, "host_lab": "pass", "compose_lab": "pass"}
```





