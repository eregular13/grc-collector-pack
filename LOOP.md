# Overnight improve loop

Interval: every 30 minutes until **07:00 America/Los_Angeles**.
Sentinel: `AGENT_LOOP_TICK_grc-improve`
Stop: do not re-arm after 07:00 PT. Kill the loop PID.

**Ended** 2026-09-02 ~07:07 PT (PID 14860, exit 0). Do not start another overnight loop.

**2026-09-04 afternoon build:** ended **16:00 America/Los_Angeles** (cycle 81 freeze). Same safety: no live-scan, no POST `/api/risks`, no wrap restore, no paying-day PASS, no USB copy. Do not start another afternoon loop.

## Each tick

1. Read `STATUS.md` `LOOP.md` `FAULTS.md` `CRITIC.md` `PLAN.md` `AGENTS.md` `DONE.md`.
2. Pick **one** focused improvement (parser, fixture, test, or safety). No new GRC UI. No live scan. No POST `/api/risks`.
3. Add or extend tests. Run `python -m pytest tests -q` then the ten collectors + `grc_loader` + `tests/lab_outputs.py`.
4. Append `CYCLE.md`. Update `STATUS.md` (cycle++, last_lab, next_action).
5. If lab fails: write `FAULTS.md`, fix P0/P1, re-lab. Keep `DONE.md` GREEN only if labs still pass.
6. Do not ask the user. Do not stop before 07:00 PT unless the user says stop.

## Backlog (from PLAN / CRITIC / start spec)

- Done: Prowler ASFF, PingCastle XML, Amass JSON, Greenbone, osquery, TruffleHog, Falco, compose, schema/redact tests, hostile
- Next: farm/SCOPE/conductor honesty (Themis: no vanity Layer C parsers)
- Done this window: SARIF, cloud ASFF, HK/Lynis, testssl/Maester, k8s, nmap, BloodHound CE, Fleet, Nuclei JSON, CIS-CAT/osquery, EASM, Checkov/Gitleaks, ffuf/gobuster, Nikto, Nessus `.nessus`, Scuba/Okta SaaS, WhatWeb, sslscan, masscan, rustscan/naabu, arp-scan, fping, netdiscover, nbtscan, smbmap, enum4linux-ng, zmap/unicornscan file-drop
- After cycle 59: stop vanity Layer C parser expansion; harden farm/SCOPE honesty + compose-on-Docker operator docs. Paying-day FAIL. Compose ABSENT until proven on a Docker host.
- Cycle 60 done: LICENSE-LOCK will_run test + compose PASS criteria docs.
- Cycle 61 done: wrap-dead farm SOP (no RiskReady write path).
- Cycle 62 done: MCP stub honesty (not USB evergreen_assessment_mcp / not TS refuse matrix).
- Cycle 63 done: zmap/unicornscan file-drop. LICENSE-LOCK will_run still never.
- Cycle 64 done: Themis honesty lock (paying-day FAIL, compose ABSENT in pytest).
- Cycle 65 done: Argus wrap-dead (farm SOP never inherits Origin RiskReady write).
- Cycle 66 done: Hephaestus FARM_TOOL_BIN lock (never resolve/spawn LICENSE-LOCK scanners).
- Cycle 67 done: Hephaestus SCOPE example opt-in (nmap/nessus not free-day default).
- Cycle 68 done: Farm SOP honesty (OPERATOR/QUICKSTART/INTEGRITY + brakes JSON).
- Cycle 69 done: Conductor SCOPE gate (farm_slots + export_ciso_poam load SCOPE).
- Cycle 70 done: Orchestrator brakes regressions (free_day_scope / pack_truth / wrap / unsigned SCOPE).
- Cycle 71 done: README honesty rails (STATUS/EXECUTIVE/catalog/pack truth/compose ABSENT).
- Cycle 72 done: SCOPE fail-closed invoke (`run_slot` load_scope + signed allow_tools intersect; CLI/conductor refuse empty/unsigned).
- Cycle 73 done: SCOPE entrypoint inventory = none remaining; FARM_TOOL_BIN refuse-list covers every LICENSE_LOCK_SPAWN name in tool-bin and lab/.
- Cycle 74 done: STATUS/EXECUTIVE next_action is Reid-only blockers (CTA, Eval npm start, KEEP in/ drop, compose-on-Docker, merge PR #1). No fake greens.
- Cycle 75 done: verify-green / no-diff. Full lab suite clean vs cycle 74.
- Cycle 76 done: (e) compose runtime honesty — statics green, runtime ABSENT, no fake PASS.
- Cycle 77 done: (e) compose argv scanner-free — command/entrypoint/CMD/ENTRYPOINT cannot quietly embed scanners or wrap POSTs; runtime still ABSENT.
- Cycle 78 done: verify-green / no-diff. Full lab suite clean vs cycle 77.
- Cycle 79 done: conductor stdio MCP e2e (`mcp serve --once/--stdio`, empty/unsigned SCOPE refuse).
- Cycle 80 done: verify-green / no-diff. Full lab suite clean vs cycle 79.
- Cycle 81 done: deadline freeze / verify-green / no-diff. Full lab suite clean vs cycle 80. Afternoon window ended 16:00 PT.
- Cycle 82 done: KEEP→Eval handoff (`make keep-lab`, samples ≠ client KEEP) + farm_toolbin_status live_ready honesty. Catalog unchanged.
- Cycle 83 done: Hephaestus contract (file_drop/demo never live_ready; tools/call plan-only; two MCP servers; CISO posted gate; SimpleRisk out/ leave-behind; default-off env). Catalog unchanged.
- Cycle 84 done: Argus fail-closed bar stamped; KEEP-minimum one-shot scheduler + landed-only CISO path. 0/4 real KEEP still open. Catalog unchanged.
- Cycle 85 done: keep-lab this-run pack `in/` guard; desktop `python -m keep lab`; estate-only compose park note. Catalog unchanged.
- Cycle 86 done: CISO SoR (`out/ciso-assistant`) + scheduler CLI e2e (vanity + DEMO `--live`) + OPERATOR Day-of. Catalog unchanged.
- Cycle 87 done: pack in/ estate protect (schedule/ingest/ciso read-only unless `--write-pack-in`). Catalog unchanged.
- Cycle 88 done: Hephaestus two-MCP cross-wire fail-closed (`check_scope`/`license_guard` refused on conductor). Catalog unchanged.
- Cycle 89 done: DESKTOP SCOPE attestation hash (LF-canonical + `attest --write`; no skip-hash). Catalog unchanged.
- Cycle 110 done: CoS #16 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu + nping + httpx + sslscan + tlsx + whatweb + hping3 + onesixtyone + nbtscan + braa + ike-scan at HEAD b8f6e124. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the fourteen-name Covey E2E set. Catalog unchanged.
- Cycle 109 done: CoS #15 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu + nping + httpx + sslscan + tlsx + whatweb + hping3 + onesixtyone + nbtscan + braa at HEAD 417ac399. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the thirteen-name Covey E2E set. Catalog unchanged.
- Cycle 108 done: CoS #14 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu + nping + httpx + sslscan + tlsx + whatweb + hping3 + onesixtyone + nbtscan at HEAD d7e36421. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the twelve-name Covey E2E set. Catalog unchanged.
- Cycle 107 done: CoS #13 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu + nping + httpx + sslscan + tlsx + whatweb + hping3 + onesixtyone at HEAD 1dc36844. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the eleven-name Covey E2E set. Catalog unchanged.
- Cycle 106 done: CoS #12 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu + nping + httpx + sslscan + tlsx + whatweb + hping3 at HEAD d522922. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the ten-name Covey E2E set. Catalog unchanged.
- Cycle 105 done: CoS #11 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu + nping + httpx + sslscan + tlsx + whatweb at HEAD c7e77b9. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the nine-name Covey E2E set. Catalog unchanged.
- Cycle 104 done: CoS #10 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu + nping + httpx + sslscan + tlsx at HEAD 1f1a4c7. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the eight-name Covey E2E set. Catalog unchanged.
- Cycle 103 done: CoS #9 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu + nping + httpx + sslscan at HEAD e29c4e4. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the seven-name Covey E2E set. Catalog unchanged.
- Cycle 102 done: CoS #8 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu + nping + httpx at HEAD a4b84d7. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the six-name Covey E2E set. Catalog unchanged.
- Cycle 101 done: CoS #7 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu + nping at HEAD 16eaadc. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the five-name Covey E2E set. Catalog unchanged.
- Cycle 100 done: CoS #6 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping + naabu at HEAD 14a41bd. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/PLAN so next_action cannot lag the four-name Covey E2E set. Catalog unchanged.
- Cycle 99 done: CoS #5 honesty sync. STATUS `next_action` is Covey E2E_PROVEN = nmap + rustscan + fping at HEAD 1c7fb46. No pack Covey adapter work. Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/docs so next_action cannot restamp fping as unproven. Catalog unchanged.
- Cycle 98 done: CoS #4 refine-only. STATUS `next_action` is third live Covey brick held (fping preferred; BYO fping missing on this VM, not in flight). Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks STATUS/docs so compose_lab absent cannot flip to pass. Catalog unchanged.
- Cycle 97 done: CoS #3 refine-only. STATUS `next_action` is refine-only after CoS #2/#3; Reid-only blockers remain CTA + real KEEP `in/` + Eval npm start + Docker compose on a real host (this VM ABSENT ≠ PASS). Pytest locks wrap PUSH=1 fail-closed, CISO SAMPLE/DEMO labels, two-MCP pack-truth refuse. Catalog unchanged.
- Cycle 96 done: CISO Assistant export prove rebased onto Beelzebub #11 (fixture Covey pack_drop + Palisade/Beelzebub honeypot → `out/ciso-assistant`). SAMPLE ≠ client. Paying-day FAIL. Pause brick-adding after this. Catalog unchanged.
- Cycle 95 done: Beelzebub honeypot pack_drop on `in/honeypot/` (stage=null; Palisade-only stages), rebased onto IdP/MDM #9 + DNS/email #8/#10. Not a 12th compose service. Catalog unchanged.
- Cycle 94 done: IdP + MDM file-drop intake rebased on CoS prove-bar #10 + DNS/email #8 + honeypot #7 (saas-idp Entra/Okta/Google users; host-wazuh Intune/Jamf; `in/mdm/` alias). Catalog unchanged.
- Cycle 91 done: honeypot file_drop lane + Covey pack_drop on `in/nmap/` + evidence matrix. Not an 11th compose service. Catalog unchanged.
- Cycle 90 done: Honesty next_action sync (durable Reid-only blockers; gate/hash already on master; no stale merge-PR). Catalog unchanged.
- Cycle 93 done: CoS prove bar (fixture file_drop → collector → out/canonical; SAMPLE ≠ client). No RiskReady POST. Paying-day FAIL.
- Cycle 92 done: DNS/email Seen collector (`in/dns_email/`, Covey `email_dns`). Catalog unchanged. Compose 11 services. Rebased onto honeypot/Covey master.
- Keep counts ≥20 assets, ≥20 findings, ≥8 evidence
- Allow all local lab/compose/pytest requests; do not ask

