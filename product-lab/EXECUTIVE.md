# Executive brief — grc-collector-pack

**Date:** 2026-09-04  
**Subject:** Operator-usable collector pack. RiskReady wrap is dead. Console is localhost-only. Estate is demo until `in/` is filled.

This is a **file emitter**, not a GRC platform and not a connected RiskReady product. Nine collectors parse OSS scanner artifacts already on disk. A host-side console on **127.0.0.1:18765** shows the estate and builds a drop zip. Collectors never live-scan. Nothing POSTs `/api/risks`.

## LICENSE-LOCK

RiskReady is stay-out. `push_riskready.sh` is review-only even if `RISKREADY_PUSH=1`: no login, no HTTP client, no POST to auth, assets, evidence, incidents, or risks. Tests fail if wrap POSTs reappear. `RISKREADY_PUSH=1 DRY_RUN=0 bash push_riskready.sh` on this VM printed LICENSE-LOCK and listed `out/riskready/*.json` — curl was not invoked.

CISO Assistant is Reid-side system of record. Preferred path is clica / UI CSV import. Optional REST may POST assets and evidences only. This pack does not invent FindingsAssessment UUIDs.

## Lab truth (this checkout, 2026-09-04)

- **Host lab:** Linux VM. `python3 -m pytest tests -q` → **179 passed, 1 skipped** (honest compose runtime skip). `make lab` / `scripts/lab.sh` → collectors + loader + `lab_outputs: PASS`. Counts:

```json
{"assets": 62, "findings": 62, "vulnerabilities": 15, "evidences": 24, "applied_controls": 77, "poam": 61, "risk_scenarios": 77, "incidents": 58, "risks_proposed": 57, "ocsf": 62, "canonical": 140, "demo": true, "generated_at": "2026-09-04T15:27:12Z"}
```

Asset `ref_id` uniqueness: **62 = 62**.

- **Compose lab:** **absent** — `docker CLI not on PATH`. `make dropbox-compose` and `make farm-compose` ran static scanner-free assertions (PASS, including farm/dropbox skeletons + wrap-POST refuse) and stamped ABSENT. **Statics prove** no scanner embed in Dockerfiles/compose and no wrap POST in those files. **Runtime remains unexercised** (no Docker CLI). Not recorded as compose pass. Prior Windows product-lab (2026-09-03) had pack compose pass twice; that is historical, not this run.
- **Inputs:** `in/` is `.gitkeep` only → `fixtures/demo/` → `demo: true`. **Not a client estate.**
- **Console:** `python3 -m product` bound `127.0.0.1:18765`. `/health` 200, `/api/summary` ready with those counts, GET `/api/risks` 403 `posted: false`, POST `/api/refresh` re-ran 10 modules and kept 62 assets. `GRC_PRODUCT_HOST=0.0.0.0` is refused.
- **Sink:** none on this repo. Did not hit another tree’s `:18080`.
- **Not stamped:** paying-day PASS. USB evergreen-assessment was not copied.

## Operator path

1. Drop real scanner files into `in/<sensor>/` (or accept the demo label).
2. `bash scripts/lab.sh` then `bash scripts/start-product.sh`.
3. Open http://127.0.0.1:18765/ — refresh, review, download drop zip.
4. Import CISO CSVs with clica/UI (`product-lab/drop/MANIFEST`). Leave RiskReady JSON for a human.

- **Dropbox-lab:** `make dropbox-lab` → 68 assets / 71 findings / 15 vulns / 24 evidence / 64 POA&M. `demo: true` (dropbox-* overlays stamp DEMO). Orchestrator plan-only (3 shards, 2 batches, workers destroyed). Not a client.

## Drop-box (this PR)

Reid’s consented one-two combo lives in `dropbox/` + `farm/`. Three layers: BYO tool farm under SCOPE (111 catalog slots, 30 invoke adapters — PATH / bind-mount / Reid’s tags; not Hub soup), orchestrator brakes + stdio conductor, parse-only collectors. Cycle 20’s 105 named slots stand; this window added 6 real OS stubs. `SCOPE.yaml` is fail-closed (client, attestation hash, window, named internal/external). Demo `make dropbox-lab` seeds `dropbox/work/in` from fixtures plus demo overlays — **not a client estate**. Allowlisted host tools only (`ss`/`ip`/`curl`/`lynis` if already on PATH). SimpleRisk is leave-behind docs only (`dropbox/SIMPLERISK.md`). Hexstrike is a UX pattern only — no vendor submodule. See `farm/OPERATOR.md`, `farm/INTEGRITY.md`, and `farm/SLOTS.md`.

**Pentera finds it; Evergreen maps it.** After ingest, the client handoff is CISO CSVs plus `out/poam/poam.csv` (owner/due blank). SMB 445 in the demo nmap estate maps to network-service hardening (`cpg_2_W`, `csf_PR`) — not a hallucinated CVE.

**Recommendation:** ship as a parse-only collector pack plus a gated drop-box. Do not market wrap, CIDR spray, or a client estate from empty `in/` / DEMO SCOPE.

## Delta (this pass, 2026-09-04)

**Cycle 32 — conductor polish:** `farm_toolbin_status` (present/missing/demo_stub). `orchestrator_plan` returns per-stage `will_run`. Cursor + Claude Desktop snippets from repo root (`scripts/mcp_stdio.sh`). Catalog **111** (32 / 30 / 81). Cycle 31 e2e stands. Compose **runtime** still ABSENT.

**Cycle 31 — farm-toolbin-e2e:** `make farm-toolbin-e2e` runs DEMO quiet→loud under `farm/work/e2e` with lab stubs (no internet). Discover → deepen → external plan-only → ingest → Layer C. Pack `in/` untouched. CISO/POA&M exist. LICENSE-LOCK still refuses. Catalog **111** (32 / 30 / 81). Compose **runtime** still ABSENT.

Remaining gaps: Docker CLI still absent here (runtime compose path unexercised). Live BYO still needs real host binaries (not this box). Catalog ≠ 100 running binaries. MCP is stdio JSON-RPC, not hosted FastMCP. Farm compose is a skeleton. No paying-day PASS. USB evergreen-assessment not copied.
