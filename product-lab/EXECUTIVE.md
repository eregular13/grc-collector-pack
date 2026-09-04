# Executive brief — grc-collector-pack

**Date:** 2026-09-04  
**Subject:** Operator-usable collector pack. RiskReady wrap is dead. Console is localhost-only. Estate is demo until `in/` is filled.

This is a **file emitter**, not a GRC platform and not a connected RiskReady product. Nine collectors parse OSS scanner artifacts already on disk. A host-side console on **127.0.0.1:18765** shows the estate and builds a drop zip. Collectors never live-scan. Nothing POSTs `/api/risks`.

## LICENSE-LOCK

RiskReady is stay-out. `push_riskready.sh` is review-only even if `RISKREADY_PUSH=1`: no login, no HTTP client, no POST to auth, assets, evidence, incidents, or risks. Tests fail if wrap POSTs reappear. `RISKREADY_PUSH=1 DRY_RUN=0 bash push_riskready.sh` on this VM printed LICENSE-LOCK and listed `out/riskready/*.json` — curl was not invoked.

CISO Assistant is Reid-side system of record. Preferred path is clica / UI CSV import. Optional REST may POST assets and evidences only. This pack does not invent FindingsAssessment UUIDs.

## Lab truth (this checkout, 2026-09-04)

- **Host lab:** Linux VM. `python3 -m pytest tests -q` → **61 passed**. `make lab` / `scripts/lab.sh` → collectors + loader + `lab_outputs: PASS`. Counts:

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 10, "applied_controls": 74, "risk_scenarios": 74, "incidents": 58, "risks_proposed": 57, "ocsf": 59, "canonical": 137, "demo": true, "generated_at": "2026-09-04T05:08:28Z"}
```

Asset `ref_id` uniqueness: **62 = 62**.

- **Compose lab:** Docker daemon **absent** on this VM. Not run. Prior Windows product-lab (2026-09-03) had compose pass twice; that is historical, not this run.
- **Inputs:** `in/` is `.gitkeep` only → `fixtures/demo/` → `demo: true`. **Not a client estate.**
- **Console:** `python3 -m product` bound `127.0.0.1:18765`. `/health` 200, `/api/summary` ready with those counts, GET `/api/risks` 403 `posted: false`, POST `/api/refresh` re-ran 10 modules and kept 62 assets. `GRC_PRODUCT_HOST=0.0.0.0` is refused.
- **Sink:** none on this repo. Did not hit another tree’s `:18080`.
- **Not stamped:** paying-day PASS. USB evergreen-assessment was not copied.

## Operator path

1. Drop real scanner files into `in/<sensor>/` (or accept the demo label).
2. `bash scripts/lab.sh` then `bash scripts/start-product.sh`.
3. Open http://127.0.0.1:18765/ — refresh, review, download drop zip.
4. Import CISO CSVs with clica/UI (`product-lab/drop/MANIFEST`). Leave RiskReady JSON for a human.

- **Dropbox-lab:** `make dropbox-lab` → 68 assets / 69 findings / 15 vulns / 10 evidence. `demo: false` only because fixtures were copied into `dropbox/work/in`. Orchestrator plan-only (3 shards, 2 batches, workers destroyed). Not a client.

## Drop-box (this PR)

Reid’s consented one-two combo lives in `dropbox/`. `SCOPE.yaml` is fail-closed (client, attestation hash, window, named internal/external). Demo `make dropbox-lab` seeds `dropbox/work/in` from fixtures plus demo overlays — **not a client estate**. Allowlisted host tools only (`ss`/`ip`/`curl`/`lynis` if already on PATH). SimpleRisk is leave-behind docs only (`dropbox/SIMPLERISK.md`).

**Recommendation:** ship as a parse-only collector pack plus a gated drop-box. Do not market wrap, CIDR spray, or a client estate from empty `in/` / DEMO SCOPE.
