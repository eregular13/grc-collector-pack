# Executive brief — grc-collector-pack

**Date:** 2026-09-04  
**Subject:** Operator-usable collector pack. RiskReady wrap is dead. Console is localhost-only. Estate is demo until `in/` is filled.

This is a **file emitter**, not a GRC platform and not a connected RiskReady product. Nine collectors parse OSS scanner artifacts already on disk. A host-side console on **127.0.0.1:18765** shows the estate and builds a drop zip. Collectors never live-scan. Nothing POSTs `/api/risks`.

## LICENSE-LOCK

RiskReady is stay-out. `push_riskready.sh` is review-only even if `RISKREADY_PUSH=1`: no login, no HTTP client, no POST to auth, assets, evidence, incidents, or risks. Tests fail if wrap POSTs reappear. Humans review `out/riskready/*.json`.

CISO Assistant is Reid-side system of record. Preferred path is clica / UI CSV import. Optional REST may POST assets and evidences only. This pack does not invent FindingsAssessment UUIDs.

## Lab truth (this checkout)

- **Host lab:** run on this Linux VM (`scripts/lab.sh` / `make lab`). Docker daemon **absent** — no compose lab this run.
- **Inputs:** `in/` is `.gitkeep` only → `fixtures/demo/` → `demo: true`. Not a client estate.
- **Counts:** live in `out/summary.json` after the lab. Do not stamp a paying-day PASS. Prior Windows product-lab recorded 62 assets / 59 findings / 15 vulns / 10 evidence on fixtures; this run must re-measure.
- **Sink:** none on this repo. Do not hit another tree’s `:18080`.

## Operator path

1. Drop real scanner files into `in/<sensor>/` (or accept the demo label).
2. `bash scripts/lab.sh` then `bash scripts/start-product.sh`.
3. Open http://127.0.0.1:18765/ — refresh, review, download drop zip.
4. Import CISO CSVs with clica/UI. Leave RiskReady JSON for a human.

**Recommendation:** ship as a parse-only collector pack with those labels. Do not market wrap, live scan, or a client estate from empty `in/`.
