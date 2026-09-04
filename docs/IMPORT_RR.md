# Import — RiskReady

This pack emits RiskReady Community Edition JSON. Preview rows are **PENDING-shaped**. A human must approve. The pack never auto-PENDING-approves and never POSTs `/api/risks`.

## Files

- `out/riskready/assets.json`
- `out/riskready/incidents.json`
- `out/riskready/evidence.json`
- `out/riskready/risks_proposed.json` — on disk only
- `out/import_preview/riskready_pending.json` and `MANIFEST.json` after `python scripts/preview_rr.py`

## Operator path

1. Run the host lab or Refresh in the console.
2. Import assets, evidence, and incidents in RiskReady (UI or API when `RISKREADY_PUSH=1` **and** `DRY_RUN` is not `1`).
3. Open `risks_proposed.json`. A human decides which proposed risks become real risks.
4. Optional dry preview: `python scripts/preview_rr.py`. Status is `PENDING`, `auto_approve: false`, `posts_api_risks: false`.

## Dual-gate push

`push_riskready.sh` stays dry unless **both** `RISKREADY_PUSH=1` and `DRY_RUN` is not `1`. Allowed live POSTs: login, assets, evidence, incidents.

HITL approve on RiskReady. Never auto-PENDING-approve. Never `POST /api/risks`.
