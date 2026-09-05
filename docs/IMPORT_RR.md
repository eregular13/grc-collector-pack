# Import — RiskReady

This pack emits RiskReady Community Edition JSON. Preview rows are **PENDING-shaped**. A human must approve. The pack never auto-PENDING-approves and never wraps or POSTs to RiskReady — not `/api/risks`, not login, not assets/evidence/incidents.

## Files

- `out/riskready/assets.json`
- `out/riskready/incidents.json`
- `out/riskready/evidence.json`
- `out/riskready/risks_proposed.json` — on disk only
- `out/import_preview/riskready_pending.json` and `MANIFEST.json` after `python scripts/preview_rr.py`

## Operator path

1. Run the host lab or Refresh in the console.
2. Review `out/riskready/` on disk. Import into RiskReady is a **human** UI action outside this pack.
3. Open `risks_proposed.json`. A human decides which proposed risks become real risks.
4. Optional dry preview: `python scripts/preview_rr.py`. Status is `PENDING`, `auto_approve: false`, `posts_api_risks: false`.

## LICENSE-LOCK stay-out

`push_riskready.sh` is review-only **forever**, even if `RISKREADY_PUSH=1` and `DRY_RUN=0`. No login. No HTTP client. No POST. Farm SOP never points at a RiskReady write.

HITL approve on RiskReady. Never auto-PENDING-approve. Never wrap.
