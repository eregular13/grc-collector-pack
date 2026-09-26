# Import — RiskReady

This pack **does not emit** RiskReady Community Edition JSON. RiskReady is LICENSE-LOCK stay-out (PR #128 removed it from the packaged drop; the loader no longer writes `out/riskready/`).

Count identity is CISO Assistant CSVs + `out/poam/poam.csv` (`open_risks`). Import those. Never wrap or POST to RiskReady — not `/api/risks`, not login, not assets/evidence/incidents.

## Operator path

1. Run the host lab or Reload from disk in the console.
2. Hand `out/ciso-assistant/` and `out/poam/poam.csv` (SimpleRisk leave-behind: `out/simplerisk/poam.csv`).
3. Optional leftover preview only if an old tree still has `out/riskready/`: `python scripts/preview_rr.py`. Status is `PENDING`, `auto_approve: false`, `posts_api_risks: false`.

## LICENSE-LOCK stay-out

`push_riskready.sh` is review-only **forever**, even if `RISKREADY_PUSH=1` and `DRY_RUN=0`. No login. No HTTP client. No POST. Farm SOP never points at a RiskReady write.

HITL approve on RiskReady is outside this pack. Never auto-PENDING-approve. Never wrap.
