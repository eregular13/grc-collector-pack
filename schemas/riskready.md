# RiskReady Community Edition — LICENSE-LOCK stay-out

**This pack never wraps or runs RiskReady and does not generate `out/riskready/`.** `push_riskready.sh` is review-only even if `RISKREADY_PUSH=1`: no login, no HTTP client, no POST.

Count identity is the CISO risk register + POA&M (`open_risks`). The operator console reads those files, not RiskReady JSON. Never auto-POST `/api/risks`.

Historical field map (not produced):

- likelihood: `RARE|UNLIKELY|POSSIBLE|LIKELY|ALMOST_CERTAIN`
- impact: `NEGLIGIBLE|MINOR|MODERATE|MAJOR|SEVERE`

Map (kept in `shared.schema.rr_likelihood_impact` for tests only): info→RARE/NEGLIGIBLE, low→UNLIKELY/MINOR, medium→POSSIBLE/MODERATE, high→LIKELY/MAJOR, critical→ALMOST_CERTAIN/SEVERE.
