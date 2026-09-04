# RiskReady — review-only

LICENSE-LOCK. This pack does not login or POST to RiskReady, even if `RISKREADY_PUSH=1`.

Read `out/riskready/risks_proposed.json` as a human. Import elsewhere is a person-with-a-file problem.

Client leave-behind is SimpleRisk-shaped **POA&M** in `out/poam/poam.csv` (owner and milestone blank, status `open`).

Never `POST /api/risks`.
