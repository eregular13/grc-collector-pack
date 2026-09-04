# RiskReady export (review only)

LICENSE-LOCK: this pack does **not** wrap, login, or POST to RiskReady.

`push_riskready.sh` is fail-closed. Files under `out/riskready/` are for a human. Never POST `/api/risks`.

SimpleRisk Core is the client leave-behind via `out/poam/`.
