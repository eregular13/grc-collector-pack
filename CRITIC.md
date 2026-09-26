# CRITIC — cycle 201 (FEDRAMP_OPEN_FLOOD_GUARD)

Lab this brick: pytest **1226** passed, 1 skipped. Ten collectors +
`grc_loader` + `tests/lab_outputs.py` PASS (`assets=78` `findings=101`
`vulnerabilities=22` `applied_controls=123` `risk_scenarios=123`
`poam=122` `excluded=17` `duplicates_merged=16` `flood_guard`
`findings_in=139` `demo=true`). Host-lab unique counts **unchanged**
vs cycle 200. Farm `assets=48` `findings=134` `poam=85` `excluded=89`
(`findings_in=174`). Zero P0/P1. FedRAMP Open == poam.csv decision
set; excluded items never Open. Merged-away rows reach excluded.csv
as DUPLICATE_INSTANCE with surviving EGP-. No rollups. Catalog
**unchanged** **111 / 32 / 30 / 81**. paying_day **FAIL**. No POST
`/api/risks`. RiskReady stay-out. CoS #48 rails below are unchanged.

# CRITIC — cycle 200 (NO_PENTERA_CONSOLE_REFRESH)

Lab this brick: pytest **1223** passed, 1 skipped. Ten collectors +
`grc_loader` + `tests/lab_outputs.py` PASS (`assets=78` `findings=101`
`vulnerabilities=22` `applied_controls=123` `risk_scenarios=123`
`poam=122` `excluded=1` `duplicates_merged=16` `demo=true`). Host-lab
counts **unchanged** vs cycle 199. Zero P0/P1. Pentera vendor line
removed from `scripts/refresh_product_lab_drop_sinks.py` writers and
the loopback console (`product/static/index.html`, export.zip
IMPORT.md). Drift test locks console sources + temp-dir refresh
writes. `product-lab/drop` is **not** regenerated here. Merged master
`9aeb229` (#147 lifecycle) — carried pending ledger rows now ride
both poam.csv and poam_fedramp.csv. Catalog **unchanged**
**111 / 32 / 30 / 81**. paying_day **FAIL**. No POST `/api/risks`.
RiskReady stay-out. CoS #48 rails below are unchanged.
