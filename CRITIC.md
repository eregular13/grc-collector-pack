# CRITIC — cycle 27 (external ingest inventory)

**8/10** — zero P0/P1. Catalog **unchanged**: **111 / 32 / 30 / 81**. External stays plan-only. `ingest_stage` now inventories operator-dropped `in/easm|…` files (`dropped_external`); skips `.gitkeep` / `plan.json`; never curl/testssl. SCOPE named-host/URL gate from cycle 26 stands. Labs green.

−1 compose runtime still absent (no Docker CLI).  
−1 live BYO still plan-only here (nmap/nessus missing). 30 invoke adapters ≠ 100 running binaries.

```json
{"pytest": 163, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "assets_empty_in": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```
