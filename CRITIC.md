# CRITIC — cycle 26 (external plan-only)

**8/10** — zero P0/P1. Catalog **unchanged**: **111 / 32 / 30 / 81**. Stage graph adds `external (plan-only)` after deepen, before ingest. SCOPE refuses CIDR / wildcards / `0.0.0.0/0` in external; named hosts and `https://` URLs allowed. External SLOTS list `will_run=false`. No live curl/testssl from orchestrate. `make dropbox-external` stays DEMO fixture writer. Labs green.

−1 compose runtime still absent (no Docker CLI).  
−1 live BYO still plan-only here (nmap/nessus missing). 30 invoke adapters ≠ 100 running binaries.

```json
{"pytest": 160, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "assets_empty_in": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```
