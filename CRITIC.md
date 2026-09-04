# CRITIC — cycle 24 (brakes JSON)

**8/10** — zero P0/P1. Cycle 20’s 105 named slots stand. **32 wired / 30 invoke / 81 file_drop** of **111**. Conductor `farm_slots` now returns `brakes` (INTEGRITY defaults) plus `by_sensor`. `tools/list` stable; `farm_slot_status` filters by category. Ingest map on `SLOTS.md`. Labs green.

−1 compose runtime still absent (no Docker CLI).  
−1 live BYO still plan-only here (nmap/nessus missing). 30 invoke adapters ≠ 100 running binaries.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "assets_empty_in": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```
