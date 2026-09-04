# CRITIC — cycle 25 (farm ↔ orchestrator slots)

**8/10** — zero P0/P1. Catalog **unchanged**: **111 / 32 wired / 30 invoke / 81 file_drop**. Plan lists `allow_tools ∩ wired invoke` per discover/deepen/external. `--live` discover uses PATH invoke only; missing → skip_reason. Deepen batches use deepen invoke on discover-live / deepen_hosts. nuclei/openvas never subprocess. Labs green.

−1 compose runtime still absent (no Docker CLI).  
−1 live BYO still plan-only here (nmap/nessus missing). 30 invoke adapters ≠ 100 running binaries.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "assets_empty_in": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```
