# CRITIC — cycle 29 (FARM_TOOL_BIN lab stubs)

**8/10** — zero P0/P1. Catalog **unchanged**: **111 / 32 / 30 / 81**. DEMO shell stubs `farm/tool-bin/lab/{nmap,curl}` write fixture-shaped stdout; no network. `farm_which` honors `FARM_TOOL_BIN` then PATH. Plan `will_run` true when pointed at stubs; external stage still plan-only. `make farm-lab` stays plan-only (FARM_TOOL_BIN unset). Compose still ABSENT. Wrap review-only.

−1 compose runtime still absent (no Docker CLI).  
−1 live BYO still plan-only here unless `FARM_TOOL_BIN` points at DEMO stubs or real PATH binaries. 30 invoke adapters ≠ 100 running binaries.

```json
{"pytest": 172, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "assets_empty_in": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```
