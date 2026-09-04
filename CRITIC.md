# CRITIC — cycle 67 (Hephaestus SCOPE example opt-in)

**8/10** — zero P0/P1. Catalog **unchanged**: **111 / 32 / 30 / 81**. No new parsers. Client `SCOPE.example.yaml` no longer default-allowlists nmap/nessus. Invoke stays signed SCOPE only. `FARM_TOOL_BIN` never resolves or spawns LICENSE-LOCK scanners. RiskReady wrap stays **dead** forever (no login / no assets / no incidents / no evidence POST — not only `/api/risks`). Farm SOP never points at a RiskReady write. STATUS `wrap: review-only`. Paying-day **FAIL**. Compose **ABSENT** (hole, not a PASS). DEMO ≠ client. Hexstrike pattern-only. USB `evergreen_assessment_mcp` (`check_scope` / `license_guard`) remains pack truth — MCP stub is not. Scanner-free + wrap-dead hold because rails 1–3 hold. Host lab 64/79/19/27 poam 82. e2e 64/80/19 poam 82 demo true. pytest **310**.

−1 compose runtime still absent (no Docker CLI).  
−1 stubs are DEMO, not real nmap/nessus.

```json
{"pytest": 310, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_toolbin_e2e": "pass", "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```
