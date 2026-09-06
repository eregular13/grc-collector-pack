# CRITIC — cycle 83 (Hephaestus live_ready + two-MCP contract)

**8/10** — zero P0/P1. Catalog **unchanged**: **111 / 32 / 30 / 81**. Conductor honesty: file_drop-only and DEMO stubs never `live_ready`; `tools/call` plan-only; two MCP servers stay unmerged; SimpleRisk is `out/` leave-behind only; RiskReady stays review-only even if `RISKREADY_PUSH=1`. Full pytest **331**. Labs no-diff vs cycle 82 counts. Wrap **dead**. Paying-day **FAIL**. DEMO ≠ client. SAMPLE ≠ client KEEP.

−1 compose runtime still absent (no Docker CLI).  
−1 stubs are DEMO, not real nmap/nessus; keep-lab is samples, not a client KEEP drop.

```json
{"pytest": 331, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "keep_lab": "pass", "farm_toolbin_e2e": "pass", "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never", "scope_gap": "none"}
```
