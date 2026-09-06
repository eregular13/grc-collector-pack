# CRITIC — cycle 82 (KEEP→Eval handoff + farm_toolbin_status live_ready)

**8/10** — zero P0/P1. Catalog **unchanged**: **111 / 32 / 30 / 81**. Slice B is honest samples (not client KEEP) plus a file-drop Eval JSON (max-5, no HTTP). Slice C makes `farm_toolbin_status` tell operators DEMO stubs are not live-ready. Full pytest **328**. Labs no-diff vs cycle 81 counts. Wrap **dead**. Paying-day **FAIL**. DEMO ≠ client. SAMPLE ≠ client KEEP.

−1 compose runtime still absent (no Docker CLI).  
−1 stubs are DEMO, not real nmap/nessus; keep-lab is samples, not a client KEEP drop.

```json
{"pytest": 328, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "keep_lab": "pass", "farm_toolbin_e2e": "pass", "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never", "scope_gap": "none"}
```
