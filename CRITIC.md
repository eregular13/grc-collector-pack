# CRITIC — cycle 21 (quality: invoke toward 30)

**8/10** — zero P0/P1. Cycle 20’s 105 named slots stand; cycle 21 adds 5 real OS PATH stubs (not fake padding) and rewires journalctl / kubectl client / snmpwalk. **31 wired / 29 invoke / 81 file_drop** of **110**. nikto/gobuster/ffuf/amass/subfinder/scoutsuite/checkov stay file_drop. `tools/list` order is stable; `farm_slot_status` filters by category. Every `output_glob` lands in an existing Layer C sensor dir. `farm/INTEGRITY.md` records brakes defaults. Labs green. Scanner-free statics hold.

−1 compose runtime still absent (no Docker CLI).  
−1 live BYO still plan-only here (nmap/nessus missing). 29 invoke is toward 30, not 100 running binaries.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 110, "wired": 31, "invoke": 29, "file_drop": 81, "assets_empty_in": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```
