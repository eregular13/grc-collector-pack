# CRITIC — cycle 63 (zmap/unicornscan file-drop)

**8/10** — zero P0/P1. Catalog **unchanged**: **111 / 32 / 30 / 81**. Layer C parses operator-landed zmap JSON/CSV/text and unicornscan text under `in/nmap/`. Open ports only. Empty/closed/RST invent nothing. Detect does not steal nmap / smbmap / arp / naabu. Demo attaches FTP/21 to existing `filesrv.corp.local`. No zmap/unicornscan subprocess. Slots stay `file_drop`. No quiet→loud via catalog growth.

**LICENSE-LOCK rail (Metis, reconfirmed):** BloodHound / Nuclei / OpenVAS / GVM / PingCastle / exploit-class / zmap / unicornscan / enum4linux-ng / smbmap never appear in invoke `will_run=true` even when every slot is allowlisted and on PATH. nmap/nessus invoke only when SCOPE.allow_tools + stage + PATH/FARM_TOOL_BIN.

Host lab 64/79/19/27 poam 82. e2e 64/80/19 poam 82 demo true. pytest **301**. Compose **ABSENT**. Paying-day **FAIL**. Wrap review-only. Scanner-free. No Hexstrike vendor.

−1 compose runtime still absent (no Docker CLI).  
−1 stubs are DEMO, not real nmap/nessus. 30 invoke adapters ≠ 100 running binaries.

```json
{"pytest": 301, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_toolbin_e2e": "pass", "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only", "paying_day": "FAIL", "license_lock_will_run": "never"}
```
