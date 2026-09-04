# CRITIC — cycle 39 (nmap file-drop harden)

**8/10** — zero P0/P1. Catalog **unchanged**: **111 / 32 / 30 / 81**. Layer C parses operator-landed gnmap / XML / JSON under `in/nmap/` (no nmap subprocess). Stub gnmap from `farm/tool-bin/lab/nmap` → assets + SSH exposure. 445 / 3389 / 23 map to existing SMB / RDP / Telnet POA&M. Empty `in/` still uses fixtures. Host lab 64/65/17 poam 66. e2e 64/66 poam 66 demo true. pytest **206**. Docs/e2e stand. No live internet. Compose still ABSENT. Wrap review-only. No slot inflation. k8s cycle 38 stands.

−1 compose runtime still absent (no Docker CLI).  
−1 stubs are DEMO, not real nmap/nessus. 30 invoke adapters ≠ 100 running binaries.

```json
{"pytest": 206, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_toolbin_e2e": "pass", "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```
