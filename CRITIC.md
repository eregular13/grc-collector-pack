# CRITIC — cycle 16 (compose scanner-free + honest ABSENT)

**8/10** — zero P0/P1. Dockerfile + `docker-compose.dropbox.yml` stay scanner-free under automated assertions (apt/pip/wget/FROM). `make dropbox-compose` stamps **absent** on this VM (`docker CLI not on PATH`) after statics pass — not recorded as compose pass. Wrap review-only. Host + dropbox labs green. MANIFEST hashes match current empty-`in/` lab.

−1 compose runtime still absent (no Docker CLI).  
−1 live BYO still plan-only here (nmap/nessus missing).

```json
{"pytest": 136, "pytest_skipped": 1, "assets_empty_in": 62, "findings_empty_in": 62, "evidences": 24, "poam": 61, "assets_dropbox_lab": 68, "findings_dropbox_lab": 71, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "compose_lab_reason": "docker CLI not on PATH", "scanner_free": true, "wrap": "review-only"}
```
