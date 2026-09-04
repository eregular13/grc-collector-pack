# CRITIC — cycle 14 (architecture + DEMO E2E + adapter invoke)

**8/10** — zero P0/P1. Three-layer contract written. Hexstrike-pattern operator stub only (no exploit API, no submodule). Wrap still review-only. Host lab + dropbox-lab green. Evidence floor 24 (≥18). Dropbox-lab now `demo: true` (honest DEMO labels on dropbox-* overlays). Adapters invoke stub PATH binaries in tests.

−1 compose absent on this VM.  
−1 operator MCP is a CLI stub, not a hosted conductor; live BYO still plan-only here (nmap/nessus missing).

```json
{"pytest": 126, "assets_empty_in": 62, "findings_empty_in": 62, "evidences": 24, "poam": 61, "assets_dropbox_lab": 68, "findings_dropbox_lab": 71, "poam_dropbox_lab": 64, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "wrap": "review-only", "orchestrator": "plan-only quiet→loud", "demo_dropbox_lab": true}
```
