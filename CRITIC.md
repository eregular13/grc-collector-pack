# CRITIC — cycle 12 (orchestrator brakes)

**8/10** — zero P0/P1. Host lab green. Dropbox-lab green including quiet→loud plan-only (no Nmap/Nessus on PATH). `stages.deepen` fail-closed when missing. Compose not run (daemon absent). Wrap dead. Console localhost-only. POA&M still 58 blank-owner rows.

−1 compose absent on this VM (historical Windows compose pass is not this run).  
−1 dropbox-lab copies fixtures into `work/in`, so `summary.demo` is false even though the estate is still fixtures + demo overlays — documented, not a client.

```json
{"assets_empty_in": 62, "findings_empty_in": 59, "assets_dropbox_lab": 68, "findings_dropbox_lab": 69, "poam": 58, "pytest": 88, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "wrap": "review-only", "orchestrator": "plan-only quiet→loud"}
```
