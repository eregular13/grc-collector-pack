# CRITIC — cycle 8 (product lab)

**9/10** — zero P0/P1. Host lab green twice. Compose lab green twice (daemon up). Reports have commands, exit codes, durations. Did not hit `C:\GRC Collector` `:18080`.

−1 P2: `OUT_DIR` pointing at a missing path mkdir’s an empty estate instead of failing closed (`PL-OUTDIR-MKDIR`). Read-only `OUT_DIR` does fail. Unset `OUT_DIR` uses repo `out/`.

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 10, "canonical": 137, "pytest": 39, "host_lab": "pass", "compose_lab": "pass", "sink": "absent"}
```
