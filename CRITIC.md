# CRITIC — cycle 13 (rebase + orchestrator harden)

**8/10** — zero P0/P1. Rebased onto master GITHUB-HARDEN. Wrap still review-only (`test_wrap_lock` green). Host lab + dropbox-lab green. Evidence floor 24 (≥18). Orchestrator quiet→loud with fail-closed `--live` tests.

−1 compose absent on this VM.  
−1 dropbox-lab `demo: false` because fixtures were copied into `work/in` — still not a client estate.

```json
{"pytest": 111, "assets_empty_in": 62, "findings_empty_in": 59, "evidences": 24, "poam": 58, "assets_dropbox_lab": 68, "findings_dropbox_lab": 69, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "wrap": "review-only", "orchestrator": "plan-only quiet→loud"}
```
