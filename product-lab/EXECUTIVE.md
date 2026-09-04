# Executive — assessment engine (this GitHub tree)

**Date:** 2026-09-03 22:50 America/Los_Angeles  
**Tree:** `C:\Users\R\grc-collector-pack` = https://github.com/eregular13/grc-collector-pack  
**Not proven here:** `C:\GRC Collector` overnight lab; Hermes verify-cron.

## What is real

- Parse pack: ten collectors, localhost console `python -m product` on 127.0.0.1:18765.
- Host lab + compose: 62 assets / 59 findings / 24 evidence / POA&M rows from findings.
- RiskReady wrap is **dead**. `push_riskready.sh` never POSTs, including login/assets/incidents, even if PUSH=1.
- Drop-box orchestrator: SCOPE schema, plan-only without nmap/nessus, fixture quiet→loud→ingest, deepen batches capped at 5, workers destroyed after stage.
- CISO SoR path: CSVs + clica. POA&M CSV/JSON in `out/poam/` (owner/milestone blank). Golden SMBv1 map → CPG_2_W.

## What is fixture / BYO

- Empty `in/` is demo fixtures, not a client estate.
- `noop_discover` live hosts are synthetic.
- Nmap/Nessus run only if allowlisted **and** on PATH **and** SCOPE is signed; this pack never installs them.
- No mock GRC sink on this compose project.

## Commands

```powershell
python -m pytest tests -q
powershell -ExecutionPolicy Bypass -File .\scripts\lab.ps1
python -m dropbox.orchestrator plan --scope dropbox/SCOPE.example.yaml
python -m product
```

## Next

Operator MCP as a later wrap around this CLI. Not a public attack API. Quote remediation from POA&M + CISO SoR after HITL.
