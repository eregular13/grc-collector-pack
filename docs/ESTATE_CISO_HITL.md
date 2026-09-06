# Docker estate — HITL leftover after mock importer

Mock GRC on this host: `http://127.0.0.1:18080`.

Already auto-pushed (assets + evidences only) when `CISO_PUSH=1` against the mock. Those CSVs are **pack loader fixture rows** (`out/ciso-assistant`), not the two live-byo Cleartext HTTP rows. A paying client would still review them.

Human import next (do not auto-push):

- `out/ciso-assistant/findings.csv`
- `out/ciso-assistant/vulnerabilities.csv`
- `out/ciso-assistant/risk_scenarios.csv`
- `out/ciso-assistant/applied_controls.csv`
- `out/poam/poam.csv` and `dropbox/out/poam.csv` (estate live-byo: Cleartext HTTP / 127.0.0.1)
- `out/quote/quote.csv` — hours/rate/total blank
- `out/simplerisk/risks_import.csv` — leave-behind, no API

CISO Assistant UI Extra → Import, or `clica`. No FindingsAssessment UUIDs invented here.

RiskReady stays WRAP_DEAD. Never POST `/api/risks`.
