# CYCLE log

## cycle 1 — BUILD / LAB / GREEN

Pack shipped. Two consecutive green labs. critic 9/10. DONE.md GREEN.

## cycle 2 — parsers + tests (2026-09-01 evening PT)

Overnight 30m loop armed until 07:00 PT (PID 14860).

Improvements:
- Prowler ASFF Findings parser + `fixtures/demo/cloud/prowler-asff.json`
- PingCastle XML parser + `fixtures/demo/identity/pingcastle.xml`
- Amass JSONL `name` field + `fixtures/demo/easm/amass.jsonl`
- Greenbone results fixture
- osquery host coverage in host-wazuh
- `tests/test_schema.py` `tests/test_redact.py` `tests/test_parsers.py`
- `scripts/lab.ps1` `LOOP.md`

Lab: 23 pytest passed; lab_outputs PASS; docker compose loader exit 0. P2 closed. Makefile compose now `--exit-code-from grc-loader`.

```json
{"assets": 50, "findings": 44, "vulnerabilities": 11, "evidences": 10, "applied_controls": 55, "risk_scenarios": 55, "incidents": 41, "risks_proposed": 40, "ocsf": 44, "canonical": 106, "demo": true}
```

## cycle 3 — TruffleHog + Falco (allow-all)

User: allow all requests. Added TruffleHog JSONL (redacted) and Falco runtime events. pytest 25 passed. lab_outputs PASS.

```json
{"assets": 52, "findings": 46, "vulnerabilities": 13, "evidences": 10, "applied_controls": 59, "risk_scenarios": 59, "incidents": 44, "risks_proposed": 43, "ocsf": 46, "canonical": 112, "demo": true}
```

## cycle 4 — 10:36 PM PT tick

Cloud Custodian policies, Steampipe control rows, Nmap greppable (`-oG`). pytest 28 passed. lab_outputs PASS.

```json
{"assets": 55, "findings": 50, "vulnerabilities": 13, "evidences": 10, "applied_controls": 63, "risk_scenarios": 63, "incidents": 47, "risks_proposed": 46, "ocsf": 50, "canonical": 119, "demo": true}
```

## overnight loop ended — 2026-09-02 07:00 PT

PID 14860 exited 0 after the 07:00 America/Los_Angeles cutoff (~9 hours). Not re-armed.

Completed ticks that produced labs: cycle 2–4. Cycle 5 parsers (BloodHound edges, Fleet, SARIF) were written during the 23:07 PT tick; the lab command was interrupted, so those counts were never recorded.

## cycle 5 — C5-LAB + C5-STAMP (2026-09-02 21:58 PT)

`scripts\lab.ps1`: pytest 31 passed, lab_outputs PASS.

Proved in canonical: BloodHound GenericAll/DCSync/AdminTo, Fleet `fleet-laptop-07` coverage, SARIF `python.lang.security.audit.sql-injection`.

```json
{"assets": 60, "findings": 54, "vulnerabilities": 14, "evidences": 10, "applied_controls": 68, "risk_scenarios": 68, "incidents": 52, "risks_proposed": 51, "ocsf": 54, "canonical": 129, "demo": true}
```

DONE_CYCLE5.md GREEN.

## cycle 6 — KEEP queue

KEEP-HK HardeningKitty CSV (identity, no new service). KEEP-MAESTER. KEEP-TESTSSL. KEEP-ASFF2 ScoutSuite. HOSTILE+ Fleet missing hostname. docs/EXCEPTIONS.md. filtering_labels strip blanks. Double lab.ps1 62=62 unique. Evidence names all nine sensors. Compose loader 62/58.

pytest 36. DONE_IMPROVE.md GREEN.

```json
{"assets": 62, "findings": 58, "vulnerabilities": 15, "evidences": 10, "applied_controls": 73, "risk_scenarios": 73, "incidents": 57, "risks_proposed": 56, "ocsf": 58, "canonical": 136, "demo": true}
```

## cycle 7 — README-weak formats

CONTINUE queue 1–12 already GREEN. Added Microsoft Graph directoryRoles (README Scuba/Graph/Okta), kube-bench + httpx unit tests, wizard-safe `cpg_2_W` on CISO filtering_labels.

pytest 39. lab 62 assets / 59 findings.

## cycle 8 — product lab (Docker + evidence)

No new parsers. Inventory + host lab ×2 + compose ×2 + sink truth + negatives. Reports under `product-lab/`. `DONE_PRODUCT_LAB.md` GREEN. Critic 9/10 (P2 typo `OUT_DIR` mkdir empty). Sink absent on this repo; host `:18080` is the other tree and was not contacted.

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 10, "pytest": 39, "host_lab": "pass", "compose_lab": "pass", "sink": "absent"}
```

## cycle 10 — public-repo hardening

CI workflow, SECURITY.md, loopback bind lock, evidence floor 24, import previews, VERSION 0.3.0. Two host labs + compose. `DONE_GITHUB.md` GREEN.

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 24, "pytest": 55, "host_lab": "pass", "compose_lab": "pass"}
```





