# KEEP → CISO Assistant CSVs (+ Origin Eval handoff)

Thin file-drop from pack KEEP-chain parsers to **CISO Assistant CSVs**
(primary) and an optional Origin Eval max-5 JSON.
**No live Eval HTTP from this pack.** No RiskReady wrap. No `/api/risks`.

Primary operator path (SAMPLE ≠ client KEEP):

```bash
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0
python3 -m keep lab
# import keep/work/out/ciso-assistant/*.csv  (see IMPORT.md)
```

`IMPORT.json` stamps `demo: true`, `sample: true`, `client_keep: false`,
`paying_day: FAIL` on this checkout. Fixture pack_drop prove is a different
path (`python3 scripts/prove_ciso.py`).

## When to use

Operator has (or will have) KEEP-chain exports:

- HardeningKitty Audit CSV
- Maester / Entra assessment JSON
- testssl.sh JSON
- Prowler JSON **or** ScoutSuite `services.*.findings` JSON

This checkout does **not** ship those four client files. Redacted samples
in `fixtures/keep-samples/` make `python -m keep lab` pass. **SAMPLE ≠ client
KEEP.** See `keep/OPERATOR.md`. Desktop has no `make` / `gh` — use
`python -m keep lab` (or `python3 -m keep lab`). keep-lab never writes
pack `in/`; pre-existing estate there is ignored on the sample path.

## Artifacts

Primary: `keep/work/out/ciso-assistant/*.csv` + `IMPORT.json` after
`python -m keep lab`. Optional Eval: `keep/work/out/eval/handoff.json`.

| Field | Meaning |
|---|---|
| `consumer` | `origin-eval` |
| `posted` / `http` | always `false` |
| `wrap` | `review-only` |
| `sample` / `demo` | `true` until pack `in/` has all four non-sample families |
| `client_keep` | `true` only on a real four-file KEEP drop |
| `max_findings` | `5` — Eval max-5 report shape |
| `findings` | severity-ranked slice (critical → high → medium) |
| `assets` | assets named by those findings |
| `ciso` | paths to CISO Assistant CSVs already on disk |
| `poam` | `poam.csv` path; owner/due blank |

Eval imports the JSON (or the CISO CSVs). A human starts Eval (`npm start`)
on the Eval tree. This pack only writes files.

## Adapters

`keep/adapters.py` detects family and copies into `keep/work/in/<sensor>/`.
Existing Layer C collectors parse. No new sensors. No subprocess of
HardeningKitty / Maester / testssl / Prowler / ScoutSuite.
