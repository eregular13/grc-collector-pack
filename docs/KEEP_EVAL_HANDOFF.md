# KEEP → Origin Eval handoff

Thin file-drop from pack KEEP-chain parsers to Origin Eval / CISO JSON.
**No live Eval HTTP from this pack.** No RiskReady wrap. No `/api/risks`.

## When to use

Operator has (or will have) KEEP-chain exports:

- HardeningKitty Audit CSV
- Maester / Entra assessment JSON
- testssl.sh JSON
- Prowler JSON **or** ScoutSuite `services.*.findings` JSON

This checkout does **not** ship those four client files. Redacted samples
in `fixtures/keep-samples/` make `make keep-lab` pass. **SAMPLE ≠ client
KEEP.** See `keep/OPERATOR.md`.

## Artifact

`keep/work/out/eval/handoff.json` after `make keep-lab` / `python3 -m keep lab`.

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
