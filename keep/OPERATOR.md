# KEEP-chain → Origin Eval handoff

**SAMPLE ≠ client KEEP.** This path parses HardeningKitty / Maester / testssl /
Prowler|ScoutSuite file-drops and writes a max-5 findings + assets JSON that
Origin Eval can import. The pack does **not** call Eval over HTTP and does
**not** POST `/api/risks`. RiskReady wrap stays review-only.

## What this is

Layer C already parses those four KEEP families. keep-lab is a thin lab +
file-drop adapters + Eval handoff — not a new collector suite.

| Family | Adapter | Lands in | Existing collector |
|---|---|---|---|
| HardeningKitty Audit CSV | `keep.adapters.hardeningkitty` | `identity/` | `identity_ad.py` |
| Maester JSON | `keep.adapters.maester` | `saas/` | `saas_idp.py` |
| testssl JSON | `keep.adapters.testssl` | `vuln/` | `vuln_scan.py` |
| Prowler JSON **or** ScoutSuite JSON | `keep.adapters.prowler` / `scoutsuite` | `cloud/` | `cloud_prowler.py` |

Adapters **detect + copy**. They never subprocess those tools.

## Samples vs client KEEP

Four real client files are **absent** from pack `in/` on this checkout.

`fixtures/keep-samples/` ships redacted fixtures so keep-lab stays
green. Hosts use `.invalid`. JSON files set `"sample": true`. See
`fixtures/keep-samples/README.md`.

keep-lab prefers pack `in/` **only** when all four families are present and
none carry the sample banner. Otherwise it lands the samples under
`keep/work/in/` and stamps `sample: true` / `demo: true`.

**keep-lab never writes pack `in/`.** Pre-existing estate files there are
ignored for the sample path. The fail guard is this-run mutation only.

Desktop has no `make` / `gh`. Use:

```bash
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0
python -m keep lab
# or: python3 -m keep lab
```

Outputs (isolated; not pack `out/`):

- `keep/work/out/eval/handoff.json` — Origin Eval file (max 5 findings + assets)
- `keep/work/out/eval/MANIFEST.json` — `posted: false`, `http: false`
- `keep/work/out/ciso-assistant/*.csv` — CISO Assistant CSVs
- `keep/work/out/poam/poam.csv` — owner/due blank
- `keep/work/keep-lab.json` — lab stamp

## Eval consume (no live HTTP from this pack)

Origin Eval (`npm start` on Reid’s Eval tree) reads `handoff.json`:

```json
{
  "consumer": "origin-eval",
  "posted": false,
  "http": false,
  "max_findings": 5,
  "findings": [{"ref_id": "...", "name": "...", "severity": "high", "assets": []}],
  "assets": [{"ref_id": "...", "name": "..."}],
  "ciso": {"shape": "ciso-assistant", "files": ["findings.csv", "assets.csv"]}
}
```

Copy that file (or the CISO CSVs) into Eval. Do not point this pack at a
live Eval URL.

## Real KEEP drop (operator)

1. Land client exports in pack `in/identity/*.csv`, `in/saas/*.json`,
   `in/vuln/*.json`, `in/cloud/*.json`.
2. Re-run `python -m keep lab`. Stamp flips to `client_keep: true` only if all
   four families parse and are not samples.
3. Human reviews `handoff.json` before Eval import.

DEMO fixtures in `fixtures/demo/` are a different estate (full nine-sensor
lab). keep-lab does **not** ingest those.

## Estate already in pack `in/` (DESKTOP)

If pack `in/` already has client/estate files:

- `python -m keep lab` still isolates under `keep/work/`. It does **not**
  park, overwrite, or require you to empty pack `in/`.
- `docker compose up` parses **that estate** (Layer C). Empty-folder
  collectors would otherwise fall back to `fixtures/demo/` — that is the
  fixtures-park pattern. With estate present there is no fixtures-park.
  Either run compose as **estate-only** (current `in/`) **or** park/move
  estate `in/` aside first if you want fixture counts.
- `docker compose config --services` should list exactly 10. Optional
  `up` is skipped when you do not want to mix estate + fixtures.

## Do not

- Treat keep-lab greens as a client KEEP drop
- POST `/api/risks` or restore RiskReady wrap
- Call Origin Eval HTTP from this repo
- Apt-install HardeningKitty / Maester / testssl / Prowler / ScoutSuite
