# KEEP-chain → CISO Assistant (SAMPLE)

**SAMPLE ≠ client KEEP.** This path parses HardeningKitty / Maester / testssl /
Prowler|ScoutSuite file-drops and writes CISO Assistant CSVs under
`keep/work/out/ciso-assistant/`. The pack does **not** call CISO Assistant or
Eval over HTTP and does **not** POST `/api/risks`. RiskReady wrap stays
review-only. `paying_day` stays **FAIL**.

## Primary path this week (Desktop — no make / no gh)

**Human dry-run:** [docs/DESKTOP_DRY_RUN.md](../docs/DESKTOP_DRY_RUN.md)
(`DRY_RUN=1`, `CISO_PUSH=0`). Self-lab uses redacted
`fixtures/keep-samples/` until a real client KEEP lands in pack `in/`.
Do not treat this as a client estate. **SAMPLE ≠ client KEEP.**
`paying_day` cannot PASS from SAMPLE. RiskReady stay-out.

```bash
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0
python3 -m keep lab
# alias: python3 -m keep ciso
# optional: python3 -m keep lab --pack-in ./in --work ./keep/work
```

Import (clica or CISO Assistant UI) — see `keep/work/out/ciso-assistant/IMPORT.md`:

- `keep/work/out/ciso-assistant/assets.csv`
- `keep/work/out/ciso-assistant/findings.csv`
- `keep/work/out/ciso-assistant/vulnerabilities.csv`
- `keep/work/out/ciso-assistant/applied_controls.csv`
- `keep/work/out/ciso-assistant/evidences.csv`
- `keep/work/out/ciso-assistant/risk_scenarios.csv`

Honesty on that bundle (`IMPORT.json`): `demo: true`, `sample: true`,
`client_keep: false`, `paying_day: FAIL`, `posted: false`. **SAMPLE ≠ client.**

Optional Eval max-5 file (same run): `keep/work/out/eval/handoff.json`.
A human starts Origin Eval (`npm start`) on Reid’s Eval tree. This pack
only writes files.

## What this is

Layer C already parses those four KEEP families. keep-lab is a thin lab +
file-drop adapters + CISO/Eval handoff — not a new collector suite.

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
`fixtures/keep-samples/README.md`. `fixtures/demo/` KEEP-shaped files are a
different estate — they do **not** flip `client_keep`.

keep-lab prefers pack `in/` **only** when all four families are present and
none carry the sample/demo banner. Otherwise it lands the samples under
`keep/work/in/` and stamps `sample: true` / `demo: true`.

**keep-lab never writes pack `in/`.** Pre-existing estate files there are
ignored for the sample path. The fail guard is this-run mutation only.

Outputs (isolated; not pack `out/`):

- `keep/work/out/ciso-assistant/*.csv` — CISO Assistant import (primary)
- `keep/work/out/ciso-assistant/IMPORT.json` — honesty + file list
- `keep/work/out/eval/handoff.json` — Origin Eval file (max 5 findings + assets)
- `keep/work/out/eval/MANIFEST.json` — `posted: false`, `http: false`
- `keep/work/out/opengrc/{risks,assets,implementations}.csv` — OpenGRC Data Manager (file-only)
- `keep/work/out/import_preview/probo.json` — Probo addRisk/addFinding drafts (not a live create)
- `keep/work/out/poam/poam.csv` — owner/due blank
- `keep/work/keep-lab.json` — lab stamp

SAMPLE/DEMO KEEP is enough for those sinks (`demo: true`). Do not wait for
a denser client KEEP drop. RiskReady stay-out. `posted: false`.

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
   `in/vuln/*.json`, `in/cloud/*.json`. IdP user-inventory (Entra/Okta/Google)
   also lands in `in/saas/`; Intune/Jamf device inventory in `in/mdm/` or
   `in/wazuh/` (host-wazuh extra path). Those are file-drop assessment
   collectors, not additional KEEP families.
2. Re-run `python -m keep lab`. Stamp flips to `client_keep: true` only if all
   four families parse and are not samples or `fixtures/demo/` KEEP.
3. Human reviews `IMPORT.md` / `handoff.json` before CISO or Eval import.

DEMO fixtures in `fixtures/demo/` are a different estate (full nine-sensor
lab). keep-lab does **not** ingest those as client KEEP.

## Estate already in pack `in/` (DESKTOP)

If pack `in/` already has client/estate files:

- `python -m keep lab` still isolates under `keep/work/`. It does **not**
  park, overwrite, or require you to empty pack `in/`.
- `docker compose up` parses **that estate** (Layer C). Empty-folder
  collectors would otherwise fall back to `fixtures/demo/` — that is the
  fixtures-park pattern. With estate present there is no fixtures-park.
  Either run compose as **estate-only** (current `in/`) **or** park/move
  estate `in/` aside first if you want fixture counts.
- `docker compose config --services` should list exactly 11. Optional
  `up` is skipped when you do not want to mix estate + fixtures.

## Do not

- Treat keep-lab greens as a client KEEP drop
- POST `/api/risks` or restore RiskReady wrap
- Call Origin Eval or CISO Assistant HTTP from this repo
- Apt-install HardeningKitty / Maester / testssl / Prowler / ScoutSuite
- Stamp `paying_day` PASS from SAMPLE/DEMO KEEP
- Skip [docs/DESKTOP_DRY_RUN.md](../docs/DESKTOP_DRY_RUN.md) on a client host
