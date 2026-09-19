# DESKTOP / client-host dry-run

**SAMPLE ≠ client KEEP.** This is a file-only rehearsal on a DESKTOP or
client host. It does **not** stamp `paying_day` PASS. **SAMPLE keep
cannot stamp client-ready.** Eval day-of (evergreen-eval
`docs/DESKTOP-DAY-OF.md`, loopback HITL) ≠ pack paying_day PASS.
Operator order: [EVAL_PACK_HANDOFF.md](EVAL_PACK_HANDOFF.md). RiskReady wrap
stays review-only. Never POST `/api/risks`. Never live-scan.

No Docker. No `make`. No `gh`. No CISO / OpenGRC / Probo credentials.

## 1. Safety env (required)

From the clone root:

```bash
export PYTHONPATH="$PWD"
export DRY_RUN=1
export GRC_LIVE_SCAN=0
export CISO_PUSH=0
export RISKREADY_PUSH=0
export DROPBOX_LIVE=0
```

`python3 -m keep lab` also **forces** `DRY_RUN=1`, `CISO_PUSH=0`,
`RISKREADY_PUSH=0`, and `GRC_LIVE_SCAN=0` even if your shell had
`CISO_PUSH=1`.

## 2. Run the SAMPLE path

One command (sets the safety env, runs keep-lab, verifies `IMPORT.json`):

```bash
cd /path/to/grc-collector-pack
./scripts/sample_to_sor.sh
# DESKTOP: .\scripts\sample_to_sor.ps1
```

Equivalent without the wrapper:

```bash
cd /path/to/grc-collector-pack
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0
python3 -m keep lab
# same command: python3 -m keep ciso
```

Optional isolation (still never writes pack `in/`):

```bash
python3 -m keep lab --pack-in ./in --work ./keep/work
```

Until pack `in/` has all four **non-sample** KEEP families, this uses
redacted `fixtures/keep-samples/`.

## 3. What you should see

| Path | What it is |
|---|---|
| `keep/work/out/ciso-assistant/*.csv` | CISO Assistant import (primary) |
| `keep/work/out/ciso-assistant/IMPORT.json` | Honesty: `demo: true`, `sample: true`, `client_keep: false`, `paying_day: FAIL`, `posted: false` |
| `keep/work/out/ciso-assistant/IMPORT.md` | Human import notes |
| `keep/work/out/opengrc/{risks,assets,implementations}.csv` | OpenGRC Data Manager (file-only) |
| `keep/work/out/import_preview/probo.json` | Probo `addRisk` / `addFinding` drafts (`posted: false`) |
| `keep/work/out/eval/handoff.json` | Origin Eval max-5 file (no HTTP) |
| `keep/work/keep-lab.json` | Lab stamp (`wrap: review-only`) |

Re-run the file sinks without collectors:

```bash
python3 -m exporters --sink all --out-dir keep/work/out
```

## 4. Verify honesty (before any import)

Open `keep/work/out/ciso-assistant/IMPORT.json` and confirm:

- `demo` / `sample` are **true**
- `client_keep` is **false**
- `paying_day` is **FAIL** (SAMPLE cannot PASS)
- `posted` / `http` are **false**
- `wrap` is **review-only**

OpenGRC `MANIFEST.json` and Probo `probo.json` must also show
`posted: false`, `paying_day: FAIL`, `client: false`. RiskReady is
**stay-out** — do not run a wrap POST.

## 5. Import by hand (not this pack)

1. **CISO Assistant** — clica or the UI CSV import of
   `keep/work/out/ciso-assistant/*.csv`. See `IMPORT.md`. Do not invent
   FindingsAssessment UUIDs. Leave `CISO_PUSH=0`.
2. **OpenGRC** — Data Manager → Import Data → Risks, then Assets, then
   Implementations. Map headers. Status stays **Not Assessed**.
   See [IMPORT_OPENGRC.md](IMPORT_OPENGRC.md).
3. **Probo** — paste one `addRisk` / `addFinding` object at a time after
   filling `organization_id` on **their** instance.
   See [IMPORT_PROBO.md](IMPORT_PROBO.md).

This pack never POSTs those APIs.

## 6. What still blocks true client KEEP (0/4)

Pack `in/` on this checkout does **not** contain the four client KEEP
families (HardeningKitty, Maester, testssl, Prowler|ScoutSuite).
`argus_keep_real` stays **0/4**. SAMPLE/DEMO files in
`fixtures/keep-samples/` and `fixtures/demo/` cannot flip `client_keep`.

Reid-only (this pack cannot invent them):

- Real KEEP files dropped into pack `in/`
- LinkedIn / client CTA
- Origin Eval `npm start` on Reid’s Eval tree
- Docker compose on a real host (this VM `compose_lab` **ABSENT ≠ PASS**)

Gate/hash is already on master (`python -m dropbox gate`).

## Do not

- Treat this dry-run as a client estate or a paying-day PASS
- POST `/api/risks` or restore RiskReady wrap
- Set `CISO_PUSH=1` / `DRY_RUN=0` on SAMPLE
- Live-scan, apt-install scanners, or start Covey adapters
- Add pack_drop integrity vanity bricks
