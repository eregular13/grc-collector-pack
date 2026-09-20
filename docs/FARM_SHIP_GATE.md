# Brick 4 — farm wipe/clone ship-gate

CI/lab only. Not a public operator entrypoint.

Cold farm_drop → SoR analog of `sample-to-sor-cold`: wipe dest, isolated
clean checkout of pack HEAD, run `farm_drop_to_sor` (DEMO/SAMPLE labeled),
`assert_risk_register_and_poam`, exit non-zero on garbage.

Operator twins stay unchanged:

- SAMPLE keep (primary KEEP path): `./scripts/sample_to_sor.sh`
- Farm leave-behind: `./scripts/farm_drop_to_sor.sh`

This file documents the **ship event**, not a new console command.

## When it fires (HEAD or assertion surface)

Job `farm-drop-to-sor-cold` in `.github/workflows/lab.yml`.

`scripts/ci/farm_ship_surface.py` diffs this checkout against the PR
base SHA (or `github.event.before` on push to master).

**FARM_SHIP=yes** only when one of these trees changed:

- `scripts/farm_drop_to_sor.sh` / `.ps1`
- `scripts/prove_ciso.py`
- `shared/ciso_shape.py` / `shared/farm_ship.py`
- `collectors/grc_loader.py` (POA&M emitter)
- `fixtures/pack_drop/`
- the gate itself (`.github/workflows/lab.yml`, `scripts/ci/*`, this doc,
  `tests/test_farm_ship_gate.py`)

**FARM_SHIP=skip** when that surface is identical to the compare ref.
An identical re-PASS of the same files is **not** a ship event and does
not re-run the wipe/clone prove. STATUS restamps, catalog comments, and
unrelated collectors are not the product.

Empty / all-zero compare ref (first push) is treated as **yes**.

Surface fingerprint is the sha256 of those file bytes. Pack HEAD is
printed as metadata. Changing HEAD without touching the surface is skip.

## What PASS means

- Isolated clean checkout (`git archive HEAD` into a wiped dest) contained
  `farm_drop_to_sor`, `prove_ciso`, `ciso_shape`, and `fixtures/pack_drop`.
- `farm_drop_to_sor` wrote DEMO/SAMPLE CISO + POA&M under an isolated work dir.
- `prove-ciso.json`: `sample`/`demo` true, `client` false, `paying_day` FAIL,
  `posted` false.
- Risk register + POA&M **shape** (`assert_risk_register_and_poam`): findings
  >= 1, risk_scenarios >= findings, poam_rows >= 1, headers match, farm
  vulnerabilities == 0 (exposure, not CVE-class). Not mere file counts.

Elapsed seconds are honesty-only. Not a 10-minute warm grind.

## What PASS does not mean

- Not client KEEP. SAMPLE/DEMO != client. `argus_keep_real` stays 0/4.
- Not a paying_day PASS. `paying_day` FAIL is required.
- Not a CTA / GTM / public operator entrypoint.
- Not Readiness to skip HITL or POST `/api/risks`.
- Not a substitute for `sample-to-sor-cold` (KEEP samples / CVE-class vulns).
- Re-running the same surface is not a new ship.

## Scripts (CI/lab only)

```
python3 scripts/ci/farm_ship_surface.py --compare-ref <sha>
bash scripts/ci/farm_drop_wipe_clone_ship.sh --from DIR --clone DIR --work DIR
```

Do not add these to Makefile first-line targets or README cold-start lines.
Partial / corrupt wipe-clone trees fail closed (missing `prove_ciso` / pack_drop).

## Honesty

SAMPLE/DEMO != client. paying_day FAIL. posted=false. RiskReady stay-out.
Brick 5 (denser SAMPLE pack_drop) is out of scope here.
