# Import — CISO Assistant / Probo-shaped handoff

This pack emits CISO Assistant Community CSVs. The Probo preview is **createRisk-shaped documentation only**. It does not call a network API.

## Files

- `out/ciso-assistant/*.csv` (or `out/ciso_drop/` if you copy them there)
- `out/import_preview/probo.json` after `python scripts/preview_probo.py`

## Operator path

1. Run the host lab or `python -m product` and Refresh estate.
2. Confirm `out/summary.json` and `evidences.csv`.
3. Import CSVs with [clica](https://github.com/intuitem/ciso-assistant-community) or the CISO Assistant UI.
4. Optional: `python scripts/preview_probo.py` and read `out/import_preview/probo.json`. That file documents high/critical rows as `createRisk` drafts. It is not a live create.

## Dual-gate push

`push_ciso.sh` stays dry unless **both** `CISO_PUSH=1` and `DRY_RUN` is not `1`. REST, if ever enabled, is `/api/assets/` and `/api/evidences/` only.

Never `POST /api/risks`.
