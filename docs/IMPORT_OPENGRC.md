# OpenGRC import

OpenGRC Data Manager accepts CSV per entity. This pack writes files; it does **not** POST until Reid confirms the create-body schema (public searchable names only: asset `name`/`description`/`asset_tag`, risk `title`/`description`/`mitigation`). Sanctum create-body beyond those names is unconfirmed — **no live POST**.

## Files

`out/opengrc/`

| File | Header | Source |
| --- | --- | --- |
| `assets.csv` | `name,description,asset_tag` | canonical assets (`out/canonical/*.jsonl`) |
| `risks.csv` | `title,description,mitigation` | canonical findings |
| `MAPPING.md` | mapping table | same |

`asset_tag` is the pack `ref_id`. `mitigation` is the mapped control name when present.

## Commands

```powershell
cd "C:\GRC Collector\grc-collector-pack"
$env:PYTHONPATH = (Get-Location)
$env:DRY_RUN = "1"
python -m dropbox.import_grc --target opengrc --dry-run
```

`--dry-run` writes the CSVs and prints a plan. **No network.**

`--live` requires `OPENGRC_URL` + `OPENGRC_TOKEN` **and** `push/GATE_OPENGRC` (gitignored). Missing gate or env → exit 2, no socket. With gate, this pack still **does not POST** (schema unconfirmed). Import the CSVs in OpenGRC UI: Data Manager → Assets, then Risks.

Never default a LAN URL. Never POST `/api/risks`.

`client_facing_ready` stays false on docker-sim.
