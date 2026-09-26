# OpenGRC ingest (file-only)

Auth: none from this pack. Operator uses the OpenGRC UI Data Manager.
API (not used here): `Authorization: Bearer <Sanctum token>` at `/api/risks`
and `/api/assets`. This pack never sends those requests.

Source of rows: `out/ciso-assistant/*.csv` from `python3 -m dropbox ciso`
or `python3 scripts/prove_ciso.py`. SAMPLE/DEMO ≠ client.

```bash
export PYTHONPATH="$PWD"
python3 -m exporters --sink opengrc
# files: out/opengrc/{risks,assets,implementations}.csv
```

`posted` is always **false**. No sockets.

## risks.csv

```
code,name,description,status,inherent_likelihood,inherent_impact,inherent_risk,residual_likelihood,residual_impact,residual_risk,is_active
```

- `code` = CISO finding / scenario `ref_id` (upsert key)
- `status` = `Not Assessed` (OpenGRC RiskStatus label)
- scores are 1–5; `*_risk` = likelihood × impact
- residual is one step down when CISO residual is blank
- `is_active` = `true`
- No extra `estate` column — the Data Manager wizard maps the fillable
  fields above. Estate label is in `ESTATE.txt` and in description/notes.

## assets.csv

```
asset_tag,name,hostname,ip_address,notes,is_active,alternative_name
```

- `asset_tag` = CISO `ref_id`
- hostname / IPv4 extracted when present in name/description/link
- taxonomy FKs omitted (`asset_type_id`, `status_id`, …)

## implementations.csv

```
title,details,notes
```

Mapped from CISO `applied_controls.csv`. No control-standard FK invented.
