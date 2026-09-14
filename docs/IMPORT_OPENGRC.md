# Import — OpenGRC

This pack writes **Data Manager CSV** files OpenGRC can import. It does not
call the OpenGRC REST API. `posted` stays **false**.

Public contract: [OpenGRC Importing Data](https://docs.opengrc.com/data-manager/import/).
Entity fields: [Risk Management](https://docs.opengrc.com/features/risk-management/),
[Asset Management](https://docs.opengrc.com/features/assets/),
models in [LeeMangold/OpenGRC](https://github.com/LeeMangold/OpenGRC).

## Honesty

| Claim | Truth |
|---|---|
| Estate | **SAMPLE/DEMO ≠ client** unless you pointed `--out-dir` at a real KEEP run. |
| Paying-day | **FAIL.** File-drop export is not a PASS stamp. |
| Posted | **false.** No `/api/risks`, no Sanctum token, no sockets. |
| RiskReady | Stay-out. Do not build a RiskReady sink here. |
| CISO SoR | Unchanged. This sink **reads** `out/ciso-assistant/*.csv`. |

## What OpenGRC expects

The wizard is **CSV → map columns → review**. Templates from the UI are
authoritative for enum labels. This pack emits wizard-mappable headers:

| File | Entity | Columns |
|---|---|---|
| `out/opengrc/risks.csv` | Risks | `code`, `name`, `description`, `status` (`Not Assessed`), inherent/residual likelihood + impact (1–5) + scores, `is_active` |
| `out/opengrc/assets.csv` | Assets | `asset_tag`, `name`, `hostname`, `ip_address`, `notes`, `is_active`, `alternative_name` |
| `out/opengrc/implementations.csv` | Implementations | `title`, `details`, `notes` (from CISO `applied_controls`) |

Omitted on purpose (would invent foreign keys): `id`, `department_id`,
`asset_type_id`, `status_id`, owner IDs. Upsert uses `code` / `asset_tag` /
`name` when you re-import.

## How to run

After the CISO prove path (or any `python3 -m dropbox ciso` that already
wrote `out/ciso-assistant/`):

```bash
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0
python3 -m exporters --sink opengrc
# or
python3 scripts/export_opengrc.py
```

From the SAMPLE prove tree:

```bash
python3 scripts/prove_ciso.py
python3 -m exporters --sink opengrc --out-dir prove/work/out
```

Then in OpenGRC: **Data Manager → Import Data → Risks** (then Assets,
then Implementations). Map headers. Review the first five rows. Status
stays **Not Assessed** until a human scores the risk in OpenGRC.

CSV schema notes: [../schemas/opengrc.md](../schemas/opengrc.md).
CISO headers this sink consumes: [../schemas/ciso-assistant.md](../schemas/ciso-assistant.md).
