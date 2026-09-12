# CISO Assistant import (Reid-side SoR)

**CISO Assistant Community (Intuitem) is Reid’s findings system of record.** This pack writes CSVs. It does not invent FindingsAssessment UUIDs. It does not become the client’s ISMS.

Canonical tree on this host: `C:\GRC Collector\grc-collector-pack`.  
Do not mix with `C:\Users\R\grc-collector-pack`.

Say out loud: **`engagements\litware-lab` is fixture Litware, not a paying client pack.** Never import it into a production CISO tenant as a customer estate.

Lab SCOPE `dropbox\SCOPE.example.yaml` `window_end` was **2026-09-05T09:00-07:00** (expired). After that, live is `window_not_open`. Fixture `--stage all` still ingests **labeled fixture**. Do not extend the window to fake live eligibility.

## Files

Directory: `out\ciso-assistant\` (or `engagements\<slug>\out\ciso-assistant\` after `new_engagement`).

| File | Header (exact) | Auto-push? |
|---|---|---|
| `assets.csv` | `ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets` | yes if `CISO_PUSH=1` |
| `evidences.csv` | `name,description` | yes if `CISO_PUSH=1` |
| `applied_controls.csv` | `ref_id,name,description,domain,status,category,priority,csf_function` | **HITL** |
| `findings.csv` | `ref_id,name,description,severity,status,filtering_labels` | **HITL** |
| `vulnerabilities.csv` | `ref_id,name,description,status,severity,assets,applied_controls` | **HITL** |
| `risk_scenarios.csv` | semicolon-delimited: `ref_id;assets;threats;name;description;existing_controls;current_impact;current_proba;current_risk;additional_controls;residual_impact;residual_proba;residual_risk;treatment` | **HITL** |

Also HITL (not CISO auto-push): `out\poam\poam.csv`.

Live fixture counts on this host: **132** assets, **155** findings, **9** evidence.md files. Evidence is thin vs findings — a demo smell, not a screenshot pack.

## Defaults

```
DRY_RUN=1
CISO_PUSH=0
```

From `dropbox\OPERATOR.md`:

- Dry-run: `$env:CISO_PUSH=0`; `.\push_ciso.ps1` lists files, **no HTTP**.
- Auto-push when you mean it: `$env:CISO_PUSH=1` + `CISO_TOKEN` uploads **assets.csv** and **evidences.csv** only to `/api/importer/`.
- Findings, vulnerabilities, risk_scenarios, applied_controls, and `out\poam\poam.csv` stay **HITL**: CISO Assistant UI Extra → Import, or `clica` if you have it. **Do not auto-push findings.**

## Commands on this tree

```powershell
cd "C:\GRC Collector\grc-collector-pack"
$env:PYTHONPATH = (Get-Location)
$env:DRY_RUN = "1"
$env:CISO_PUSH = "0"
$env:RISKREADY_PUSH = "0"
$env:GRC_LIVE_SCAN = "0"

powershell -ExecutionPolicy Bypass -File .\run_lab.ps1
powershell -ExecutionPolicy Bypass -File .\push_ciso.ps1
# expect: DRY_RUN, lists assets.csv evidences.csv, lists HITL files, exit 0, no HTTP
```

Preferred operator command (dry-run, no HTTP):

```powershell
python -m dropbox.import_grc --target ciso --dry-run
```

`--live` is dual-gate: `CISO_URL` + `CISO_TOKEN` **and** file `push/GATE_CISO` (copy from `push/GATE_CISO.example`; gitignored). Missing gate or env → exit 2, no socket. Live still uploads **assets.csv + evidences.csv** only to `/api/importer/`. Do not invent FindingsAssessment UUIDs. Never POST `/api/risks`.

When Reid really has a CISO Community token and a **non-fixture** tenant:

```powershell
$env:CISO_PUSH = "1"
$env:CISO_URL = "http://127.0.0.1:8000"   # or Reid's URL
$env:CISO_TOKEN = "<token>"               # never commit
Copy-Item push\GATE_CISO.example push\GATE_CISO
python -m dropbox.import_grc --target ciso --live
# or: powershell -ExecutionPolicy Bypass -File .\push_ciso.ps1
# uploads assets.csv + evidences.csv only
# then Extra → Import (or clica) for findings / vulns / risk_scenarios / applied_controls / poam.csv
```

clica (if installed): Extra Import the HITL CSVs after review. Do not invent FindingsAssessment UUIDs. Do not POST findings.

## Success

- Dry-run: `push_ciso.ps1` exit 0, no HTTP, lists the six CSVs.
- After intentional `CISO_PUSH=1`: **132** (or current `out\summary.json` `assets`) assets visible in CISO; **evidences** landed.
- Findings / vulns / risk_scenarios / POA&M still **HITL** until Reid imports them in the UI.
- `client_facing_ready` stays **false** on this lab SCOPE.

See also: `dropbox\OPERATOR.md`, `docs\DEMO_30MIN.md`, `docs\FIRST_LIVE_CHECKLIST.md`.
