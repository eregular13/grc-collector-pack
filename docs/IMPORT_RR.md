# RiskReady — LICENSE-LOCK stay-out

RiskReady is **stay-out forever** on this product. See pack `NOTICE`.

This is **not** an import how-to. There is no wrap, no login, no HTTP, even if flags say push.

## What exists

Review-only JSON under `out\riskready\`:

- `assets.json`
- `evidence.json`
- `incidents.json`
- `risks_proposed.json` — human review only; never upload

## What the script does

```powershell
cd "C:\GRC Collector\grc-collector-pack"
$env:RISKREADY_PUSH = "1"
powershell -ExecutionPolicy Bypass -File .\push_riskready.ps1
```

Expected: prints `WRAP_DEAD`, lists the JSON filenames, **exit 2**, **no HTTP**.

`RISKREADY_PUSH=1` is ignored fail-closed. `DRY_RUN=0` does not revive a wrap.

Never wrap, embed, run, or log in to RiskReady.  
Never POST assets, incidents, evidence, `/api/auth/login`, `/api/itsm`, or `/api/risks`.  
Never treat `risks_proposed.json` as a successful upload.

CISO Assistant is the Reid-side SoR (`docs\IMPORT_CISO.md`). SimpleRisk Core is leave-behind CSV only (`out\simplerisk\risks_import.csv`).

`client_facing_ready: false` on this lab. Scheduler cancelled. I-069 not started.
