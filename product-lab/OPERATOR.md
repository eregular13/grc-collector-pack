# Operator — run the lab on this Windows host

**Written:** 2026-09-03 21:45 America/Los_Angeles  
**Host:** Windows 10/11, PowerShell, Docker Desktop 4.89.0, Compose v5.5.0, `python` 3.14 at `C:\Python314\python.exe`  
**Repo:** `C:\Users\R\grc-collector-pack`

Do not ask someone else to run these. Do not set `GRC_LIVE_SCAN=1` as a real scan. Do not POST `/api/risks`. Do not hit `localhost:18080` unless `docker compose ps` **in this directory** shows a bind — it will not.

## Host lab

```powershell
cd C:\Users\R\grc-collector-pack
powershell -ExecutionPolicy Bypass -File .\scripts\lab.ps1
```

Expect: pytest `39 passed`, ten collector prints, `lab_outputs: PASS`, exit 0. Typical duration ~3 s. Windows pytest may print `PermissionError` on `pytest-of-R` at atexit; ignore if the 39 passed.

Run twice. `out\ciso-assistant\assets.csv` data rows must equal unique `ref_id` (62 = 62).

## Compose lab

```powershell
cd C:\Users\R\grc-collector-pack
docker compose up --build --exit-code-from grc-loader
```

Expect: ten services, `grc-loader-1 exited with code 0`, compose exit 0, `out\summary.json` assets 62 / findings 59 / evidences 10. Typical duration ~8 s with a warm cache. Compose v5 may log `Aborting on container exit` while collectors finish; the loader still runs after `depends_on`.

There is no `run_docker_lab.ps1` or facet script here.

## Safety env (already in compose and `lab.ps1`)

`DRY_RUN=1` `CISO_PUSH=0` `RISKREADY_PUSH=0` `GRC_LIVE_SCAN=0`

Push scripts (Git bash) with those defaults print dry-run and exit 0:

```powershell
& "C:\Program Files\Git\bin\bash.exe" .\push_ciso.sh
& "C:\Program Files\Git\bin\bash.exe" .\push_riskready.sh
```

## Inputs

Drop scanner JSON/XML/CSV into `in\<sensor>\`. Empty `in/` uses `fixtures/demo/` and labels records `demo`.

## Outputs to hand a GRC operator

See `product-lab\drop\README.md`. Import CISO CSVs with clica/UI. Import RiskReady JSON as assets / evidence / incidents. Leave `risks_proposed.json` for a human. Never auto-POST risks.
