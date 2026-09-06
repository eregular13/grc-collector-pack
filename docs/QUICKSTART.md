# Quickstart

From the **pack root** (this repo). Lab-sim is not a customer pack. `client_facing_ready` stays false.

```powershell
python -m venv .venv
$py = ".\.venv\Scripts\python.exe"
& $py -m pip install -r requirements.txt
$env:PYTHONPATH = (Get-Location)
$env:DRY_RUN = "1"; $env:CISO_PUSH = "0"; $env:RISKREADY_PUSH = "0"; $env:GRC_LIVE_SCAN = "0"
& $py -m pytest tests -q
docker compose -f docker-compose.estate.yml up -d
& $py -m dropbox.product_demo --help
& $py -m dropbox.product_demo
```

`--help` prints usage and exits (no HTTP). Default `run` needs estate-web on `127.0.0.1:18081` or exits 2 `estate_down`. It does **not** fall back to Litware CSVs.

Zip lands under `engagements/`. Import path: [IMPORT_CISO.md](IMPORT_CISO.md). HITL: [HITL.md](HITL.md). Estate net: [ESTATE.md](ESTATE.md). Future client checklist: [CLIENT_ASSESS.md](CLIENT_ASSESS.md). Safety: [SECURITY.md](../SECURITY.md), [NOTICE](../NOTICE).

Unix/macOS: `source .venv/bin/activate` then the same `python -m` commands. `run_lab.ps1` is the Windows fixture lab (pytest + collectors); it must not wipe `engagements/docker-estate-product`.
