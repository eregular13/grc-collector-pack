# 30-minute fixture demo (no pve2)

Say out loud: **this is fixture Litware, not a customer.**

Tree: `C:\GRC Collector\grc-collector-pack`

```powershell
cd "C:\GRC Collector\grc-collector-pack"
$env:PYTHONPATH = (Get-Location)
$env:DRY_RUN = "1"; $env:CISO_PUSH = "0"; $env:RISKREADY_PUSH = "0"; $env:GRC_LIVE_SCAN = "0"

powershell -ExecutionPolicy Bypass -File .\run_lab.ps1

python -m dropbox.orchestrator plan --scope dropbox\SCOPE.example.yaml
python -m dropbox.archive_out --client "Litware Lab LLC"
python -m dropbox.orchestrator run --scope dropbox\SCOPE.example.yaml --stage all

python -m dropbox.new_engagement --slug litware-lab --scope dropbox\SCOPE.example.yaml --archive-leftover
python -m dropbox.package_engagement --slug litware-lab

python -m dropbox.orchestrator console
# http://127.0.0.1:18765/   GET-only, localhost only
```

Show:

1. `engagements\litware-lab\MANIFEST.json` → `client_facing_ready: false`
2. `engagements\litware-lab\out\poam\poam.csv` → SMBv1 row, CPG/CSF refs, owner blank
3. `engagements\litware-lab\out\quote\quote.csv` → hours/rate/total **blank**, status `draft`
4. `engagements\litware-lab\out\ciso-assistant\assets.csv` (and evidences)
5. Zip `engagements\engagement-litware-lab-YYYYMMDD.zip`

Do not set `EVERGREEN_ORCH_LIVE=1`. Do not claim a paying-day PASS.

CISO landing: `docs\IMPORT_CISO.md`. RiskReady: `docs\IMPORT_RR.md` (WRAP_DEAD). Probo: `docs\IMPORT_PROBO.md` (not on this host).
