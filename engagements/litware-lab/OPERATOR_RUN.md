# OPERATOR_RUN — litware-lab

Fixture Litware-style kit unless Reid replaces SCOPE.yaml with a signed live SCOPE.

```powershell
cd "C:\GRC Collector\grc-collector-pack"
$env:PYTHONPATH = (Get-Location)
powershell -ExecutionPolicy Bypass -File .\run_lab.ps1
python -m dropbox.orchestrator plan --scope engagements\litware-lab\SCOPE.yaml
python -m dropbox.new_engagement --slug litware-lab --scope engagements\litware-lab\SCOPE.yaml
python -m dropbox.package_engagement --slug litware-lab
```

Say out loud: this is fixture, not a customer. client_facing_ready is false.

Import: `docs\IMPORT_CISO.md` (CISO SoR). RiskReady is WRAP_DEAD (`docs\IMPORT_RR.md`). No Probo on this lab (`docs\IMPORT_PROBO.md`).
