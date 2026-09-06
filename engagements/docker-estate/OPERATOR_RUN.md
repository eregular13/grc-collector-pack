# OPERATOR_RUN — docker-estate

Fixture Litware-style kit unless Reid replaces SCOPE.yaml with a signed live SCOPE.

```powershell
cd "C:\GRC Collector\grc-collector-pack"
$env:PYTHONPATH = (Get-Location)
powershell -ExecutionPolicy Bypass -File .\run_lab.ps1
python -m dropbox.orchestrator plan --scope engagements\docker-estate\SCOPE.yaml
python -m dropbox.new_engagement --slug docker-estate --scope engagements\docker-estate\SCOPE.yaml
python -m dropbox.package_engagement --slug docker-estate
```

Say out loud: this is fixture, not a customer. client_facing_ready is false.
