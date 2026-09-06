#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
$env:PYTHONPATH = $Root
$env:DRY_RUN = "1"
$env:CISO_PUSH = if ($env:CISO_PUSH) { $env:CISO_PUSH } else { "0" }
$env:RISKREADY_PUSH = "0"
$env:GRC_LIVE_SCAN = "0"
Remove-Item Env:EVERGREEN_ORCH_LIVE -ErrorAction SilentlyContinue
python -m dropbox.product_demo
exit $LASTEXITCODE
