$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$env:PYTHONPATH = $Root
$env:OUT_DIR = Join-Path $Root "out"
$env:DRY_RUN = "1"
$env:GRC_LIVE_SCAN = "0"
$env:CISO_PUSH = "0"
$env:RISKREADY_PUSH = "0"
$env:GRC_PRODUCT_HOST = "127.0.0.1"
$env:GRC_PRODUCT_PORT = "18765"
if (-not (Test-Path (Join-Path $Root "out\summary.json"))) {
    & (Join-Path $PSScriptRoot "lab.ps1")
}
Write-Host "Opening http://127.0.0.1:18765/"
Start-Process "http://127.0.0.1:18765/"
python -m product
