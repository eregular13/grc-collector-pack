# LICENSE-LOCK: RiskReady wrap is stay-out forever.
# Review-only JSON may exist under out\riskready. This script never POSTs
# to that product (wrap stay-out), even when RISKREADY_PUSH=1 and DRY_RUN=0.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Push = if ($env:RISKREADY_PUSH) { $env:RISKREADY_PUSH } else { "0" }
$Dir = Join-Path $Root "out\riskready"

Write-Host "WRAP_DEAD: RiskReady stay-out. No HTTP. Review-only listing of $Dir"
if (Test-Path $Dir) { Get-ChildItem $Dir | ForEach-Object { $_.Name } }
if ($Push -eq "1") {
    Write-Host "WRAP_DEAD: RISKREADY_PUSH=1 ignored (fail-closed, no POST)."
    exit 2
}
exit 0
