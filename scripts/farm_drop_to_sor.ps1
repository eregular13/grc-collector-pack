# Covey pack_drop fixtures → CISO Assistant CSVs (farm leave-behind SoR).
# SAMPLE keep remains the primary KEEP path (.\scripts\sample_to_sor.ps1).
# DESKTOP (no make / no gh): .\scripts\farm_drop_to_sor.ps1
param(
    [string]$Work = "",
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$env:PYTHONPATH = $Root
$env:DRY_RUN = "1"
$env:GRC_LIVE_SCAN = "0"
$env:CISO_PUSH = "0"
$env:RISKREADY_PUSH = "0"
$env:DROPBOX_LIVE = "0"

function Resolve-RepoPath([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $Raw }
    if ([System.IO.Path]::IsPathRooted($Raw)) { return $Raw }
    return (Join-Path $Root $Raw)
}

if ([string]::IsNullOrWhiteSpace($Work)) {
    $Work = Join-Path $Root "prove\work"
} else {
    $Work = Resolve-RepoPath $Work
}

$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$Ciso = Join-Path $Work "out\ciso-assistant"
$ProvePy = Join-Path $Root "scripts\prove_ciso.py"
$Start = Get-Date

if (-not $VerifyOnly) {
    Write-Host "farm_drop_to_sor: python scripts/prove_ciso.py (pack_drop → CISO)"
    & $Python $ProvePy --work $Work
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "farm_drop_to_sor: verify prove-ciso.json honesty"
& $Python $ProvePy --verify-only --work $Work
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$Elapsed = [math]::Round(((Get-Date) - $Start).TotalSeconds, 3)
Write-Host "farm_drop_to_sor: elapsed=${Elapsed}s"
Write-Host "farm_drop_to_sor: ciso=$Ciso"
Write-Host "farm_drop_to_sor: prove=$(Join-Path $Work 'prove-ciso.json')"
Write-Host "farm_drop_to_sor: SAMPLE/DEMO ≠ client. paying_day FAIL. posted=false."
Write-Host "farm_drop_to_sor: SAMPLE keep remains the primary KEEP path (sample_to_sor)."
