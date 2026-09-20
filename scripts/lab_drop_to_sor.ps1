# LAB dest_in -> CISO Assistant CSVs. Does NOT reseed fixtures/pack_drop.
# LAB/DEMO != SAMPLE != client. paying_day FAIL.
# DESKTOP (no make / no gh): .\scripts\lab_drop_to_sor.ps1 -Work DIR
param(
    [string]$Work = "",
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$env:PYTHONPATH = $Root
$env:PYTHONIOENCODING = "utf-8"
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
$Poam = Join-Path $Work "out\poam\poam.csv"
$PoamMd = Join-Path $Work "out\poam\poam.md"
$ProvePy = Join-Path $Root "scripts\prove_ciso.py"
$Start = Get-Date

if (-not $VerifyOnly) {
    Write-Host "lab_drop_to_sor: python scripts/prove_ciso.py --use-existing-in (LAB dest_in -> CISO)"
    & $Python $ProvePy --work $Work --use-existing-in
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "lab_drop_to_sor: verify prove-ciso.json honesty"
& $Python $ProvePy --verify-only --work $Work
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$Elapsed = [math]::Round(((Get-Date) - $Start).TotalSeconds, 3)
Write-Host "lab_drop_to_sor: elapsed=${Elapsed}s"
Write-Host "lab_drop_to_sor: ciso=$Ciso"
Write-Host "lab_drop_to_sor: poam=$Poam"
Write-Host "lab_drop_to_sor: poam_md=$PoamMd"
Write-Host "lab_drop_to_sor: prove=$(Join-Path $Work 'prove-ciso.json')"
Write-Host "lab_drop_to_sor: LAB/DEMO != SAMPLE != client. paying_day FAIL. posted=false."
Write-Host "lab_drop_to_sor: did not reseed fixtures/pack_drop."
