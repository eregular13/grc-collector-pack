# SAMPLE fixtures → CISO Assistant CSVs (primary SoR). SAMPLE ≠ client KEEP.
# DESKTOP (no make / no gh): .\scripts\sample_to_sor.ps1
param(
    [string]$Work = "",
    [string]$PackIn = "",
    [switch]$Exporters,
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
    $Work = Join-Path $Root "keep\work"
} else {
    $Work = Resolve-RepoPath $Work
}
if (-not [string]::IsNullOrWhiteSpace($PackIn)) {
    $PackIn = Resolve-RepoPath $PackIn
}

$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$Ciso = Join-Path $Work "out\ciso-assistant"
$Start = Get-Date

if (-not $VerifyOnly) {
    Write-Host "sample_to_sor: python -m keep lab (SAMPLE → CISO)"
    $lab = @("-m", "keep", "lab", "--work", $Work)
    if (-not [string]::IsNullOrWhiteSpace($PackIn)) {
        $lab += @("--pack-in", $PackIn)
    }
    & $Python @lab
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "sample_to_sor: verify IMPORT.json honesty"
& $Python -m keep verify --ciso $Ciso
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Exporters) {
    Write-Host "sample_to_sor: python -m exporters --sink all"
    & $Python -m exporters --sink all --out-dir (Join-Path $Work "out")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$Elapsed = [math]::Round(((Get-Date) - $Start).TotalSeconds, 3)
Write-Host "sample_to_sor: elapsed=${Elapsed}s"
Write-Host "sample_to_sor: ciso=$Ciso"
Write-Host "sample_to_sor: import=$(Join-Path $Ciso 'IMPORT.json')"
Write-Host "sample_to_sor: opengrc=$(Join-Path $Work 'out\opengrc')"
Write-Host "sample_to_sor: probo=$(Join-Path $Work 'out\import_preview\probo.json')"
Write-Host "sample_to_sor: SAMPLE ≠ client KEEP. paying_day FAIL. posted=false."
