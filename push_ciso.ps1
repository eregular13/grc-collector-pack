# Upload CISO Assistant Community CSVs when CISO_PUSH=1. Default is dry-run.
# Auto-push is assets + evidences only (northstar P0). Findings/POA&M are HITL via UI/clica.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Push = if ($env:CISO_PUSH) { $env:CISO_PUSH } else { "0" }
$Url = if ($env:CISO_URL) { $env:CISO_URL } else { "http://127.0.0.1:8000" }
$Token = $env:CISO_TOKEN
$Dir = Join-Path $Root "out\ciso-assistant"
$Hitl = @(
    "applied_controls.csv",
    "findings.csv",
    "vulnerabilities.csv",
    "risk_scenarios.csv"
)
$files = @(
    "assets.csv",
    "evidences.csv"
)

if ($Push -ne "1") {
    Write-Host "DRY_RUN: CISO_PUSH!=1, not uploading $Dir"
    Write-Host "auto-push (CISO_PUSH=1): assets.csv evidences.csv"
    Write-Host "HITL clica/UI: $($Hitl -join ' ') plus out\poam\poam.csv"
    if (Test-Path $Dir) { Get-ChildItem $Dir | ForEach-Object { $_.Name } }
    exit 0
}
if (-not $Token) { throw "CISO_TOKEN is required when CISO_PUSH=1" }

foreach ($f in $files) {
    $path = Join-Path $Dir $f
    Write-Host "upload $Url/api/importer/ $f"
    curl.exe -fsS -X POST "$Url/api/importer/" -H "Authorization: Token $Token" -F "file=@$path"
}
Write-Host "HITL remaining:" ($Hitl -join " ")
Write-Host "Import those in CISO Assistant UI or clica after review. Not auto-pushed."
