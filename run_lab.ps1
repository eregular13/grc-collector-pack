#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$env:PYTHONPATH = $Root
$env:PACK_ROOT = $Root
$env:OUT_DIR = Join-Path $Root "out"
$env:DRY_RUN = "1"
$env:CISO_PUSH = "0"
$env:RISKREADY_PUSH = "0"
$env:GRC_LIVE_SCAN = "0"

Write-Host "pytest"
python -m pytest tests -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$collectors = @(
    "cloud_prowler.py",
    "inventory_nmap.py",
    "vuln_scan.py",
    "host_wazuh.py",
    "identity_ad.py",
    "easm.py",
    "k8s_kubescape.py",
    "code_secrets.py",
    "saas_idp.py",
    "grc_loader.py"
)

function Invoke-CollectorsAndLoader {
    param([string]$Label)
    foreach ($c in $collectors) {
        Write-Host "run $c ($Label)"
        python (Join-Path $Root "collectors\$c")
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}

Write-Host "collectors+loader pass 1"
Invoke-CollectorsAndLoader "pass 1"
$summaryPath = Join-Path $Root "out\summary.json"
$pass1Path = Join-Path $Root "out\evidence\summary-pass1.json"
if (-not (Test-Path $summaryPath)) {
    Write-Host "LAB_FAIL: summary.json missing after pass 1"
    exit 1
}
New-Item -ItemType Directory -Force -Path (Join-Path $Root "out\evidence") | Out-Null
Copy-Item $summaryPath $pass1Path -Force

Write-Host "collectors+loader pass 2 (idempotent regression)"
Invoke-CollectorsAndLoader "pass 2"

Write-Host "lab_outputs"
python (Join-Path $Root "tests\lab_outputs.py") --stamp
$labCode = $LASTEXITCODE

$dockerReport = Join-Path $Root "out\evidence\docker-probe.md"
try {
    $ver = docker info --format "{{.ServerVersion}}" 2>$null
    if ($LASTEXITCODE -eq 0 -and $ver) {
        @(
            "# Docker probe"
            ""
            "daemon: up"
            "server_version: $ver"
            "note: full compose extra lab is run_docker_lab.ps1 (not every local pytest tick)"
        ) | Set-Content -Path $dockerReport -Encoding utf8
        Write-Host "docker daemon up ($ver)"
    } else {
        @(
            "# Docker probe"
            ""
            "daemon: down"
        ) | Set-Content -Path $dockerReport -Encoding utf8
        Write-Host "docker daemon down; extra compose lab skipped"
    }
} catch {
    Write-Host "docker probe skipped: $_"
}

exit $labCode
