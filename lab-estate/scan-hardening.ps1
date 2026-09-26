# Run Lynis + OpenSCAP on isolated lab Linux containers and land raw
# reports next to the nmap dest_in leaf (in\wazuh\). File-drop only.
# From lab-estate on a Windows host with Docker Desktop:
#   cd lab-estate
#   .\scan-hardening.ps1
#   .\scan-hardening.ps1 -DestIn C:\path\to\prove\work\in
# Then ingest with:
#   ..\scripts\lab_drop_to_sor.ps1 -Work C:\path\to\prove\work
param(
    [string]$DestIn = ""
)

$ErrorActionPreference = "Stop"
$Here = $PSScriptRoot
$Root = Split-Path -Parent $Here
$Compose = Join-Path $Here "hardening\docker-compose.yml"

if ([string]::IsNullOrWhiteSpace($DestIn)) {
    $DestIn = Join-Path $Root "prove\work\in"
} elseif (-not [System.IO.Path]::IsPathRooted($DestIn)) {
    $DestIn = Join-Path $Root $DestIn
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "docker CLI absent. Copy fixtures\lab-drop\wazuh\ into dest_in instead."
}

$Wazuh = Join-Path $DestIn "wazuh"
New-Item -ItemType Directory -Force -Path $Wazuh | Out-Null
$LabBanner = "LAB/DEMO -- not a client estate.`nLynis + OpenSCAP lab hardening drop. Not SAMPLE keep. Not a client export.`n"
if (-not (Test-Path (Join-Path $DestIn "LAB.txt"))) {
    Set-Content -Path (Join-Path $DestIn "LAB.txt") -Value $LabBanner -Encoding utf8
}
Set-Content -Path (Join-Path $Wazuh "LAB.txt") -Value "LAB/DEMO -- not a client estate.`n" -Encoding utf8

Write-Host "lab-estate scan-hardening: docker compose up --build (isolated 192.168.64.0/24)"
docker compose -f $Compose up --build -d
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

docker compose -f $Compose exec -T lab-jump /opt/lab-scan/run-host.sh /drop
docker compose -f $Compose exec -T lab-ftp /opt/lab-scan/run-host.sh /drop
docker compose -f $Compose cp "lab-jump:/drop/." $Wazuh
docker compose -f $Compose cp "lab-ftp:/drop/." $Wazuh

$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$env:PYTHONPATH = $Root
& $Python -c @"
from pathlib import Path
from shared.drop_manifest import write_drop_manifest
dest = Path(r'$Wazuh')
write_drop_manifest(
    dest,
    header=(
        'LAB dest_in wazuh drop -- Lynis report.dat + OpenSCAP XCCDF.\n'
        'SHA256 of LF bytes. LAB != SAMPLE != client. Never POST /api/risks.'
    ),
    relative_to=dest,
)
print('wrote', dest / 'MANIFEST')
"@
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "lab hardening drop: $Wazuh"
Write-Host "next: ..\scripts\lab_drop_to_sor.ps1 -Work <prove-work>"
Write-Host "LAB != SAMPLE != client. paying_day FAIL. No /api/risks."
