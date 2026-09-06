#Requires -Version 5.1
# Parallel Docker facet lab. Does not stop the 30m Grok schedule.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$Compose = @("-p", "grc-facet", "-f", "docker-compose.facets.yml")

docker info --format "{{.ServerVersion}}" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker daemon is not running" }

New-Item -ItemType Directory -Force -Path (Join-Path $Root "out-facet") | Out-Null

Write-Host "=== iso collectors + loader + lab_outputs ==="
$iso = @(
    "iso_cloud","iso_nmap","iso_vuln","iso_wazuh","iso_identity",
    "iso_easm","iso_k8s","iso_code","iso_saas","iso_loader","iso_lab"
)
docker compose @Compose up --build --exit-code-from iso_lab @iso
if ($LASTEXITCODE -ne 0) { throw "iso_lab failed" }

Write-Host "=== safety pytest ==="
docker compose @Compose up --build --exit-code-from safety safety
if ($LASTEXITCODE -ne 0) { throw "safety failed" }

Write-Host "=== live-scan-ignored collectors ==="
$live = @(
    "live_cloud","live_nmap","live_vuln","live_wazuh","live_identity",
    "live_easm","live_k8s","live_code","live_saas"
)
docker compose @Compose up --build --exit-code-from live_nmap @live
if ($LASTEXITCODE -ne 0) { throw "live collectors failed" }

Write-Host "=== facet sink + matrix + push_probe ==="
docker compose @Compose up --build -d facet_sink
docker compose @Compose up --build --exit-code-from push_probe push_probe facet_sink
if ($LASTEXITCODE -ne 0) { throw "push_probe failed" }
docker compose @Compose up --build --exit-code-from matrix matrix facet_sink
if ($LASTEXITCODE -ne 0) { throw "matrix failed" }

Write-Host "FACET_DOCKER_GREEN"
exit 0
