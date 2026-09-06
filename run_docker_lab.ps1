#Requires -Version 5.1
# Extra lab: ten collector containers + loader + pytest lab. Does not stop the 30m Grok schedule.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$env:DRY_RUN = "1"
$env:CISO_PUSH = "0"
$env:RISKREADY_PUSH = "0"
$env:GRC_LIVE_SCAN = "0"

docker info --format "{{.ServerVersion}}" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker daemon is not running" }

Write-Host "compose up collectors + loader + lab"
docker compose -p grc-collector up --build --abort-on-container-exit --exit-code-from lab
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "live_scan_ignored extra container"
docker compose -p grc-collector --profile extra run --rm --no-deps live_scan_ignored
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "mock_sink extra container"
docker compose -p grc-collector --profile extra up -d --no-deps mock_sink
$ok = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    python (Join-Path $Root "tests\hit_mock_sink.py")
    if ($LASTEXITCODE -eq 0) { $ok = $true; break }
}
if (-not $ok) { throw "mock_sink did not become healthy on :18080" }

Write-Host "DOCKER_LAB_GREEN"
exit 0
