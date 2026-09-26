# LAB-only. Authorized-lab-only. Do not run against a client estate.
#
# HardeningKitty (MIT, scipag/HardeningKitty) Audit against the LOCAL
# Windows lab host. Uses Microsoft Security Baseline finding lists
# (finding_list_msft_security_baseline_*), NEVER finding_list_cis_*.
# Nothing on this feed is labeled CIS Benchmark or CIS-CAT.
#
# Does NOT start Docker, compose, or any other service.
# Does NOT ship HardeningKitty in the pack image — fetches or reuses
# it at run time on this lab host only.
# File-drop only: writes CSV + MANIFEST into dest_in\identity\.
# Never POST /api/risks. LAB != SAMPLE != client. paying_day FAIL.
#
# From lab-estate on the authorized Windows lab host:
#   .\scan-windows-hardening.ps1 -AuthorizedLab
#   .\scan-windows-hardening.ps1 -AuthorizedLab -DestIn C:\path\to\prove\work\in
# Then ingest with:
#   ..\scripts\lab_drop_to_sor.ps1 -Work C:\path\to\prove\work

param(
    [switch]$AuthorizedLab,
    [string]$DestIn = "",
    [string]$FindingList = "",
    [string]$HardeningKittyRoot = ""
)

$ErrorActionPreference = "Stop"

Write-Host "LAB-only authorized-lab-only HardeningKitty Audit."
Write-Host "LOCAL Windows lab host only. MS Security Baseline lists only."
Write-Host "Does not start Docker. Does not POST /api/risks."

if (-not $AuthorizedLab -and $env:LAB_HARDENING_AUTHORIZED -ne "1") {
    Write-Error "Refusing: pass -AuthorizedLab (or LAB_HARDENING_AUTHORIZED=1). Authorized lab host only."
}

if (-not $IsWindows -and $env:OS -notlike "*Windows*") {
    Write-Error "Refusing: this runner is for a local Windows lab host only."
}

$Here = $PSScriptRoot
$Root = Split-Path -Parent $Here

if ([string]::IsNullOrWhiteSpace($DestIn)) {
    $DestIn = Join-Path $Root "prove\work\in"
} elseif (-not [System.IO.Path]::IsPathRooted($DestIn)) {
    $DestIn = Join-Path $Root $DestIn
}

$Identity = Join-Path $DestIn "identity"
New-Item -ItemType Directory -Force -Path $Identity | Out-Null

$LabBanner = @(
    "LAB/DEMO -- not a client estate."
    "HardeningKitty MS Security Baseline dest_in (in/identity/)."
    "Not a CIS benchmark / CIS-CAT deliverable. Never finding_list_cis_*."
    "Not SAMPLE keep. Not a client export. File-drop ingest only."
    "LAB != SAMPLE != client. paying_day FAIL."
) -join "`n"

if (-not (Test-Path (Join-Path $DestIn "LAB.txt"))) {
    Set-Content -Path (Join-Path $DestIn "LAB.txt") -Value $LabBanner -Encoding utf8
}
Set-Content -Path (Join-Path $Identity "LAB.txt") -Value $LabBanner -Encoding utf8

function Resolve-MsBaselineList {
    param([string]$HkRoot, [string]$Requested)
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        $name = [System.IO.Path]::GetFileName($Requested)
        if ($name -like "finding_list_cis_*") {
            Write-Error "Refusing CIS-benchmark finding list: $name. Use finding_list_msft_security_baseline_*."
        }
        if ($name -notlike "finding_list_msft_security_baseline_*") {
            Write-Error "Refusing non-MS baseline list: $name. Use finding_list_msft_security_baseline_*."
        }
        if (Test-Path $Requested) { return (Resolve-Path $Requested).Path }
        $under = Join-Path $HkRoot (Join-Path "lists" $name)
        if (Test-Path $under) { return (Resolve-Path $under).Path }
        Write-Error "Finding list not found: $Requested"
    }
    $lists = Join-Path $HkRoot "lists"
    $preferred = @(
        "finding_list_msft_security_baseline_windows_11_24h2_machine.csv",
        "finding_list_msft_security_baseline_windows_11_23h2_machine.csv",
        "finding_list_msft_security_baseline_windows_10_22h2_machine.csv",
        "finding_list_msft_security_baseline_windows_server_2022_21h2_member_machine.csv"
    )
    foreach ($name in $preferred) {
        $path = Join-Path $lists $name
        if (Test-Path $path) { return (Resolve-Path $path).Path }
    }
    $any = Get-ChildItem -Path $lists -Filter "finding_list_msft_security_baseline_*_machine.csv" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike "finding_list_cis_*" } |
        Select-Object -First 1
    if ($any) { return $any.FullName }
    Write-Error "No finding_list_msft_security_baseline_* list under $lists"
}

function Install-HardeningKittyLab {
    param([string]$Hint)
    if (-not [string]::IsNullOrWhiteSpace($Hint) -and (Test-Path (Join-Path $Hint "HardeningKitty.psm1"))) {
        return (Resolve-Path $Hint).Path
    }
    foreach ($candidate in @(
        $Hint,
        (Join-Path $env:TEMP "HardeningKitty-lab"),
        (Join-Path $Here "HardeningKitty-lab")
    )) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $mod = Join-Path $candidate "HardeningKitty.psm1"
        if (Test-Path $mod) { return (Resolve-Path $candidate).Path }
        $nested = Get-ChildItem -Path $candidate -Filter "HardeningKitty.psm1" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($nested) { return $nested.Directory.FullName }
    }
    $dest = Join-Path $env:TEMP "HardeningKitty-lab"
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $zip = Join-Path $dest "HardeningKitty-master.zip"
    Write-Host "Fetching scipag/HardeningKitty (MIT) to $dest — lab host only, not the pack image."
    Invoke-WebRequest -Uri "https://github.com/scipag/HardeningKitty/archive/refs/heads/master.zip" -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $dest -Force
    $mod = Get-ChildItem -Path $dest -Filter "HardeningKitty.psm1" -Recurse | Select-Object -First 1
    if (-not $mod) { Write-Error "HardeningKitty.psm1 missing after fetch." }
    return $mod.Directory.FullName
}

$HkRoot = Install-HardeningKittyLab -Hint $HardeningKittyRoot
$List = Resolve-MsBaselineList -HkRoot $HkRoot -Requested $FindingList
if ([System.IO.Path]::GetFileName($List) -like "finding_list_cis_*") {
    Write-Error "Refusing CIS-benchmark finding list."
}

Import-Module (Join-Path $HkRoot "HardeningKitty.psm1") -Force
$Report = Join-Path $Identity ("hardeningkitty-lab-" + $env:COMPUTERNAME + ".csv")
Write-Host "Invoke-HardeningKitty -Mode Audit -FileFindingList $List"
Invoke-HardeningKitty -Mode Audit -FileFindingList $List -Report -ReportFile $Report -SkipMachineInformation

# Stamp ComputerName so dest_in ingest can attach the host. Official HK
# report columns stay intact; this is an extra column the pack parser reads.
if (Test-Path $Report) {
    $rows = Import-Csv -Path $Report
    $hostName = $env:COMPUTERNAME
    foreach ($row in $rows) {
        Add-Member -InputObject $row -NotePropertyName ComputerName -NotePropertyValue $hostName -Force
    }
    $rows | Export-Csv -Path $Report -NoTypeInformation -Encoding utf8
}

$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$env:PYTHONPATH = $Root
& $Python -c @"
from pathlib import Path
from shared.drop_manifest import write_drop_manifest
dest = Path(r'$Identity')
write_drop_manifest(
    dest,
    header=(
        'LAB dest_in identity drop -- HardeningKitty MS Security Baseline CSV.\n'
        'SHA256 of LF bytes. LAB != SAMPLE != client. Never POST /api/risks.\n'
        'Not a CIS benchmark / CIS-CAT deliverable. Never finding_list_cis_*.'
    ),
    relative_to=dest,
)
print('wrote', dest / 'MANIFEST')
"@
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "lab HardeningKitty drop: $Identity"
Write-Host "next: ..\scripts\lab_drop_to_sor.ps1 -Work <prove-work>"
Write-Host "LAB != SAMPLE != client. paying_day FAIL. No /api/risks. No Docker."
