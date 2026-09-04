$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$env:PYTHONPATH = $Root
$env:OUT_DIR = Join-Path $Root "out"
$env:DRY_RUN = "1"
$env:GRC_LIVE_SCAN = "0"
$env:CISO_PUSH = "0"
$env:RISKREADY_PUSH = "0"
python -m pytest tests -q
@(
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
) | ForEach-Object { python (Join-Path $Root "collectors\$_") }
python (Join-Path $Root "scripts\preview_probo.py")
python (Join-Path $Root "scripts\preview_rr.py")
python (Join-Path $Root "tests\lab_outputs.py")
