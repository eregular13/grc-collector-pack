#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"
export OUT_DIR="$ROOT/out"
export DRY_RUN=1
export GRC_LIVE_SCAN=0
export CISO_PUSH=0
export RISKREADY_PUSH=0
PYTHON="${PYTHON:-python3}"
"$PYTHON" -m pytest tests -q
# Carry prior lab ledgers into in/ so LEDGER_LOST does not stick across
# consecutive lab runs. LAB/DEMO is never client KEEP.
if [[ -f "$ROOT/out/poam/poam-ledger.json" ]]; then
  mkdir -p "$ROOT/in/poam"
  cp -f "$ROOT/out/poam/poam-ledger.json" "$ROOT/in/poam/poam-ledger.json"
fi
if [[ -f "$ROOT/out/assets/asset-ledger.json" ]]; then
  mkdir -p "$ROOT/in/assets"
  cp -f "$ROOT/out/assets/asset-ledger.json" "$ROOT/in/assets/asset-ledger.json"
fi
for s in cloud_prowler inventory_nmap vuln_scan host_wazuh identity_ad easm k8s_kubescape code_secrets saas_idp dns_email honeypot grc_loader; do
  "$PYTHON" "collectors/${s}.py"
done
"$PYTHON" tests/lab_outputs.py
