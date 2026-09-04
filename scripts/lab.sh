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
for s in cloud_prowler inventory_nmap vuln_scan host_wazuh identity_ad easm k8s_kubescape code_secrets saas_idp grc_loader; do
  "$PYTHON" "collectors/${s}.py"
done
"$PYTHON" tests/lab_outputs.py
