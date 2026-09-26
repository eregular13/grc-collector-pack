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
# Do not copy ledgers into in/. A file under in/ counts as a live drop and
# skips fixtures/demo (0 findings, lab_outputs exit 1). run_ledger already
# falls back to out/poam/poam-ledger.json. LAB/DEMO is never client KEEP.
for s in cloud_prowler inventory_nmap vuln_scan host_wazuh identity_ad easm k8s_kubescape code_secrets saas_idp dns_email honeypot grc_loader; do
  "$PYTHON" "collectors/${s}.py"
done
"$PYTHON" tests/lab_outputs.py
