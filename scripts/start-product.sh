#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"
export OUT_DIR="${OUT_DIR:-$ROOT/out}"
export DRY_RUN=1
export GRC_LIVE_SCAN=0
export CISO_PUSH=0
export RISKREADY_PUSH=0
export GRC_PRODUCT_HOST=127.0.0.1
export GRC_PRODUCT_PORT="${GRC_PRODUCT_PORT:-18765}"
PYTHON="${PYTHON:-python3}"
if [[ ! -f "$OUT_DIR/summary.json" ]]; then
  bash "$ROOT/scripts/lab.sh"
fi
echo "Opening http://127.0.0.1:${GRC_PRODUCT_PORT}/"
exec "$PYTHON" -m product
