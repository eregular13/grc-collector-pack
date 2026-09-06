#!/usr/bin/env bash
# LICENSE-LOCK: RiskReady wrap is stay-out forever.
# Review-only JSON may exist under out/riskready. This script never POSTs
# to that product (wrap stay-out), even when RISKREADY_PUSH=1 and DRY_RUN=0.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
: "${RISKREADY_PUSH:=0}"
DIR="$ROOT/out/riskready"

echo "WRAP_DEAD: RiskReady stay-out. No HTTP. Review-only listing of $DIR"
ls -1 "$DIR" 2>/dev/null || true
if [[ "$RISKREADY_PUSH" == "1" ]]; then
  echo "WRAP_DEAD: RISKREADY_PUSH=1 ignored (fail-closed, no POST)."
  exit 2
fi
exit 0
