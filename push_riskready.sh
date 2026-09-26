#!/usr/bin/env bash
set -euo pipefail
# LICENSE-LOCK: RiskReady stay-out. Review-only. Never wrap, login, or POST.
# RISKREADY_PUSH is ignored. Humans review JSON on disk.

OUT="${OUT_DIR:-./out}/riskready"
echo "LICENSE-LOCK: RiskReady stay-out. Review-only. Never wrap or POST."
echo "RISKREADY_PUSH=${RISKREADY_PUSH:-0} is ignored — no login, no HTTP."
echo "This pack no longer writes out/riskready/. Count identity is CISO register + POA&M."
echo "Never auto-POST risks. Stay-out forever."
if [[ -d "$OUT" ]]; then
  echo "  leftover directory ${OUT} is not a pack output (ignore / delete)"
fi
exit 0
