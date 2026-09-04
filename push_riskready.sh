#!/usr/bin/env bash
set -euo pipefail
# LICENSE-LOCK: RiskReady stay-out. Review-only. Never wrap, login, or POST.
# RISKREADY_PUSH is ignored. Humans review JSON on disk.

OUT="${OUT_DIR:-./out}/riskready"
echo "LICENSE-LOCK: RiskReady stay-out. Review-only. Never wrap or POST."
echo "RISKREADY_PUSH=${RISKREADY_PUSH:-0} is ignored — no login, no HTTP."
echo "Human review files (do not POST /api/risks):"
for f in risks_proposed.json assets.json evidence.json incidents.json; do
  p="${OUT}/${f}"
  if [[ -f "$p" ]]; then
    echo "  READY ${p}"
  else
    echo "  MISSING ${p} (run collectors + loader first)"
  fi
done
exit 0
