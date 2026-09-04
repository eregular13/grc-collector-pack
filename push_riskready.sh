#!/usr/bin/env bash
set -euo pipefail
# LICENSE-LOCK: RiskReady wrap is dead. Review-only files may exist on disk.
# This script never POSTs /api/auth/login, /itsm/assets, /evidence, /incidents, or /api/risks —
# even when RISKREADY_PUSH=1 and DRY_RUN=0.
OUT="${OUT_DIR:-./out}/riskready"
echo "RiskReady wrap disabled (LICENSE-LOCK). Human review only: ${OUT}/risks_proposed.json"
echo "Refused: login, assets, evidence, incidents, /api/risks."
exit 0
