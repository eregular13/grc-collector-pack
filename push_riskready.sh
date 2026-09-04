#!/usr/bin/env bash
set -euo pipefail
# Push RiskReady assets, evidence, incidents. Never POST /api/risks.
if [[ "${RISKREADY_PUSH:-0}" != "1" ]]; then
  echo "RISKREADY_PUSH=${RISKREADY_PUSH:-0}; dry run, not pushing"
  exit 0
fi
API="${RISKREADY_API:-http://localhost:9380/api}"
OUT="${OUT_DIR:-./out}/riskready"
echo "Would POST ${API}/auth/login then ${API}/itsm/assets, ${API}/evidence, ${API}/incidents"
echo "Skipped /api/risks — see ${OUT}/risks_proposed.json"
if [[ "${DRY_RUN:-1}" == "1" ]]; then
  exit 0
fi
# Login then POST assets/evidence/incidents only.
if command -v curl >/dev/null 2>&1; then
  TOKEN=$(curl -sS -X POST "${API}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${RISKREADY_EMAIL:-}\",\"password\":\"${RISKREADY_PASSWORD:-}\"}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  curl -sS -X POST "${API}/itsm/assets" -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" --data-binary @"${OUT}/assets.json" >/dev/null
  curl -sS -X POST "${API}/evidence" -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" --data-binary @"${OUT}/evidence.json" >/dev/null
  curl -sS -X POST "${API}/incidents" -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" --data-binary @"${OUT}/incidents.json" >/dev/null
fi
