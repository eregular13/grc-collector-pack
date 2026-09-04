#!/usr/bin/env bash
set -euo pipefail
# CISO Assistant is Reid-side SoR. Prefer clica / UI CSV import.
# Optional REST: assets + evidences only. Never invent FindingsAssessment UUIDs.
# Never POST /api/risks.
OUT="${OUT_DIR:-./out}/ciso-assistant"
echo "Preferred path: clica or CISO Assistant UI import of ${OUT}/*.csv"
echo "Do not invent FindingsAssessment UUIDs."
if [[ "${CISO_PUSH:-0}" != "1" ]]; then
  echo "CISO_PUSH=${CISO_PUSH:-0}; dry run, not pushing"
  exit 0
fi
API="${CISO_API:-http://localhost:8000/api}"
TOKEN="${CISO_TOKEN:-}"
if [[ -z "$TOKEN" ]]; then
  echo "CISO_TOKEN missing" >&2
  exit 1
fi
echo "Would POST ${API}/assets/ from ${OUT}/assets.csv"
echo "Would POST ${API}/evidences/ from ${OUT}/evidences.csv"
echo "Skipped /api/risks (forbidden)"
if [[ "${DRY_RUN:-1}" == "1" ]]; then
  echo "DRY_RUN=1; use clica/UI instead of REST"
  exit 0
fi
# Optional live POST of assets/evidences only — never risks, never FindingsAssessment.
if command -v curl >/dev/null 2>&1; then
  curl -sS -X POST "${API}/assets/" \
    -H "Authorization: Token ${TOKEN}" \
    -H "Content-Type: text/csv" \
    --data-binary @"${OUT}/assets.csv" >/dev/null
  curl -sS -X POST "${API}/evidences/" \
    -H "Authorization: Token ${TOKEN}" \
    -H "Content-Type: text/csv" \
    --data-binary @"${OUT}/evidences.csv" >/dev/null
fi
