#!/usr/bin/env bash
set -euo pipefail
# Push CISO Assistant assets + evidences only. Never POST /api/risks.
if [[ "${CISO_PUSH:-0}" != "1" ]]; then
  echo "CISO_PUSH=${CISO_PUSH:-0}; dry run, not pushing"
  exit 0
fi
API="${CISO_API:-http://localhost:8000/api}"
TOKEN="${CISO_TOKEN:-}"
OUT="${OUT_DIR:-./out}/ciso-assistant"
if [[ -z "$TOKEN" ]]; then
  echo "CISO_TOKEN missing" >&2
  exit 1
fi
# Import path: upload CSVs via documented clica / UI. REST limited to assets and evidences.
echo "Would POST ${API}/assets/ from ${OUT}/assets.csv"
echo "Would POST ${API}/evidences/ from ${OUT}/evidences.csv"
echo "Skipped /api/risks (forbidden)"
if [[ "${DRY_RUN:-1}" == "1" ]]; then
  exit 0
fi
# Optional live POST of assets/evidences only — never risks.
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
