#!/usr/bin/env bash
# Upload CISO Assistant Community CSVs when CISO_PUSH=1.
# Auto-push is assets + evidences only. Findings/POA&M are HITL (UI / clica).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
: "${CISO_PUSH:=0}"
: "${CISO_URL:=http://127.0.0.1:8000}"
: "${CISO_TOKEN:=}"
DIR="$ROOT/out/ciso-assistant"

if [[ "$CISO_PUSH" != "1" ]]; then
  echo "DRY_RUN: CISO_PUSH!=1, not uploading $DIR"
  echo "auto-push (CISO_PUSH=1): assets.csv evidences.csv"
  echo "HITL clica/UI: applied_controls.csv findings.csv vulnerabilities.csv risk_scenarios.csv plus out/poam/poam.csv"
  ls -1 "$DIR" 2>/dev/null || true
  exit 0
fi

if [[ -z "$CISO_TOKEN" ]]; then
  echo "CISO_TOKEN is required when CISO_PUSH=1" >&2
  exit 1
fi

for f in assets.csv evidences.csv; do
  echo "POST $CISO_URL/api/importer/ $f"
  curl -fsS -X POST "$CISO_URL/api/importer/" \
    -H "Authorization: Token $CISO_TOKEN" \
    -F "file=@$DIR/$f"
done
echo "HITL remaining: findings/vulnerabilities/risk_scenarios/applied_controls + POA&M — clica/UI after review. Not auto-pushed."
