#!/usr/bin/env bash
# SAMPLE fixtures → CISO Assistant CSVs (primary SoR). SAMPLE ≠ client KEEP.
# From a clean checkout: ./scripts/sample_to_sor.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PYTHONPATH="$ROOT"
export DRY_RUN=1
export GRC_LIVE_SCAN=0
export CISO_PUSH=0
export RISKREADY_PUSH=0
export DROPBOX_LIVE=0

PYTHON="${PYTHON:-python3}"
PACK_IN=""
WORK="$ROOT/keep/work"
EXPORTERS=0
VERIFY_ONLY=0

usage() {
  cat <<'EOF'
usage: scripts/sample_to_sor.sh [--work DIR] [--pack-in DIR] [--exporters] [--verify-only]

One command: SAMPLE keep-samples → keep/work/out/ciso-assistant/*.csv
Forces PYTHONPATH + DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0
Then verifies IMPORT.json honesty (sample/demo true, paying_day FAIL, client_keep false).
Optional --exporters re-writes OpenGRC + Probo from those CSVs (keep lab already writes them).
SAMPLE ≠ client KEEP. This pack does not POST /api/risks.
EOF
}

abs_path() {
  local raw="$1"
  if [[ "$raw" = /* ]]; then
    printf '%s\n' "$raw"
  else
    printf '%s\n' "$ROOT/$raw"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --work)
      WORK="$(abs_path "$2")"
      shift 2
      ;;
    --pack-in)
      PACK_IN="$(abs_path "$2")"
      shift 2
      ;;
    --exporters)
      EXPORTERS=1
      shift
      ;;
    --verify-only)
      VERIFY_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "sample_to_sor: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

START="$(date +%s)"
CISO="$WORK/out/ciso-assistant"

if [[ "$VERIFY_ONLY" -eq 0 ]]; then
  echo "sample_to_sor: python -m keep lab (SAMPLE → CISO)"
  lab_args=(--work "$WORK")
  if [[ -n "$PACK_IN" ]]; then
    lab_args+=(--pack-in "$PACK_IN")
  fi
  "$PYTHON" -m keep lab "${lab_args[@]}"
fi

echo "sample_to_sor: verify IMPORT.json honesty"
"$PYTHON" -m keep verify --ciso "$CISO"

if [[ "$EXPORTERS" -eq 1 ]]; then
  echo "sample_to_sor: python -m exporters --sink all"
  "$PYTHON" -m exporters --sink all --out-dir "$WORK/out"
fi

END="$(date +%s)"
ELAPSED="$((END - START))"

echo "sample_to_sor: elapsed=${ELAPSED}s"
echo "sample_to_sor: ciso=$CISO"
echo "sample_to_sor: import=$CISO/IMPORT.json"
echo "sample_to_sor: opengrc=$WORK/out/opengrc"
echo "sample_to_sor: probo=$WORK/out/import_preview/probo.json"
echo "sample_to_sor: SAMPLE ≠ client KEEP. paying_day FAIL. posted=false."
