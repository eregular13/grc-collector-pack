#!/usr/bin/env bash
# Covey pack_drop fixtures → CISO Assistant CSVs (farm leave-behind SoR).
# SAMPLE keep remains the primary KEEP path (./scripts/sample_to_sor.sh).
# From a clean checkout: ./scripts/farm_drop_to_sor.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PYTHONPATH="$ROOT"
export PYTHONIOENCODING=utf-8
export DRY_RUN=1
export GRC_LIVE_SCAN=0
export CISO_PUSH=0
export RISKREADY_PUSH=0
export DROPBOX_LIVE=0

PYTHON="${PYTHON:-python3}"
WORK="$ROOT/prove/work"
VERIFY_ONLY=0

usage() {
  cat <<'EOF'
usage: scripts/farm_drop_to_sor.sh [--work DIR] [--verify-only]

Farm leave-behind twin of sample_to_sor: fixtures/pack_drop -> prove/work/out/ciso-assistant/
Forces PYTHONPATH + DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0
Runs python3 scripts/prove_ciso.py (isolated under prove/work/; never writes pack in/).
Then fail-closes if prove JSON / CISO outputs claim client estate or paying_day PASS.
SAMPLE keep remains the primary KEEP path. SAMPLE/DEMO != client. This pack does not POST /api/risks.
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
    --verify-only)
      VERIFY_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "farm_drop_to_sor: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

START="$("$PYTHON" -c 'import time; print(time.perf_counter())')"
CISO="$WORK/out/ciso-assistant"
POAM="$WORK/out/poam/poam.csv"
POAM_MD="$WORK/out/poam/poam.md"

if [[ "$VERIFY_ONLY" -eq 0 ]]; then
  echo "farm_drop_to_sor: python3 scripts/prove_ciso.py (pack_drop -> CISO)"
  "$PYTHON" "$ROOT/scripts/prove_ciso.py" --work "$WORK"
fi

echo "farm_drop_to_sor: verify prove-ciso.json honesty"
"$PYTHON" "$ROOT/scripts/prove_ciso.py" --verify-only --work "$WORK"

ELAPSED="$("$PYTHON" -c "import time; print(f'{time.perf_counter() - float('$START'):.3f}')")"

echo "farm_drop_to_sor: elapsed=${ELAPSED}s"
echo "farm_drop_to_sor: ciso=$CISO"
echo "farm_drop_to_sor: poam=$POAM"
echo "farm_drop_to_sor: poam_md=$POAM_MD"
echo "farm_drop_to_sor: prove=$WORK/prove-ciso.json"
echo "farm_drop_to_sor: SAMPLE/DEMO != client. paying_day FAIL. posted=false."
echo "farm_drop_to_sor: SAMPLE keep remains the primary KEEP path (sample_to_sor)."
