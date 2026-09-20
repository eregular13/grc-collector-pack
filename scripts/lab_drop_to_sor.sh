#!/usr/bin/env bash
# LAB dest_in -> CISO Assistant CSVs. Does NOT reseed fixtures/pack_drop.
# LAB/DEMO != SAMPLE != client. paying_day FAIL.
# Point --work at a dir whose in/ already holds compose-lab or operator pack_drop.
# From a populated work dir: ./scripts/lab_drop_to_sor.sh --work DIR
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
usage: scripts/lab_drop_to_sor.sh [--work DIR] [--verify-only]

LAB dest_in -> prove/work/out/ciso-assistant/ (no fixture reseed).
Requires DIR/in already populated (DESKTOP compose lab pack_drop or operator copy).
Calls python3 scripts/prove_ciso.py --use-existing-in (alias --no-seed).
Never rmtree/reseed dest_in. Never writes pack in/.
LAB/DEMO != SAMPLE != client. This pack does not POST /api/risks.
SAMPLE keep remains the primary KEEP path (sample_to_sor).
farm_drop_to_sor remains the fixture seed path.
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
      echo "lab_drop_to_sor: unknown argument: $1" >&2
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
  echo "lab_drop_to_sor: python3 scripts/prove_ciso.py --use-existing-in (LAB dest_in -> CISO)"
  "$PYTHON" "$ROOT/scripts/prove_ciso.py" --work "$WORK" --use-existing-in
fi

echo "lab_drop_to_sor: verify prove-ciso.json honesty"
"$PYTHON" "$ROOT/scripts/prove_ciso.py" --verify-only --work "$WORK"

ELAPSED="$("$PYTHON" -c "import time; print(f'{time.perf_counter() - float('$START'):.3f}')")"

echo "lab_drop_to_sor: elapsed=${ELAPSED}s"
echo "lab_drop_to_sor: ciso=$CISO"
echo "lab_drop_to_sor: poam=$POAM"
echo "lab_drop_to_sor: poam_md=$POAM_MD"
echo "lab_drop_to_sor: prove=$WORK/prove-ciso.json"
echo "lab_drop_to_sor: LAB/DEMO != SAMPLE != client. paying_day FAIL. posted=false."
echo "lab_drop_to_sor: did not reseed fixtures/pack_drop."
