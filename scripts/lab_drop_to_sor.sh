#!/usr/bin/env bash
# LAB dest_in -> CISO Assistant CSVs. Does NOT reseed fixtures/pack_drop.
# LAB/DEMO != SAMPLE != client. paying_day FAIL.
# Point --work at a dir whose in/ already holds compose-lab or operator pack_drop.
# From a populated work dir: ./scripts/lab_drop_to_sor.sh --work DIR
#
# Carry path (ONE): #222 native prove_ciso --prior-out (no duplicate ledger copy-into-in).
# PQ-6: elapsed via argv (no nested f-string quotes).
# Optional post-prove fixstack_apply remains until collectors fully own PQ-1/PQ-2
# (SAMPLE/farm paths get collector-level fixes; lab may still call the hook).
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
PRIOR_OUT=""
SKIP_FIXSTACK=0

usage() {
  cat <<'EOF'
usage: scripts/lab_drop_to_sor.sh [--work DIR] [--verify-only] [--prior-out DIR] [--skip-fixstack]

LAB dest_in -> prove/work/out/ciso-assistant/ (no fixture reseed).
Requires DIR/in already populated (DESKTOP compose lab pack_drop or operator copy).
Calls python3 scripts/prove_ciso.py --use-existing-in (alias --no-seed).
Never rmtree/reseed dest_in. Never writes pack in/.
LAB.txt + DEMO seed trees fail-closed (LAB_SHAPE_FAIL).
LAB/DEMO != SAMPLE != client. This pack does not POST /api/risks.
SAMPLE keep remains the primary KEEP path (sample_to_sor).
farm_drop_to_sor remains the fixture seed path.
--prior-out DIR: single carry path via prove_ciso.py --prior-out (native #222).
--skip-fixstack: leave raw prove POA&M (no post-prove fixstack_apply hook).
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
    --prior-out|--prior-ledger)
      PRIOR_OUT="$(abs_path "$2")"
      shift 2
      ;;
    --skip-fixstack)
      SKIP_FIXSTACK=1
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
  if [[ -n "$PRIOR_OUT" ]]; then
    echo "lab_drop_to_sor: prior-out carry via native prove_ciso --prior-out $PRIOR_OUT"
    "$PYTHON" "$ROOT/scripts/prove_ciso.py" --work "$WORK" --use-existing-in --prior-out "$PRIOR_OUT"
  else
    "$PYTHON" "$ROOT/scripts/prove_ciso.py" --work "$WORK" --use-existing-in
  fi

  if [[ "$SKIP_FIXSTACK" -eq 0 && -f "$ROOT/scripts/fixstack_apply.py" ]]; then
    echo "lab_drop_to_sor: fixstack_apply (PQ-2 testssl -> PQ-1 rollup + runtime migration map)"
    FIXSTACK_PRIOR_OUT="$PRIOR_OUT" "$PYTHON" "$ROOT/scripts/fixstack_apply.py" "$WORK"
  fi
fi

echo "lab_drop_to_sor: verify prove-ciso.json honesty"
"$PYTHON" "$ROOT/scripts/prove_ciso.py" --verify-only --work "$WORK"

# PQ-6 fix: pass START via argv - no nested quotes inside f-string
ELAPSED="$("$PYTHON" -c 'import time,sys; print("%.3f" % (time.perf_counter() - float(sys.argv[1])))' "$START")"

echo "lab_drop_to_sor: elapsed=${ELAPSED}s"
echo "lab_drop_to_sor: ciso=$CISO"
echo "lab_drop_to_sor: poam=$POAM"
echo "lab_drop_to_sor: poam_md=$POAM_MD"
echo "lab_drop_to_sor: prove=$WORK/prove-ciso.json"
echo "lab_drop_to_sor: LAB/DEMO != SAMPLE != client. paying_day FAIL. posted=false."
echo "lab_drop_to_sor: did not reseed fixtures/pack_drop."
