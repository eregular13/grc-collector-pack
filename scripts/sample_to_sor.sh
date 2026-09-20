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

# Fail closed before python -m keep so a partial / corrupt cold-path-gate
# clone cannot surface as ModuleNotFoundError: keep.__main__.
require_keep_package() {
  local rel missing=""
  for rel in keep/__main__.py keep/lab.py keep/adapters.py; do
    if [[ ! -f "$ROOT/$rel" ]]; then
      if [[ -n "$missing" ]]; then
        missing="$missing $ROOT/$rel"
      else
        missing="$ROOT/$rel"
      fi
    fi
  done
  if [[ -n "$missing" ]]; then
    echo "sample_to_sor: keep package incomplete: missing ${missing%% *}." >&2
    echo "sample_to_sor: checkout must be a full git clone of eregular13/grc-collector-pack (not a partial copy / corrupt cold-path-gate tree)." >&2
    exit 1
  fi
  case ":${PYTHONPATH:-}:" in
    *":$ROOT:"*) ;;
    *)
      echo "sample_to_sor: PYTHONPATH does not include $ROOT (keep is not importable)." >&2
      echo "sample_to_sor: checkout must be a full git clone of eregular13/grc-collector-pack (not a partial copy / corrupt cold-path-gate tree)." >&2
      exit 1
      ;;
  esac
}

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

require_keep_package

START="$("$PYTHON" -c 'import time; print(time.perf_counter())')"
CISO="$WORK/out/ciso-assistant"

if [[ "$VERIFY_ONLY" -eq 0 ]]; then
  echo "sample_to_sor: python -m keep lab (SAMPLE -> CISO)"
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

ELAPSED="$("$PYTHON" -c "import time; print(f'{time.perf_counter() - float('$START'):.3f}')")"

echo "sample_to_sor: elapsed=${ELAPSED}s"
echo "sample_to_sor: ciso=$CISO"
echo "sample_to_sor: import=$CISO/IMPORT.json"
echo "sample_to_sor: opengrc=$WORK/out/opengrc"
echo "sample_to_sor: probo=$WORK/out/import_preview/probo.json"
echo "sample_to_sor: SAMPLE != client KEEP. paying_day FAIL. posted=false."
