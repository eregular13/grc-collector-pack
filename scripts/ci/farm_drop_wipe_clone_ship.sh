#!/usr/bin/env bash
# CI/lab only. Not a public operator entrypoint.
# LAB/SAMPLE wipe + isolated clean checkout of pack HEAD, then farm_drop_to_sor.
# SAMPLE/DEMO != client. paying_day FAIL expected. Not client KEEP.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PACK="$(cd "$HERE/../.." && pwd)"
PYTHON="${PYTHON:-python3}"
FROM="$PACK"
CLONE=""
WORK=""

usage() {
  cat <<'EOF'
usage: scripts/ci/farm_drop_wipe_clone_ship.sh [--from DIR] [--clone DIR] [--work DIR]

CI/lab only. Wipe dest, isolated clean checkout of DIR HEAD (git archive),
run farm_drop_to_sor (DEMO/SAMPLE labeled), assert risk-register + POA&M
shape, exit non-zero on garbage.

Not a public operator entrypoint. Do not add to Makefile / README first lines.
SAMPLE keep remains ./scripts/sample_to_sor.sh. Farm operator twin remains
./scripts/farm_drop_to_sor.sh. This wrapper is the cold ship-gate only.
SAMPLE/DEMO != client. paying_day FAIL. posted=false. No /api/risks.
EOF
}

abs_path() {
  local raw="$1" base="$2"
  if [[ "$raw" = /* ]]; then
    printf '%s\n' "$raw"
  else
    printf '%s\n' "$base/$raw"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)
      FROM="$(abs_path "$2" "$PACK")"
      shift 2
      ;;
    --clone)
      CLONE="$(abs_path "$2" "$PACK")"
      shift 2
      ;;
    --work)
      WORK="$(abs_path "$2" "$PACK")"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "farm_drop_wipe_clone_ship: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$FROM/.git" ]]; then
  echo "farm_drop_wipe_clone_ship: --from must be a git checkout: $FROM" >&2
  echo "farm_drop_wipe_clone_ship: isolated clean checkout requires pack HEAD." >&2
  exit 1
fi

SHA="$("$PYTHON" -c 'import subprocess,sys; r=subprocess.run(["git","-C",sys.argv[1],"rev-parse","HEAD"],capture_output=True,text=True); sys.exit(1) if r.returncode else print(r.stdout.strip())' "$FROM")"
if [[ -z "$SHA" ]]; then
  echo "farm_drop_wipe_clone_ship: cannot resolve HEAD in $FROM" >&2
  exit 1
fi

if [[ -z "$CLONE" ]]; then
  CLONE="${TMPDIR:-/tmp}/farm-ship-clone-$SHA"
fi
if [[ -z "$WORK" ]]; then
  WORK="${TMPDIR:-/tmp}/farm-ship-work-$SHA"
fi

echo "farm_drop_wipe_clone_ship: LAB=farm_wipe_clone SAMPLE=true DEMO=true"
echo "farm_drop_wipe_clone_ship: paying_day FAIL expected. Not client KEEP."
echo "farm_drop_wipe_clone_ship: from=$FROM"
echo "farm_drop_wipe_clone_ship: head=$SHA"
echo "farm_drop_wipe_clone_ship: wipe clone=$CLONE"

rm -rf "$CLONE"
mkdir -p "$CLONE"
if ! git -C "$FROM" archive --format=tar HEAD | tar -x -C "$CLONE"; then
  echo "farm_drop_wipe_clone_ship: git archive HEAD failed (need a full pack checkout)." >&2
  exit 1
fi
printf '%s\n' "$SHA" > "$CLONE/.farm-ship-head"

REQUIRED=(
  scripts/farm_drop_to_sor.sh
  scripts/prove_ciso.py
  shared/ciso_shape.py
  shared/farm_ship.py
  collectors/grc_loader.py
  fixtures/pack_drop/nmap/meta.json
)
missing=""
for rel in "${REQUIRED[@]}"; do
  if [[ ! -e "$CLONE/$rel" ]]; then
    if [[ -n "$missing" ]]; then
      missing="$missing $CLONE/$rel"
    else
      missing="$CLONE/$rel"
    fi
  fi
done
if [[ -n "$missing" ]]; then
  echo "farm_drop_wipe_clone_ship: isolated checkout incomplete: missing ${missing%% *}." >&2
  echo "farm_drop_wipe_clone_ship: need a full git checkout of eregular13/grc-collector-pack HEAD." >&2
  echo "farm_drop_wipe_clone_ship: partial copy / corrupt wipe-clone tree is fail-closed." >&2
  exit 1
fi

rm -rf "$CLONE/prove/work" "$CLONE/keep/work" "$CLONE/out"
rm -rf "$WORK"
mkdir -p "$WORK"

export PYTHONPATH="$CLONE"
export PYTHONIOENCODING=utf-8
export DRY_RUN=1
export GRC_LIVE_SCAN=0
export CISO_PUSH=0
export RISKREADY_PUSH=0
export DROPBOX_LIVE=0

echo "farm_drop_wipe_clone_ship: farm_drop_to_sor (DEMO/SAMPLE labeled)"
bash "$CLONE/scripts/farm_drop_to_sor.sh" --work "$WORK"

echo "farm_drop_wipe_clone_ship: assert_risk_register_and_poam"
"$PYTHON" - "$WORK" <<'PY'
import sys
from pathlib import Path

from shared.farm_ship import FARM_SHIP_OK_LINE, FarmShipError, assert_farm_ship_sor

work = Path(sys.argv[1])
try:
    shape = assert_farm_ship_sor(work)
except FarmShipError as exc:
    print(exc, file=sys.stderr)
    raise SystemExit(1)
print(
    f"farm_wipe_clone register ok; findings={shape['findings']} "
    f"risk_scenarios={shape['risk_scenarios']} poam_rows={shape['poam_rows']} "
    f"vulns={shape['vulnerabilities']}"
)
print(FARM_SHIP_OK_LINE)
PY

echo "farm_drop_wipe_clone_ship: clone=$CLONE"
echo "farm_drop_wipe_clone_ship: work=$WORK"
echo "farm_drop_wipe_clone_ship: ciso=$WORK/out/ciso-assistant"
echo "farm_drop_wipe_clone_ship: poam=$WORK/out/poam/poam.csv"
echo "farm_drop_wipe_clone_ship: SAMPLE/DEMO != client. paying_day FAIL. posted=false."
echo "farm_drop_wipe_clone_ship: PASS is wipe/clone farm_drop SoR shape. Not client KEEP."
