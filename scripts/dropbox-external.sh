#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"
if [[ -n "${DROPBOX_WORK_IN:-}" && -z "${IN_DIR:-}" ]]; then
  export IN_DIR="$DROPBOX_WORK_IN"
fi
exec "${PYTHON:-python3}" -m dropbox run --profile external "$@"
