#!/usr/bin/env bash
# Run Lynis + OpenSCAP on isolated lab Linux containers and land raw
# reports next to the nmap dest_in leaf (in/wazuh/). File-drop only.
# From lab-estate/: ./scan-hardening.sh [--dest-in DIR]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
COMPOSE="$HERE/hardening/docker-compose.yml"
DEST_IN="${DEST_IN:-$ROOT/prove/work/in}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest-in) DEST_IN="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker CLI absent. Land fixtures/lab-drop/wazuh/ into dest_in instead." >&2
  exit 1
fi

WAZUH="$DEST_IN/wazuh"
mkdir -p "$WAZUH"
if [[ ! -f "$DEST_IN/LAB.txt" ]]; then
  printf '%s\n' "LAB/DEMO -- not a client estate." \
    "Lynis + OpenSCAP lab hardening drop. Not SAMPLE keep. Not a client export." \
    > "$DEST_IN/LAB.txt"
fi
printf '%s\n' "LAB/DEMO -- not a client estate." > "$WAZUH/LAB.txt"

docker compose -f "$COMPOSE" up --build -d
docker compose -f "$COMPOSE" exec -T lab-jump /opt/lab-scan/run-host.sh /drop
docker compose -f "$COMPOSE" exec -T lab-ftp /opt/lab-scan/run-host.sh /drop
docker compose -f "$COMPOSE" cp lab-jump:/drop/. "$WAZUH/"
docker compose -f "$COMPOSE" cp lab-ftp:/drop/. "$WAZUH/"

PYTHONPATH="$ROOT" python3 - <<PY
from pathlib import Path
from shared.drop_manifest import write_drop_manifest
dest = Path(r"$WAZUH")
write_drop_manifest(
    dest,
    header=(
        "LAB dest_in wazuh drop — Lynis report.dat + OpenSCAP XCCDF.\\n"
        "SHA256 of LF bytes. LAB != SAMPLE != client. Never POST /api/risks."
    ),
    relative_to=dest,
)
print("wrote", dest / "MANIFEST")
PY

echo "lab hardening drop: $WAZUH"
echo "next: .\\scripts\\lab_drop_to_sor.ps1 -Work <prove-work>  (or ./scripts/lab_drop_to_sor.sh)"
echo "LAB != SAMPLE != client. paying_day FAIL. No /api/risks."
