#!/usr/bin/env bash
# Operator MCP stdio from repo root. Not FastMCP. No network bind.
# Cursor / Claude Desktop: point command at this script (absolute path).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"
export DROPBOX_LIVE="${DROPBOX_LIVE:-0}"
export GRC_LIVE_SCAN="${GRC_LIVE_SCAN:-0}"
export CISO_PUSH="${CISO_PUSH:-0}"
export RISKREADY_PUSH="${RISKREADY_PUSH:-0}"
exec python3 -m dropbox.mcp_stub serve --stdio
