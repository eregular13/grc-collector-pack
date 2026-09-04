#!/usr/bin/env python3
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
DONE = ROOT / "DONE.md"
STATUS = ROOT / "STATUS.md"

def read_stdin():
    raw = sys.stdin.read().lstrip("\ufeff").strip()
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}

def is_green():
    done = DONE.exists() and DONE.read_text(encoding="utf-8", errors="replace").upper().lstrip().startswith("GREEN")
    summary = (ROOT / "out" / "summary.json").exists() or (ROOT / "grc-collector-pack" / "out" / "summary.json").exists()
    return done and summary

payload = read_stdin()
if payload.get("status") in {"aborted", "error"} or is_green():
    sys.stdout.write("{}")
    raise SystemExit(0)

hint = STATUS.read_text(encoding="utf-8", errors="replace")[:1500] if STATUS.exists() else "STATUS.md missing"
msg = (
    "Resuming agent graph from STATUS.md.\n"
    "Do not summarize. Do not ask the user. Do not stop.\n"
    "Read STATUS.md, FAULTS.md, AGENTS.md.\n"
    "Execute the NEXT node (LAB if code exists, else BUILD).\n"
    "Run the lab. Fix P0/P1. Update STATUS.md.\n"
    "Write DONE.md first line GREEN only after two consecutive green labs "
    "and critic score >= 8.\n"
    "Forbidden: implementation complete / please run compose / next you can.\n"
    "--- STATUS.md ---\n" + hint
)
sys.stdout.write(json.dumps({"followup_message": msg}))
