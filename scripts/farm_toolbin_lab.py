#!/usr/bin/env python3
"""DEMO: FARM_TOOL_BIN=farm/tool-bin/lab → plan will_run for nmap+curl.

Does not --live. Does not start compose. Does not probe the internet.
Unset FARM_TOOL_BIN is the default farm-lab path (plan-only fixtures).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def farm_toolbin_lab(root: Path | None = None) -> dict:
    root = Path(root or ROOT)
    lab = root / "farm" / "tool-bin" / "lab"
    saved = {key: os.environ.get(key) for key in ("FARM_TOOL_BIN", "DROPBOX_ORCH_DIR", "PYTHONPATH")}
    work = root / "farm" / "work"
    work.mkdir(parents=True, exist_ok=True)
    try:
        os.environ["FARM_TOOL_BIN"] = str(lab)
        os.environ["PYTHONPATH"] = str(root)
        os.environ["DROPBOX_ORCH_DIR"] = str(work / "toolbin-orch")
        from dropbox.orchestrator.byo import farm_which
        from dropbox.scope import load_scope
        from farm.adapters.catalog import select_stage_slots

        scope = load_scope(root / "dropbox" / "SCOPE.yaml")
        disc = select_stage_slots("discover", scope.allow_tools)
        nmap = next(row for row in disc["selected"] if row["slot"] == "nmap")
        curl_ready = bool(farm_which("curl"))
        nmap_ready = bool(farm_which("nmap")) and bool(nmap.get("will_run"))
        stamp = {
            "status": "pass" if nmap_ready and curl_ready else "fail",
            "demo": True,
            "label": "DEMO — farm/tool-bin/lab stubs, not a client, not compose runtime",
            "farm_tool_bin": str(lab),
            "live": False,
            "will_run": {
                "nmap": bool(nmap.get("will_run")),
                "curl": curl_ready,
            },
            "note": "plan only. No network. No compose. LICENSE-LOCK names not invoked.",
        }
        dest = work / "toolbin-lab.json"
        dest.write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
        return stamp
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def main() -> int:
    stamp = farm_toolbin_lab()
    print(json.dumps(stamp, indent=2))
    if stamp.get("status") != "pass":
        print("FARM_TOOLBIN_LAB=fail", file=sys.stderr)
        return 1
    print("FARM_TOOLBIN_LAB=pass nmap+curl will_run (DEMO stubs, no network)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
