#!/usr/bin/env python3
"""Farm compose lab: scanner-free statics always; runtime only if Docker is up.

Operator skeleton only. Does not fake a pass when the daemon is absent.
Exit 0 on absent/skip after statics pass. Exit 1 if farm image/compose
grows a scanner or wrap POST, or a live compose run fails.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dropbox.scanner_free import (  # noqa: E402
    assert_farm_compose_is_skeleton,
    assert_image_files_scanner_free,
    docker_available,
    write_stamp,
)


def farm_compose_lab() -> dict:
    assert_image_files_scanner_free()
    assert_farm_compose_is_skeleton()
    ok, reason = docker_available()
    if not ok:
        runtime_reason = reason
        note = "static scanner-free assertions passed; farm compose runtime not run"
    else:
        runtime_reason = "farm compose is an operator skeleton; this lab does not start workers"
        note = "Docker is present but farm compose runtime was not started — not a pass"
    stamp = {
        "status": "absent",
        "reason": runtime_reason,
        "scanner_free": True,
        "farm_skeleton": True,
        "wrap_free": True,
        "profiles_run": [],
        "note": note,
    }
    dest = ROOT / "farm" / "work" / "compose-lab.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    write_stamp(stamp)
    return stamp


def main() -> int:
    stamp = farm_compose_lab()
    print(json.dumps(stamp, indent=2))
    status = stamp.get("status")
    if status == "pass":
        print("FARM_COMPOSE_LAB=pass")
        return 0
    if status in {"absent", "skip"}:
        print(f"FARM_COMPOSE_LAB={status} reason={stamp.get('reason')}")
        print("static scanner-free: PASS (not a farm compose runtime pass)")
        return 0
    print(f"FARM_COMPOSE_LAB=fail reason={stamp.get('reason')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
