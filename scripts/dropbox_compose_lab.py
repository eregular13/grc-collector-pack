#!/usr/bin/env python3
"""Dropbox compose lab: scanner-free statics always; runtime only if Docker is up.

Does not fake a pass when the daemon is absent. Exit 0 on absent/skip after
statics pass. Exit 1 if image/compose grow a scanner or a live compose run fails.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dropbox.scanner_free import compose_lab  # noqa: E402


def main() -> int:
    stamp = compose_lab()
    print(json.dumps(stamp, indent=2))
    status = stamp.get("status")
    if status == "pass":
        print("COMPOSE_LAB=pass")
        return 0
    if status in {"absent", "skip"}:
        print(f"COMPOSE_LAB={status} reason={stamp.get('reason')}")
        print("static scanner-free: PASS (not a compose runtime pass)")
        return 0
    print(f"COMPOSE_LAB=fail reason={stamp.get('reason')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
