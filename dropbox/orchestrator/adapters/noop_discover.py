"""Lab stub: fixture discover JSON. Labeled fixtures, not a client estate."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PACK = Path(__file__).resolve().parents[3]
FIXTURE = PACK / "dropbox" / "fixtures" / "discover.json"


def run(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / "discover.json"
    if FIXTURE.is_file():
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    else:
        data = {
            "label": "fixture",
            "hosts": [
                {"host": "file01.corp.local", "live": True, "in_scope": True},
                {"host": "smb-legacy.corp.local", "live": True, "in_scope": True},
            ],
        }
    data.setdefault("label", "fixture")
    dest.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data
