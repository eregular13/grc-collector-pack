from __future__ import annotations

import json
from pathlib import Path


def run(targets: list[str], out_dir: Path) -> dict:
    """Lab stub. Writes fixture discover JSON. Labeled fixtures, not a client estate."""
    out_dir.mkdir(parents=True, exist_ok=True)
    live = [t for t in targets if t][:8] or ["10.9.9.10"]
    payload = {
        "label": "fixture",
        "client_estate": False,
        "live": live,
        "targets_considered": targets,
        "note": "noop_discover: synthetic live set for lab ingest",
    }
    dest = out_dir / "discover.json"
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return {"adapter": "noop_discover", "ran": True, "live": live, "path": str(dest)}
