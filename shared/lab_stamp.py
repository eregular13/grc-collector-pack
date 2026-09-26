"""LAB dest_in provenance. LAB != SAMPLE != client KEEP."""

from __future__ import annotations

from pathlib import Path
from typing import Any

LAB_LABEL = "LAB"
LAB_BANNER = "LAB/DEMO -- not a client estate. LAB != SAMPLE != client."
SKIP_INPUT_NAMES = frozenset(
    {
        ".gitkeep",
        ".DS_Store",
        "LAB.txt",
        "SAMPLE.txt",
        "README.md",
        "MANIFEST",
        "MANIFEST.json",
        "HARDENINGKITTY.host",
    }
)


def path_is_lab(path: Path | None, row: dict[str, Any] | None = None) -> bool:
    """True when a dest_in ancestor has LAB.txt or the row is lab:true."""
    if row and row.get("lab") is True:
        return True
    if path is None:
        return False
    cur = path.parent if path.is_file() else path
    hops = 0
    while cur is not None and hops < 8:
        if (cur / "LAB.txt").is_file():
            return True
        at_dest_in = cur.name == "in"
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
        hops += 1
        if at_dest_in:
            break
    return False


def stamp_lab_labels(records: list[dict[str, Any]], *, lab: bool) -> list[dict[str, Any]]:
    """Add LAB to every row when the feed is a LAB dest_in. Never SAMPLE/KEEP."""
    if not lab:
        return records
    for rec in records:
        labels = rec.setdefault("labels", [])
        if isinstance(labels, list) and LAB_LABEL not in labels:
            labels.append(LAB_LABEL)
        extra = rec.setdefault("extra", {})
        if isinstance(extra, dict):
            extra["lab"] = True
            extra["sample"] = False
            extra["client"] = False
            extra.setdefault("provenance", LAB_BANNER)
    return records
