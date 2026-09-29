"""Pack-owned output paths. Clean retired ghosts on upgrade; never delete others.

1f8d347 (and earlier) wrote ``out/riskready/`` and ``risks_proposed.json``.
The current loader does not emit those. An in-place upgrade must remove
only those pack-owned leftovers. Operator files stay on disk.
"""

from __future__ import annotations

import shutil
from pathlib import Path

# Directories the pack used to write and no longer writes (1f8d347-era).
RETIRED_PACK_OWNED_DIRS = frozenset({"riskready"})

# Files the pack used to write at these exact relative paths.
RETIRED_PACK_OWNED_FILES = frozenset(
    {
        "risks_proposed.json",
        "riskready/risks_proposed.json",
    }
)


def _safe_rel(path: Path, root: Path) -> str | None:
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return rel.as_posix()


def is_retired_pack_owned(rel_posix: str) -> bool:
    rel = rel_posix.replace("\\", "/").lstrip("./")
    if rel in RETIRED_PACK_OWNED_FILES:
        return True
    top = rel.split("/", 1)[0]
    return top in RETIRED_PACK_OWNED_DIRS


def clean_retired_pack_outputs(out: Path) -> list[str]:
    """Remove retired pack-owned artifacts under ``out/``. Leave everything else.

    Returns the relative paths that were removed. Refuses to touch paths
    outside ``out`` or names the pack did not historically create.
    """
    root = Path(out)
    if not root.is_dir():
        return []
    removed: list[str] = []
    for rel in sorted(RETIRED_PACK_OWNED_FILES):
        path = root / rel
        if not path.exists():
            continue
        checked = _safe_rel(path, root)
        if not checked or not is_retired_pack_owned(checked):
            continue
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed.append(checked)
    for name in sorted(RETIRED_PACK_OWNED_DIRS):
        path = root / name
        if not path.exists():
            continue
        checked = _safe_rel(path, root)
        if not checked or not is_retired_pack_owned(checked):
            continue
        if path.is_dir():
            shutil.rmtree(path)
            removed.append(checked)
        elif path.is_file() or path.is_symlink():
            path.unlink()
            removed.append(checked)
    return removed
