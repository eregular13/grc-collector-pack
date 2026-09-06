"""Pack in/ estate guard. Default file-drop is read-only."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from dropbox.scope import ROOT, GateError

PACK_SKIP = frozenset({".gitkeep", ".DS_Store"})


def pack_in_dir(root: Path | None = None) -> Path:
    return Path(root or ROOT) / "in"


def is_pack_in(path: Path | None, root: Path | None = None) -> bool:
    if path is None:
        return False
    try:
        return Path(path).resolve() == pack_in_dir(root).resolve()
    except OSError:
        return False


def write_pack_in_requested(*, explicit: bool | None = None) -> bool:
    """Opt-in only. CLI --write-pack-in or PACK_IN_WRITE=1."""
    if explicit is True:
        return True
    return os.environ.get("PACK_IN_WRITE", "0") == "1"


def fingerprint(folder: Path) -> dict[str, str]:
    """Relative path → sha256. Detect THIS-run writes into pack in/."""
    out: dict[str, str] = {}
    if not folder.is_dir():
        return out
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.name in PACK_SKIP:
            continue
        rel = str(path.relative_to(folder)).replace("\\", "/")
        out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def assert_pack_in_unchanged(
    before: dict[str, str],
    after: dict[str, str],
    *,
    context: str,
) -> None:
    if before == after:
        return
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    raise GateError(
        f"{context} wrote pack in/ without --write-pack-in "
        f"(added={added[:8]} removed={removed[:8]})"
    )
