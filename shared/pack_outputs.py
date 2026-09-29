"""Pack-owned output paths. Clean 1f8d347-era ghosts; never delete others.

The loader wrote exactly four files (c1e0a56 through 5adc8b7 / #136):

  out/riskready/assets.json
  out/riskready/incidents.json
  out/riskready/evidence.json
  out/riskready/risks_proposed.json

It never wrote a top-level ``out/risks_proposed.json``. Cleanup unlinks only
those four paths when ``lstat`` says they are regular files (never follow
symlinks). ``out/riskready/`` is ``rmdir``'d only when empty afterwards.
Never ``rmtree``. Operator files, a regular file named ``riskready``, and
symlinked targets stay. Errors log a warning and do not abort.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

log = logging.getLogger(__name__)

# Directory the pack used to mkdir. Never rmtree; rmdir only if empty.
RETIRED_PACK_OWNED_DIRS = frozenset({"riskready"})
RETIRED_PACK_OWNED_DIR = "riskready"

# Files the pack actually wrote. Not a top-level risks_proposed.json.
RETIRED_PACK_OWNED_FILES = frozenset(
    {
        "riskready/assets.json",
        "riskready/incidents.json",
        "riskready/evidence.json",
        "riskready/risks_proposed.json",
    }
)


def _norm_rel(rel_posix: str) -> str:
    """Strip only a ``./`` prefix. ``lstrip('./')`` would turn ``.riskready``
    into ``riskready`` because it strips any mix of those characters."""
    rel = str(rel_posix or "").replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    return rel


def is_retired_pack_owned(rel_posix: str) -> bool:
    rel = _norm_rel(rel_posix)
    if rel in RETIRED_PACK_OWNED_FILES:
        return True
    return rel == RETIRED_PACK_OWNED_DIR


def _resolve_root(root: Path) -> Path | None:
    try:
        return root.resolve()
    except OSError as exc:
        log.warning("retired-output cleanup: cannot resolve out dir %s: %s", root, exc)
        return None


def _under_root(path: Path, root_resolved: Path) -> bool:
    """Containment via resolve of ``path``. Caller must not pass a symlink
    they intend to follow into a victim tree."""
    try:
        path.resolve().relative_to(root_resolved)
        return True
    except (ValueError, OSError):
        return False


def _lstat(path: Path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        log.warning("retired-output cleanup: lstat failed %s: %s", path, exc)
        return None


def clean_retired_pack_outputs(out: Path) -> list[str]:
    """Remove the four historical RiskReady files. Leave everything else.

    Returns the relative paths that were removed. Refuses to follow
    ``riskready`` or per-file symlinks. Never raises to the caller: every
    ``OSError`` is logged and skipped so ``load()`` can still write outputs.
    """
    try:
        return _clean_retired_pack_outputs(out)
    except OSError as exc:
        log.warning("retired-output cleanup: skipped %s: %s", out, exc)
        return []


def _clean_retired_pack_outputs(out: Path) -> list[str]:
    root = Path(out)
    try:
        if not root.is_dir():
            return []
    except OSError as exc:
        log.warning("retired-output cleanup: out is not usable %s: %s", root, exc)
        return []
    root_resolved = _resolve_root(root)
    if root_resolved is None:
        return []

    removed: list[str] = []
    rr = root / RETIRED_PACK_OWNED_DIR
    rr_st = _lstat(rr)
    if rr_st is None:
        return removed
    # Regular file or symlink named riskready: leave it. Following a
    # directory symlink would unlink files in a user project.
    if stat.S_ISLNK(rr_st.st_mode) or not stat.S_ISDIR(rr_st.st_mode):
        return removed
    if not _under_root(rr, root_resolved):
        return removed

    for rel in sorted(RETIRED_PACK_OWNED_FILES):
        path = root / rel
        try:
            if not _under_root(path.parent, root_resolved):
                continue
            st = _lstat(path)
            if st is None:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if not is_retired_pack_owned(rel):
                continue
            os.unlink(path)
            removed.append(rel)
        except OSError as exc:
            log.warning("retired-output cleanup: skip %s: %s", path, exc)

    try:
        with os.scandir(rr) as entries:
            empty = next(entries, None) is None
        if empty:
            os.rmdir(rr)
            removed.append(RETIRED_PACK_OWNED_DIR)
    except OSError as exc:
        log.warning("retired-output cleanup: keep out/riskready/: %s", exc)
    return removed
