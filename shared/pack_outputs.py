"""Pack-owned output paths. Clean 1f8d347-era ghosts; never delete others.

The loader wrote exactly four files (c1e0a56 through 5adc8b7 / #136):

  out/riskready/assets.json
  out/riskready/incidents.json
  out/riskready/evidence.json
  out/riskready/risks_proposed.json

It never wrote a top-level ``out/risks_proposed.json``. Cleanup opens
``out/riskready`` with ``O_NOFOLLOW|O_DIRECTORY`` and unlinks only those
four names when ``lstat`` (via ``dir_fd``) says they are regular files
and the bytes parse as the JSON list the pack used to write. ``rmdir``
the directory only when empty afterwards, also via ``dir_fd``. Never
``rmtree``. Operator files, a regular file named ``riskready``, and
symlinked targets stay. Errors log a warning and do not abort.
"""

from __future__ import annotations

import json
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
RETIRED_PACK_FILENAMES = (
    "assets.json",
    "incidents.json",
    "evidence.json",
    "risks_proposed.json",
)

# Keys every object in that list carried (5adc8b7^ writer).
PACK_JSON_KEYS: dict[str, frozenset[str]] = {
    "assets.json": frozenset(
        {
            "name",
            "assetType",
            "status",
            "businessCriticality",
            "dataClassification",
            "cloudProvider",
            "inIsmsScope",
            "source",
            "notes",
        }
    ),
    "incidents.json": frozenset(
        {
            "title",
            "description",
            "severity",
            "status",
            "source",
            "relatedAssets",
        }
    ),
    "evidence.json": frozenset(
        {
            "title",
            "description",
            "evidenceType",
            "sourceType",
            "status",
            "source",
        }
    ),
    "risks_proposed.json": frozenset(
        {
            "ref_id",
            "name",
            "description",
            "likelihood",
            "impact",
            "severity",
            "assets",
            "source",
            "treatment",
        }
    ),
}

_MAX_PACK_JSON_BYTES = 8 * 1024 * 1024
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


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


def looks_like_pack_json(filename: str, raw: bytes) -> bool:
    """True when ``raw`` is the JSON list the pack used to write for ``filename``."""
    keys = PACK_JSON_KEYS.get(filename)
    if keys is None:
        return False
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        return False
    if not isinstance(data, list):
        return False
    for item in data:
        if not isinstance(item, dict):
            return False
        if not keys <= set(item):
            return False
    return True


def pack_shaped_bytes(filename: str) -> bytes:
    """Empty list the pack wrote when that sink had no rows."""
    if filename not in PACK_JSON_KEYS:
        raise KeyError(filename)
    return b"[]\n"


def clean_retired_pack_outputs(out: Path) -> list[str]:
    """Remove the four historical RiskReady files. Leave everything else.

    Returns the relative paths that were removed. Opens ``riskready`` with
    ``O_NOFOLLOW|O_DIRECTORY`` so a mid-run symlink swap cannot escape.
    Never raises to the caller: every ``OSError`` is logged and skipped.
    """
    try:
        return _clean_retired_pack_outputs(out)
    except OSError as exc:
        log.warning("retired-output cleanup: skipped %s: %s", out, exc)
        return []


def _open_riskready_dir(root: Path) -> int | None:
    try:
        return os.open(os.fspath(root / RETIRED_PACK_OWNED_DIR), _DIR_FLAGS)
    except OSError as exc:
        log.warning("retired-output cleanup: skip out/riskready/: %s", exc)
        return None


def _read_named(dir_fd: int, name: str, size: int) -> bytes | None:
    if size < 0 or size > _MAX_PACK_JSON_BYTES:
        log.warning("retired-output cleanup: keep %s (size %s)", name, size)
        return None
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        log.warning("retired-output cleanup: open %s: %s", name, exc)
        return None
    try:
        chunks: list[bytes] = []
        remaining = size + 1
        while remaining > 0:
            block = os.read(fd, remaining)
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        return b"".join(chunks)
    except OSError as exc:
        log.warning("retired-output cleanup: read %s: %s", name, exc)
        return None
    finally:
        os.close(fd)


def _clean_retired_pack_outputs(out: Path) -> list[str]:
    root = Path(out)
    try:
        if not root.is_dir():
            return []
    except OSError as exc:
        log.warning("retired-output cleanup: out is not usable %s: %s", root, exc)
        return []

    dir_fd = _open_riskready_dir(root)
    if dir_fd is None:
        return []
    removed: list[str] = []
    try:
        for name in RETIRED_PACK_FILENAMES:
            rel = f"{RETIRED_PACK_OWNED_DIR}/{name}"
            try:
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                log.warning("retired-output cleanup: lstat %s: %s", rel, exc)
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            raw = _read_named(dir_fd, name, st.st_size)
            if raw is None:
                continue
            if not looks_like_pack_json(name, raw):
                log.warning(
                    "retired-output cleanup: keep %s (not pack JSON)",
                    rel,
                )
                continue
            try:
                os.unlink(name, dir_fd=dir_fd)
            except OSError as exc:
                log.warning("retired-output cleanup: skip %s: %s", rel, exc)
                continue
            removed.append(rel)

        try:
            leftover = os.listdir(dir_fd)
        except OSError as exc:
            log.warning("retired-output cleanup: keep out/riskready/: %s", exc)
            return removed
        if leftover:
            return removed
    finally:
        os.close(dir_fd)

    try:
        parent_fd = os.open(os.fspath(root), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        log.warning("retired-output cleanup: keep out/riskready/: %s", exc)
        return removed
    try:
        os.rmdir(RETIRED_PACK_OWNED_DIR, dir_fd=parent_fd)
        removed.append(RETIRED_PACK_OWNED_DIR)
    except OSError as exc:
        log.warning("retired-output cleanup: keep out/riskready/: %s", exc)
    finally:
        os.close(parent_fd)
    return removed
