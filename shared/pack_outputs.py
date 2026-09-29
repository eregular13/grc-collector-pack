"""Pack-owned output paths. Clean 1f8d347-era ghosts; never delete others.

The loader wrote exactly four files (c1e0a56 through 5adc8b7 / #136):

  out/riskready/assets.json
  out/riskready/incidents.json
  out/riskready/evidence.json
  out/riskready/risks_proposed.json

It never wrote a top-level ``out/risks_proposed.json``. On POSIX, cleanup
opens ``out/riskready`` with ``O_NOFOLLOW|O_DIRECTORY`` and unlinks only
those four names when ``lstat`` (via ``dir_fd``) says they are regular
files and the bytes parse as the JSON list the pack used to write.
``rmdir`` the directory only when empty afterwards, also via ``dir_fd``.

When ``dir_fd`` / ``O_NOFOLLOW`` / ``O_DIRECTORY`` are unavailable
(Windows), fall back to #206's path-based ``lstat`` / ``S_ISREG`` walk
plus a symlink / junction / reparse-point check on ``out/riskready``
itself. Never ``rmtree``. Operator files, a regular file named
``riskready``, and symlinked targets stay. Errors log a warning and do
not abort. A missing ``out/riskready`` is silent (the normal case).
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
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_CLEANUP_EXC = (OSError, NotImplementedError)


def _dir_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)


def _file_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


def dir_fd_cleanup_supported() -> bool:
    """True only when the fd-relative path can refuse a symlink mid-run."""
    supports = getattr(os, "supports_dir_fd", None)
    if not supports:
        return False
    needed = (os.open, os.stat, os.unlink, os.rmdir)
    if any(fn not in supports for fn in needed):
        return False
    fd_supports = getattr(os, "supports_fd", frozenset())
    if os.listdir not in fd_supports:
        return False
    return hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")


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

    Returns the relative paths that were removed. Uses ``dir_fd`` when the
    platform supports it; otherwise the #206 path-based walk. Never raises
    to the caller: ``OSError`` and ``NotImplementedError`` are logged.
    """
    try:
        return _clean_retired_pack_outputs(out)
    except _CLEANUP_EXC as exc:
        log.warning("retired-output cleanup: skipped %s: %s", out, exc)
        return []


def _read_named(dir_fd: int, name: str, size: int) -> bytes | None:
    if size < 0 or size > _MAX_PACK_JSON_BYTES:
        log.warning("retired-output cleanup: keep %s (size %s)", name, size)
        return None
    try:
        fd = os.open(name, _file_flags(), dir_fd=dir_fd)
    except _CLEANUP_EXC as exc:
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
    except _CLEANUP_EXC as exc:
        log.warning("retired-output cleanup: read %s: %s", name, exc)
        return None
    finally:
        os.close(fd)


def _read_path(path: Path, size: int) -> bytes | None:
    if size < 0 or size > _MAX_PACK_JSON_BYTES:
        log.warning("retired-output cleanup: keep %s (size %s)", path, size)
        return None
    try:
        return path.read_bytes()
    except _CLEANUP_EXC as exc:
        log.warning("retired-output cleanup: read %s: %s", path, exc)
        return None


def _lstat(path: Path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except _CLEANUP_EXC as exc:
        log.warning("retired-output cleanup: lstat failed %s: %s", path, exc)
        return None


def _is_link_or_reparse(path: Path, st=None) -> bool:
    """Symlink, Windows junction, or any reparse point — do not walk it."""
    try:
        if os.path.islink(os.fspath(path)):
            return True
    except OSError:
        pass
    isj = getattr(os.path, "isjunction", None)
    if callable(isj):
        try:
            if isj(os.fspath(path)):
                return True
        except OSError:
            pass
    if st is None:
        st = _lstat(path)
    if st is None:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0) or 0
    return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)


def _resolve_root(root: Path) -> Path | None:
    try:
        return root.resolve()
    except OSError as exc:
        log.warning("retired-output cleanup: cannot resolve out dir %s: %s", root, exc)
        return None


def _under_root(path: Path, root_resolved: Path) -> bool:
    try:
        path.resolve().relative_to(root_resolved)
        return True
    except (ValueError, OSError):
        return False


def _clean_via_dir_fd(root: Path) -> list[str]:
    try:
        dir_fd = os.open(os.fspath(root / RETIRED_PACK_OWNED_DIR), _dir_flags())
    except FileNotFoundError:
        return []
    removed: list[str] = []
    try:
        for name in RETIRED_PACK_FILENAMES:
            rel = f"{RETIRED_PACK_OWNED_DIR}/{name}"
            try:
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except _CLEANUP_EXC as exc:
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
            except _CLEANUP_EXC as exc:
                log.warning("retired-output cleanup: skip %s: %s", rel, exc)
                continue
            removed.append(rel)

        try:
            leftover = os.listdir(dir_fd)
        except _CLEANUP_EXC as exc:
            log.warning("retired-output cleanup: keep out/riskready/: %s", exc)
            return removed
        if leftover:
            return removed
    finally:
        os.close(dir_fd)

    try:
        parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        parent_fd = os.open(os.fspath(root), parent_flags)
    except _CLEANUP_EXC as exc:
        log.warning("retired-output cleanup: keep out/riskready/: %s", exc)
        return removed
    try:
        os.rmdir(RETIRED_PACK_OWNED_DIR, dir_fd=parent_fd)
        removed.append(RETIRED_PACK_OWNED_DIR)
    except _CLEANUP_EXC as exc:
        log.warning("retired-output cleanup: keep out/riskready/: %s", exc)
    finally:
        os.close(parent_fd)
    return removed


def _clean_via_path(root: Path) -> list[str]:
    """#206 lstat/S_ISREG walk plus pack-JSON gate and junction refusal."""
    root_resolved = _resolve_root(root)
    if root_resolved is None:
        return []

    removed: list[str] = []
    rr = root / RETIRED_PACK_OWNED_DIR
    rr_st = _lstat(rr)
    if rr_st is None:
        return removed
    if _is_link_or_reparse(rr, rr_st):
        log.warning(
            "retired-output cleanup: skip out/riskready/ (symlink or reparse point)"
        )
        return removed
    if not stat.S_ISDIR(rr_st.st_mode):
        return removed
    if not _under_root(rr, root_resolved):
        return removed

    for name in RETIRED_PACK_FILENAMES:
        rel = f"{RETIRED_PACK_OWNED_DIR}/{name}"
        path = root / rel
        try:
            if not _under_root(path.parent, root_resolved):
                continue
            st = _lstat(path)
            if st is None:
                continue
            if _is_link_or_reparse(path, st):
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            raw = _read_path(path, st.st_size)
            if raw is None:
                continue
            if not looks_like_pack_json(name, raw):
                log.warning(
                    "retired-output cleanup: keep %s (not pack JSON)",
                    rel,
                )
                continue
            os.unlink(path)
            removed.append(rel)
        except _CLEANUP_EXC as exc:
            log.warning("retired-output cleanup: skip %s: %s", path, exc)

    try:
        with os.scandir(rr) as entries:
            empty = next(entries, None) is None
        if empty:
            os.rmdir(rr)
            removed.append(RETIRED_PACK_OWNED_DIR)
    except _CLEANUP_EXC as exc:
        log.warning("retired-output cleanup: keep out/riskready/: %s", exc)
    return removed


def _clean_retired_pack_outputs(out: Path) -> list[str]:
    root = Path(out)
    try:
        if not root.is_dir():
            return []
    except OSError as exc:
        log.warning("retired-output cleanup: out is not usable %s: %s", root, exc)
        return []

    if dir_fd_cleanup_supported():
        try:
            return _clean_via_dir_fd(root)
        except FileNotFoundError:
            return []
        except _CLEANUP_EXC as exc:
            log.warning(
                "retired-output cleanup: dir_fd path failed, using lstat: %s",
                exc,
            )
    return _clean_via_path(root)
