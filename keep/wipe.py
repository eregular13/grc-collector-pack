"""Windows-safe wipe for keep/work trees. Not an operator entrypoint.

Bare ``shutil.rmtree(keep/work/out)`` raises ``OSError: [WinError 145]
The directory is not empty`` on DESKTOP when leftovers (or a pending
delete) remain after ``sample_to_sor``. keep-lab and MCP ``keep_ciso``
share this helper. Files-first, chmod-then-unlink, retry, rename-away.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
import time
from pathlib import Path

# Windows ERROR_DIR_NOT_EMPTY. Also retry sharing-violation / access-denied.
WIN_DIR_NOT_EMPTY = 145
WIN_ACCESS_DENIED = 5
WIN_SHARING_VIOLATION = 32
RETRY_WINERRORS = frozenset({WIN_DIR_NOT_EMPTY, WIN_ACCESS_DENIED, WIN_SHARING_VIOLATION})
RETRY_ERRNOS = frozenset(
    {
        errno.ENOTEMPTY,
        errno.EEXIST,
        errno.EACCES,
        errno.EPERM,
        errno.EBUSY,
        WIN_DIR_NOT_EMPTY,
    }
)


def retryable_wipe_error(exc: BaseException) -> bool:
    """True for WinError 145 / ENOTEMPTY / sharing-violation class errors."""
    winerror = getattr(exc, "winerror", None)
    if winerror in RETRY_WINERRORS:
        return True
    if isinstance(exc, OSError) and exc.errno in RETRY_ERRNOS:
        return True
    return False


def _chmod_writable(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
    except OSError:
        return


def _unlink_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        _chmod_writable(path)
        try:
            path.unlink()
        except FileNotFoundError:
            return
        except OSError:
            _chmod_writable(path)
            path.unlink()
            return


def _rmdir_path(path: Path) -> None:
    _chmod_writable(path)
    try:
        path.rmdir()
    except FileNotFoundError:
        return


def _onerror(func, path, _exc) -> None:  # noqa: ANN001
    target = Path(path)
    _chmod_writable(target)
    try:
        func(path)
    except FileNotFoundError:
        return


def _files_first_wipe(path: Path) -> None:
    """Unlink files, then rmdir children, deepest first. Then the root."""
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or path.is_file():
        _unlink_path(path)
        return
    for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
        folder = Path(root)
        for name in files:
            _unlink_path(folder / name)
        for name in dirs:
            child = folder / name
            if child.is_symlink() or child.is_file():
                _unlink_path(child)
            else:
                _rmdir_path(child)
    _rmdir_path(path)


def _rename_away(path: Path) -> Path | None:
    """Move a stubborn tree off the operator path so mkdir can recreate it."""
    parent = path.parent
    if not parent.is_dir():
        return None
    for idx in range(24):
        trash = parent / f".{path.name}.wipe-{os.getpid()}-{idx}"
        if trash.exists():
            continue
        try:
            path.rename(trash)
        except OSError:
            continue
        return trash
    return None


def _rmtree_fallback(path: Path) -> None:
    try:
        shutil.rmtree(path, onexc=_onerror)
    except TypeError:
        shutil.rmtree(path, onerror=_onerror)


def wipe_tree(path: Path | str, *, retries: int = 6, delay: float = 0.04) -> None:
    """Remove ``path`` even when Windows reports the directory is not empty.

    Missing paths are a no-op. After retries, rename the leftover away from
    ``keep/work/out`` so the next SAMPLE run can mkdir a fresh tree.
    """
    target = Path(path)
    if not target.exists() and not target.is_symlink():
        return
    trash: Path | None = None
    last: OSError | None = None
    for attempt in range(max(1, retries)):
        try:
            _files_first_wipe(target)
            if not target.exists() and not target.is_symlink():
                if trash is not None:
                    try:
                        _files_first_wipe(trash)
                    except OSError:
                        pass
                return
            _rmtree_fallback(target)
            if not target.exists() and not target.is_symlink():
                return
        except FileNotFoundError:
            return
        except OSError as exc:
            last = exc
            if not retryable_wipe_error(exc) and attempt == retries - 1:
                break
        time.sleep(delay * (2 ** attempt))
    if target.exists() or target.is_symlink():
        trash = _rename_away(target)
        if trash is not None:
            try:
                _files_first_wipe(trash)
            except OSError:
                pass
        if target.exists() or target.is_symlink():
            try:
                _rmtree_fallback(target)
            except OSError as exc:
                last = exc
        if target.exists() or target.is_symlink():
            if last is not None:
                raise last
            raise OSError(WIN_DIR_NOT_EMPTY, "The directory is not empty")


def _dir_is_stable(path: Path) -> bool:
    """True when ``path`` is a writable directory (pending-delete race check)."""
    if not path.is_dir():
        return False
    probe = path / f".wipe-probe-{os.getpid()}"
    try:
        probe.write_text("ok", encoding="utf-8")
        ok = probe.is_file() and probe.read_text(encoding="utf-8") == "ok"
        try:
            probe.unlink()
        except OSError:
            pass
        return ok and path.is_dir()
    except OSError:
        return False


def reset_dir(path: Path | str, *, retries: int = 6) -> Path:
    """Wipe ``path`` then mkdir a fresh empty directory. Used for keep/work/{in,out}."""
    target = Path(path)
    wipe_tree(target, retries=retries)
    parent = target.parent
    if parent != target and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(max(1, retries)):
        if target.exists() and not target.is_dir():
            wipe_tree(target, retries=2)
        target.mkdir(parents=True, exist_ok=True)
        if _dir_is_stable(target):
            return target
        time.sleep(0.04 * (2 ** attempt))
        wipe_tree(target, retries=2)
    target.mkdir(parents=True, exist_ok=True)
    return target
