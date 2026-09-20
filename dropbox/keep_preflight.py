"""Fail-closed keep-package check for cold SAMPLE→SoR.

Not an operator entrypoint. Scripts and MCP call this before
``python -m keep lab`` / ``from keep.lab`` so a partial copy or
corrupt cold-path-gate tree cannot surface as ModuleNotFoundError.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

KEEP_PACKAGE_FILES = (
    "keep/__main__.py",
    "keep/lab.py",
    "keep/adapters.py",
)
# Four SAMPLE keep-samples family files. Incomplete tree must fail closed
# (#98/#99 style) instead of emitting a hollow risk register.
KEEP_SAMPLE_FILES = (
    "fixtures/keep-samples/identity/hardeningkitty.csv",
    "fixtures/keep-samples/saas/maester.json",
    "fixtures/keep-samples/vuln/testssl.json",
    "fixtures/keep-samples/cloud/prowler.json",
)

KEEP_PACKAGE_CLONE = "eregular13/grc-collector-pack"
KEEP_PACKAGE_HINT = (
    "Checkout must be a full git clone of eregular13/grc-collector-pack "
    "(not a partial copy / corrupt cold-path-gate tree)."
)


class KeepPackageIncomplete(Exception):
    """keep package files missing or PYTHONPATH does not include the clone root."""


class KeepFixtureIncomplete(Exception):
    """SAMPLE keep-samples fixture missing, empty, or unparseable."""


def missing_keep_package_files(root: Path) -> list[str]:
    """Return required keep paths that are not files under root."""
    root = Path(root)
    missing: list[str] = []
    for rel in KEEP_PACKAGE_FILES:
        path = root / rel
        if not path.is_file():
            missing.append(str(path))
    return missing


def pythonpath_includes_root(root: Path, pythonpath: str | None = None) -> bool:
    """True when PYTHONPATH lists the clone root (scripts export this)."""
    raw = os.environ.get("PYTHONPATH", "") if pythonpath is None else pythonpath
    if not raw:
        return False
    resolved = Path(root).resolve()
    for part in raw.split(os.pathsep):
        if not part:
            continue
        if Path(part).resolve() == resolved:
            return True
    return False


def keep_package_incomplete_message(
    root: Path,
    missing: list[str] | None = None,
    *,
    pythonpath_ok: bool | None = None,
) -> str:
    """Short operator message. Names the missing path. Full-clone hint."""
    root = Path(root)
    missing = list(missing) if missing is not None else missing_keep_package_files(root)
    if missing:
        named = missing[0]
        extra = f" (and {len(missing) - 1} more)" if len(missing) > 1 else ""
        return (
            f"keep package incomplete: missing {named}{extra}. "
            f"{KEEP_PACKAGE_HINT}"
        )
    if pythonpath_ok is False:
        return (
            f"keep package PYTHONPATH does not include {root} "
            f"(keep is not importable). {KEEP_PACKAGE_HINT}"
        )
    return f"keep package incomplete under {root}. {KEEP_PACKAGE_HINT}"


def check_keep_package(
    root: Path,
    *,
    pythonpath: str | None = None,
    require_pythonpath: bool = False,
) -> dict[str, object]:
    """Inspect root. Does not import keep (keep may be the missing package)."""
    root = Path(root)
    missing = missing_keep_package_files(root)
    path_ok = pythonpath_includes_root(root, pythonpath)
    ok = not missing and (path_ok if require_pythonpath else True)
    message = ""
    if not ok:
        message = keep_package_incomplete_message(
            root,
            missing,
            pythonpath_ok=path_ok if require_pythonpath else None,
        )
    return {
        "ok": ok,
        "root": str(root),
        "missing": missing,
        "pythonpath_ok": path_ok,
        "message": message,
    }


def require_keep_package(
    root: Path,
    *,
    pythonpath: str | None = None,
    require_pythonpath: bool = False,
) -> Path:
    """Raise KeepPackageIncomplete when the checkout cannot run ``python -m keep``."""
    report = check_keep_package(
        root,
        pythonpath=pythonpath,
        require_pythonpath=require_pythonpath,
    )
    if not report["ok"]:
        raise KeepPackageIncomplete(str(report["message"]))
    return Path(root)


def missing_keep_sample_files(root: Path) -> list[str]:
    """Return required keep-samples paths that are missing or empty."""
    root = Path(root)
    missing: list[str] = []
    for rel in KEEP_SAMPLE_FILES:
        path = root / rel
        if not path.is_file() or path.stat().st_size == 0:
            missing.append(str(path))
    return missing


def keep_samples_incomplete_message(root: Path, missing: list[str] | None = None) -> str:
    """Short operator message. Names the missing fixture. Full-clone hint."""
    root = Path(root)
    missing = list(missing) if missing is not None else missing_keep_sample_files(root)
    if missing:
        named = Path(missing[0]).as_posix()
        extra = f" (and {len(missing) - 1} more)" if len(missing) > 1 else ""
        return (
            f"keep fixture incomplete: missing {named}{extra}. "
            f"SAMPLE keep-samples must include all four families. {KEEP_PACKAGE_HINT}"
        )
    return f"keep fixture incomplete under {root}. {KEEP_PACKAGE_HINT}"


def check_keep_samples(root: Path) -> dict[str, object]:
    """Inspect SAMPLE keep-samples files. Does not import keep."""
    root = Path(root)
    missing = missing_keep_sample_files(root)
    ok = not missing
    return {
        "ok": ok,
        "root": str(root),
        "missing": missing,
        "message": "" if ok else keep_samples_incomplete_message(root, missing),
    }


def require_keep_samples(root: Path) -> Path:
    """Raise KeepFixtureIncomplete when SAMPLE keep-samples cannot build a register."""
    report = check_keep_samples(root)
    if not report["ok"]:
        raise KeepFixtureIncomplete(str(report["message"]))
    return Path(root)


def abort_keep_samples(root: Path) -> Path:
    """Fail closed with a named missing fixture (not a hollow SoR)."""
    try:
        return require_keep_samples(root)
    except KeepFixtureIncomplete as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None


def abort_keep_package(
    root: Path,
    *,
    pythonpath: str | None = None,
    require_pythonpath: bool = False,
) -> Path:
    """Fail closed with the #98 preflight message (not ModuleNotFoundError)."""
    try:
        return require_keep_package(
            root,
            pythonpath=pythonpath,
            require_pythonpath=require_pythonpath,
        )
    except KeepPackageIncomplete as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None
