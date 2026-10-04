#!/usr/bin/env python3
"""Verify GNU sha256sum SHA256SUMS / MANIFEST against file bytes.

Portable replacement for ``sha256sum -c SHA256SUMS`` (Git Bash / Linux).
Windows operators: ``python scripts/verify_manifest.py [out-dir-or-file]``.

Prefers ``SHA256SUMS`` (sha256sum format). A ``MANIFEST`` is used only
when it is itself sha256sum format (operator ``out/``). The packaged
``product-lab/drop/MANIFEST`` is a markdown table — verify ``SHA256SUMS``.

Exit 0 when every listed hash matches. Exit 1 on mismatch / missing file
/ traversal / empty / malformed. Never writes. Never POSTs.
LAB/SAMPLE/DEMO are never client KEEP.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SHA256SUM_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")
CHECKSUM_NAMES = ("SHA256SUMS", "MANIFEST")
SELF_NAMES = frozenset({"SHA256SUMS", "MANIFEST"})


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_rel_rejected(rel: str) -> str | None:
    """Return a reject reason, or None when ``rel`` is a safe relative path.

    Uses both ``PureWindowsPath`` and ``PurePosixPath`` so drive letters,
    UNC, and ``..`` are rejected on Linux CI the same way as on Windows.
    """
    if not isinstance(rel, str) or not rel or rel.strip() != rel:
        return "must be a non-empty relative path"
    if "\x00" in rel:
        return "NUL byte"
    posix = PurePosixPath(rel)
    win = PureWindowsPath(rel)
    if win.drive:
        return "drive letter"
    if posix.is_absolute() or win.is_absolute():
        return "absolute"
    anchor = str(win.anchor or "")
    if anchor.startswith("\\\\") or rel.startswith(("\\\\", "//")):
        return "UNC"
    if rel.startswith(("/", "\\")):
        return "absolute"
    if ".." in posix.parts or ".." in win.parts:
        return ".."
    if ".." in rel.replace("\\", "/").split("/"):
        return ".."
    return None


def _stays_under(root: Path, rel: str) -> bool:
    try:
        root_res = root.resolve()
        candidate = (root / rel).resolve()
        candidate.relative_to(root_res)
    except (OSError, ValueError):
        return False
    return True


def resolve_manifest(raw: str | Path | None) -> Path:
    """Prefer SHA256SUMS, then a sha256sum-format MANIFEST."""
    if raw in (None, ""):
        for name in CHECKSUM_NAMES:
            dest = Path(name)
            if dest.is_file():
                return dest
        raise FileNotFoundError(
            "SHA256SUMS or MANIFEST not found in the current directory"
        )
    path = Path(raw)
    if path.is_dir():
        for name in CHECKSUM_NAMES:
            dest = path / name
            if dest.is_file():
                return dest
        raise FileNotFoundError(f"SHA256SUMS or MANIFEST not found under {path}")
    if path.is_file():
        return path
    raise FileNotFoundError(f"not a checksum file or directory: {path}")


def verify_manifest(out_or_manifest: str | Path) -> list[str]:
    """Return 'OK' lines. Raise AssertionError on the first failure.

    Always hashes file bytes in Python. Never reports OK because the
    ``sha256sum`` binary is absent.
    """
    manifest = resolve_manifest(out_or_manifest)
    root = manifest.parent
    text = manifest.read_text(encoding="utf-8")
    checked: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = SHA256SUM_LINE.match(line)
        if not match:
            raise AssertionError(f"MANIFEST is not sha256sum format: {line!r}")
        digest, rel = match.group(1), match.group(2)
        reason = manifest_rel_rejected(rel)
        if reason:
            raise AssertionError(f"MANIFEST path must be relative ({reason}): {rel!r}")
        if rel in SELF_NAMES or Path(rel).name in SELF_NAMES:
            raise AssertionError("checksum file must not list itself")
        if not _stays_under(root, rel):
            raise AssertionError(f"MANIFEST path escapes out dir: {rel!r}")
        path = root / rel
        if not path.is_file():
            raise AssertionError(f"{rel}: MISSING")
        got = _sha256(path)
        if got != digest:
            raise AssertionError(f"{rel}: FAILED (expected {digest}, got {got})")
        checked.append(f"{rel}: OK")
    if not checked:
        raise AssertionError("MANIFEST has no checksum lines")
    return checked


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify GNU sha256sum SHA256SUMS / MANIFEST hashes. Portable on "
            "Windows (no sha256sum required). Git Bash: sha256sum -c SHA256SUMS."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="",
        help="out/ directory, SHA256SUMS, or MANIFEST (default: ./SHA256SUMS or ./MANIFEST)",
    )
    args = parser.parse_args(argv)
    try:
        lines = verify_manifest(args.path or None)
    except (AssertionError, FileNotFoundError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
