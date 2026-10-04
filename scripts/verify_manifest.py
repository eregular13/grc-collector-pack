#!/usr/bin/env python3
"""Verify a GNU sha256sum MANIFEST against file bytes.

Portable replacement for ``sha256sum -c MANIFEST`` (Git Bash / Linux).
Windows operators: ``python scripts/verify_manifest.py [out-dir-or-MANIFEST]``.

Exit 0 when every listed hash matches. Exit 1 on mismatch / missing file.
Never writes. Never POSTs. LAB/SAMPLE/DEMO are never client KEEP.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SHA256SUM_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_manifest(raw: str | Path | None) -> Path:
    if raw in (None, ""):
        dest = Path("MANIFEST")
        if dest.is_file():
            return dest
        raise FileNotFoundError("MANIFEST not found in the current directory")
    path = Path(raw)
    if path.is_dir():
        dest = path / "MANIFEST"
        if dest.is_file():
            return dest
        raise FileNotFoundError(f"MANIFEST not found under {path}")
    if path.is_file():
        return path
    raise FileNotFoundError(f"not a MANIFEST file or directory: {path}")


def verify_manifest(out_or_manifest: str | Path) -> list[str]:
    """Return 'OK' lines. Raise AssertionError on the first failure."""
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
        if rel.startswith("/") or ".." in Path(rel).parts:
            raise AssertionError(f"MANIFEST path must be relative: {rel!r}")
        if rel == "MANIFEST" or Path(rel).name == "MANIFEST":
            raise AssertionError("MANIFEST must not list itself")
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
            "Verify GNU sha256sum MANIFEST hashes. Portable on Windows "
            "(no sha256sum required). Git Bash can still use sha256sum -c MANIFEST."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="",
        help="out/ directory or MANIFEST file (default: ./MANIFEST)",
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
