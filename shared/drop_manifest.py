"""SHA256 MANIFEST for operator dest_in drops. LF-stable (see .gitattributes)."""

from __future__ import annotations

import hashlib
from pathlib import Path

SKIP_NAMES = frozenset({".gitkeep", ".DS_Store"})


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_drop_manifest(
    folder: Path,
    *,
    header: str,
    relative_to: Path | None = None,
) -> Path:
    """Write a markdown table of relative path + SHA256. LF newlines only."""
    folder = Path(folder)
    root = Path(relative_to or folder)
    rows: list[tuple[str, str]] = []
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.name in SKIP_NAMES:
            continue
        if path.name in {"MANIFEST"}:
            continue
        rel = path.relative_to(root).as_posix()
        rows.append((rel, file_sha256(path)))
    lines = [
        header.rstrip() + "\n",
        "",
        "| File | SHA256 |",
        "|---|---|",
    ]
    for rel, digest in rows:
        lines.append(f"| {rel} | `{digest}` |")
    lines.append("")
    dest = folder / "MANIFEST"
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return dest


def parse_manifest_hashes(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        name, digest = cells[0], cells[1].strip("`")
        if name.lower() == "file" or name.startswith("---"):
            continue
        if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
            out[name] = digest
    return out
