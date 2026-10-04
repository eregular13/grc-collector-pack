"""verify_manifest.py hashes bytes and rejects traversal. Never fake-OK."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from scripts.verify_manifest import (
    main,
    manifest_rel_rejected,
    resolve_manifest,
    verify_manifest,
)
from shared.estate_pages import assert_manifest_sha256sum

ROOT = Path(__file__).resolve().parents[1]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_sums(root: Path, entries: list[tuple[str, bytes]]) -> Path:
    lines = []
    for rel, data in entries:
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        lines.append(f"{_digest(data)}  {rel}")
    sums = root / "SHA256SUMS"
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return sums


def test_verify_manifest_ok_and_prefers_sha256sums(tmp_path: Path) -> None:
    _write_sums(tmp_path, [("a.txt", b"alpha\n")])
    (tmp_path / "MANIFEST").write_text("# markdown table\n", encoding="utf-8")
    assert resolve_manifest(tmp_path).name == "SHA256SUMS"
    ok = verify_manifest(tmp_path)
    assert ok == ["a.txt: OK"]
    assert main([str(tmp_path)]) == 0


def test_verify_manifest_bad_hash(tmp_path: Path) -> None:
    dest = tmp_path / "a.txt"
    dest.write_bytes(b"alpha\n")
    (tmp_path / "SHA256SUMS").write_text(
        f"{'0' * 64}  a.txt\n", encoding="utf-8", newline="\n"
    )
    with pytest.raises(AssertionError, match="FAILED"):
        verify_manifest(tmp_path)
    assert main([str(tmp_path)]) == 1


def test_verify_manifest_missing_file(tmp_path: Path) -> None:
    (tmp_path / "SHA256SUMS").write_text(
        f"{_digest(b'x')}  missing.txt\n", encoding="utf-8", newline="\n"
    )
    with pytest.raises(AssertionError, match="MISSING"):
        verify_manifest(tmp_path)


@pytest.mark.parametrize(
    "rel",
    [
        "../etc/passwd",
        "..\\windows\\system32\\config",
        "foo/../../etc/passwd",
        "C:\\Windows\\x",
        "C:/Windows/x",
        r"\\srv\share\x",
        "//srv/share/x",
        "/etc/passwd",
        r"\Windows\x",
    ],
)
def test_verify_manifest_rejects_traversal(tmp_path: Path, rel: str) -> None:
    assert manifest_rel_rejected(rel)
    (tmp_path / "SHA256SUMS").write_text(
        f"{_digest(b'x')}  {rel}\n", encoding="utf-8", newline="\n"
    )
    with pytest.raises(AssertionError, match="relative|escapes"):
        verify_manifest(tmp_path)


def test_verify_manifest_malformed_line(tmp_path: Path) -> None:
    (tmp_path / "SHA256SUMS").write_text("not a hash line\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="not sha256sum format"):
        verify_manifest(tmp_path)


def test_verify_manifest_empty(tmp_path: Path) -> None:
    (tmp_path / "SHA256SUMS").write_text("\n\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="no checksum lines"):
        verify_manifest(tmp_path)


def test_verify_manifest_does_not_ok_when_sha256sum_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Python path must still fail a bad hash when sha256sum is missing."""
    dest = tmp_path / "a.txt"
    dest.write_bytes(b"alpha\n")
    (tmp_path / "SHA256SUMS").write_text(
        f"{'0' * 64}  a.txt\n", encoding="utf-8", newline="\n"
    )

    def _no_sha256sum(*_a, **_k):
        raise OSError("sha256sum absent")

    monkeypatch.setattr(subprocess, "run", _no_sha256sum)
    with pytest.raises(AssertionError, match="FAILED"):
        assert_manifest_sha256sum(tmp_path)
    with pytest.raises(AssertionError, match="FAILED"):
        verify_manifest(tmp_path)


def test_product_lab_drop_verify_manifest_exits_0() -> None:
    drop = ROOT / "product-lab" / "drop"
    assert (drop / "SHA256SUMS").is_file(), "packaged drop must ship SHA256SUMS"
    assert main([str(drop)]) == 0
    ok = verify_manifest(drop)
    assert ok
    assert all(line.endswith(": OK") for line in ok)
