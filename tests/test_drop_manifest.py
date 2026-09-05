"""CISO drop MANIFEST hashes must match the files in product-lab/drop/."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "product-lab" / "drop" / "MANIFEST"
DROP = ROOT / "product-lab" / "drop"

ROW = re.compile(r"\|\s*(\S+\.\S+)\s*\|\s*(\d+|draft)\s*\|\s*`([0-9a-f]{64})`\s*\|")


def test_drop_manifest_hashes_match_files() -> None:
    text = MANIFEST.read_text(encoding="utf-8")
    assert "owner/due" in text.lower()
    assert "blank" in text.lower()
    rows = ROW.findall(text)
    assert len(rows) >= 7
    for rel, _count, digest in rows:
        path = DROP / rel
        assert path.is_file(), rel
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        assert got == digest, f"{rel} hash drift vs MANIFEST"
    poam = (DROP / "poam" / "poam.csv").read_text(encoding="utf-8")
    assert "SMB" in poam or "445" in poam
    assert "RDP" in poam or "3389" in poam
    assert ",,open" in poam or poam.count("\n") > 2
