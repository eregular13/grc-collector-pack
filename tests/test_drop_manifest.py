"""CISO drop MANIFEST hashes must match the files in product-lab/drop/."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "product-lab" / "drop" / "MANIFEST"
DROP = ROOT / "product-lab" / "drop"
GITATTRIBUTES = ROOT / ".gitattributes"

ROW = re.compile(r"\|\s*(\S+\.\S+)\s*\|\s*(\d+|draft)\s*\|\s*`([0-9a-f]{64})`\s*\|")

HASHED = (
    "ciso/applied_controls.csv",
    "ciso/assets.csv",
    "ciso/evidences.csv",
    "ciso/findings.csv",
    "ciso/risk_scenarios.csv",
    "ciso/vulnerabilities.csv",
    "ciso/ESTATE.txt",
    "poam/poam.csv",
    "poam/poam.md",
    "poam/ESTATE.txt",
    "EXECUTIVE_SUMMARY.md",
    "SCOPE_AND_TRUST.md",
    "opengrc/risks.csv",
    "opengrc/assets.csv",
    "opengrc/implementations.csv",
    "import_preview/probo.json",
)


def test_gitattributes_pins_product_lab_drop_eol_lf() -> None:
    """MANIFEST SHA256 is of LF git blobs. Windows autocrlf must not rewrite drop files."""
    text = GITATTRIBUTES.read_text(encoding="utf-8")
    assert "product-lab/drop/**" in text
    pinned = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("product-lab/drop/**") and "eol=lf" in stripped:
            pinned = True
            break
    assert pinned, "product-lab/drop/** must be text eol=lf so MANIFEST hashes are OS-stable"


def test_product_lab_drop_hashed_files_are_lf() -> None:
    """Working-tree bytes hashed by MANIFEST tests must stay LF (see .gitattributes)."""
    cr = bytes([13])
    for rel in HASHED:
        raw = (DROP / rel).read_bytes()
        assert cr not in raw, f"{rel} has CR; MANIFEST SHA256 would drift on Windows autocrlf"


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
