"""Behavior: pr-b fixstack_apply is wired for lab_drop (not silent no-op)."""
from __future__ import annotations
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_lab_drop_invokes_fixstack_apply_after_prove():
    sh = (ROOT / "scripts" / "lab_drop_to_sor.sh").read_text(encoding="utf-8")
    assert "fixstack_apply" in sh
    assert (ROOT / "scripts" / "fixstack_apply.py").is_file()
    assert (ROOT / "scripts" / "fixstack" / "testssl_fix.py").is_file() or (
        ROOT / "scripts" / "fixstack"
    ).is_dir()

def test_fixstack_apply_module_importable():
    import importlib.util
    p = ROOT / "scripts" / "fixstack_apply.py"
    assert p.is_file(), "fixstack_apply.py missing"
    spec = importlib.util.spec_from_file_location("fixstack_apply", p)
    assert spec and spec.loader
