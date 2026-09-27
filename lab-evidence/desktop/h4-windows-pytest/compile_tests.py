"""Compile all tests/*.py to catch import-syntax errors."""
from __future__ import annotations

import py_compile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
failed = []
for path in sorted((ROOT / "tests").glob("*.py")):
    try:
        py_compile.compile(str(path), doraise=True)
    except py_compile.PyCompileError as exc:
        failed.append(f"{path.name}: {exc}")
        print(path.name, "FAIL")
if failed:
    print("FAILED", len(failed))
    for row in failed:
        print(row)
    sys.exit(1)
print("ok", len(list((ROOT / "tests").glob("*.py"))))
