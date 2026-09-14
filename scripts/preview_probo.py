#!/usr/bin/env python3
"""Dry addRisk/addFinding-shaped preview from CISO CSVs. No sockets. Documentation only."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from exporters.probo import build_probo_preview, write_probo


def write_preview(out: Path | None = None) -> Path:
    return write_probo(out)


def main() -> None:
    path = write_preview()
    print(path)


if __name__ == "__main__":
    main()
