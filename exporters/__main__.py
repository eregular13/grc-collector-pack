"""CLI: python3 -m exporters --sink opengrc|probo|all

Reads the CISO intermediate (out/ciso-assistant or --out-dir). File-only.
Never POSTs. SAMPLE/DEMO ≠ client.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from exporters.model import load_pack_estate
from exporters.opengrc import write_opengrc
from exporters.probo import write_probo


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="exporters",
        description="Pack/CISO intermediate → OpenGRC CSVs and/or Probo drafts (no POST)",
    )
    parser.add_argument(
        "--sink",
        choices=("opengrc", "probo", "all"),
        default="all",
        help="which SoR files to write (default all)",
    )
    parser.add_argument(
        "--out-dir",
        dest="out_dir",
        help="estate out/ that already has ciso-assistant/*.csv",
    )
    args = parser.parse_args(argv)
    out = Path(args.out_dir) if args.out_dir else None
    estate = load_pack_estate(out)
    result: dict = {
        "posted": False,
        "http": False,
        "sample": True,
        "client": False,
        "paying_day": "FAIL",
        "source": estate.source,
        "findings": len(estate.findings),
        "assets": len(estate.assets),
    }
    if args.sink in {"opengrc", "all"}:
        result["opengrc"] = write_opengrc(out, estate=estate)
    if args.sink in {"probo", "all"}:
        path = write_probo(out, estate=estate)
        result["probo"] = str(path)
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
