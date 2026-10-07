#!/usr/bin/env python3
"""Prepare CISO Assistant CSVs for Data-Wizard import (PQ-4/5/7/8 + PQ-9).

File-only. Dry-run by default. Never POSTs. Never prints tokens.
Never POST /api/risks.

Usage:
  python3 scripts/prepare_ciso_wizard.py \\
    --src out/ciso-assistant --dest /tmp/ciso-mapped \\
    --domain my-lab-folder --chunk-size 500
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.ciso_wizard_map import (  # noqa: E402
    DEFAULT_VULN_CHUNK,
    chunk_plan_for_mapped,
    map_ciso_csvs,
)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--src", required=True, type=Path, help="source ciso-assistant/ dir")
    p.add_argument("--dest", required=True, type=Path, help="mapped output dir")
    p.add_argument(
        "--domain",
        default="",
        help="folder name for assets/controls domain (PQ-4/5). Default: Global",
    )
    p.add_argument("--chunk-size", type=int, default=DEFAULT_VULN_CHUNK)
    p.add_argument(
        "--write-chunks",
        action="store_true",
        help="also write vulnerabilities_chunkNN.csv under dest/vuln-chunks/",
    )
    p.add_argument("--json-out", type=Path, default=None, help="write stats JSON")
    args = p.parse_args()

    domain = (args.domain or "").strip() or "Global"
    stats = map_ciso_csvs(args.src, args.dest, domain=domain)
    chunk = None
    if args.write_chunks or True:
        # Always report plan; write files when --write-chunks.
        if args.write_chunks:
            chunk = chunk_plan_for_mapped(
                args.dest, chunk_size=args.chunk_size, dest_dir=args.dest / "vuln-chunks"
            )
        else:
            n = int(stats["counts"].get("vulnerabilities") or 0)
            from shared.ciso_wizard_map import plan_vuln_chunks

            ranges = plan_vuln_chunks(n, chunk_size=args.chunk_size)
            chunk = {
                "n_rows": n,
                "chunk_size": args.chunk_size,
                "n_chunks": len(ranges),
                "ranges": [{"start": a, "end": b, "n": b - a} for a, b in ranges],
                "paths": [],
            }
    payload = {"mapped": stats, "chunk_plan": chunk, "posted": False, "http": False}
    text = json.dumps(payload, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if stats.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
