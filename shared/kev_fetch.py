"""Explicitly-invoked KEV snapshot writer. NEVER imported by the pipeline.

On a connected host only:

    KEV_FETCH_I_AM_CONNECTED=1 python -m shared.kev_fetch --dest <in/kev>

Not an operator entrypoint. Not wired into collectors, grc_loader, CI, or MCP.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from shared.kev import CISA_KEV_JSON, write_snapshot_files, _validate_catalog


def fetch_snapshot(dest: Path, url: str = CISA_KEV_JSON) -> dict:
    """Fetch CISA KEV JSON and write the three in/kev/ files.

    Refuses unless ``KEV_FETCH_I_AM_CONNECTED=1``. The pipeline never calls this.
    """
    if os.environ.get("KEV_FETCH_I_AM_CONNECTED") != "1":
        raise SystemExit(
            "KEV fetch refused: set KEV_FETCH_I_AM_CONNECTED=1 on a connected host. "
            "The pipeline and CI never fetch."
        )
    import urllib.request

    req = urllib.request.Request(url, headers={"User-Agent": "evergreen-kev-snapshot/1"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 — explicit connected-host helper
        raw = resp.read()
    data = json.loads(raw.decode("utf-8"))
    _validate_catalog(data)
    fetched = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return write_snapshot_files(dest, data, source_url=url, fetched_at_utc=fetched, raw=raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write an offline KEV snapshot. Not a pipeline or operator entrypoint."
    )
    parser.add_argument("--dest", required=True, help="Directory for the three in/kev/ files")
    parser.add_argument("--url", default=CISA_KEV_JSON)
    args = parser.parse_args(argv)
    prov = fetch_snapshot(Path(args.dest), url=args.url)
    print(json.dumps(prov, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
