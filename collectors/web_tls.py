#!/usr/bin/env python3
"""Parse recorded web/TLS probe snapshots. Does not probe the network.

Live probes live in shared.web_tls_live behind --live + signed SCOPE.
This collector never imports the live module (no network I/O).
No fixtures/demo fallback — empty in/web_tls/ writes nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

from shared.io_util import in_dir, list_files, write_canonical
from shared.web_tls import SOURCE, parse_file

LABELS = ["web-tls", "env-eval"]


def parse_file_public(path: Path) -> list[dict]:
    return parse_file(path)


def main() -> int:
    if "--live" in sys.argv:
        print(
            "web-tls: collector is parse-only. Live probes: "
            "python -m shared.web_tls_live --live --scope PATH --target HOST",
            file=sys.stderr,
        )
        return 2
    files = list_files(in_dir() / "web_tls", (".json", ".jsonl"))
    records: list[dict] = []
    for path in files:
        records.extend(parse_file(path))
    if records:
        write_canonical(SOURCE, records)
    print(f"web-tls parse: files={len(files)} records={len(records)} (no demo fallback)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
