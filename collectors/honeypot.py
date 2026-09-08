#!/usr/bin/env python3
"""Parse honeypot events under in/honeypot/ (Palisade + Beelzebub pack_drop).

Parse-only file_drop. Does not run a honeypot, scanner, or live trap.
Findings are deception-sensor / agent-behavior signals — not compromise.
Palisade may emit stage 1|2. Beelzebub is session/cmd/login only (stage=null).
"""

from __future__ import annotations

from pathlib import Path

from shared.honeypot import parse_honeypot
from shared.io_util import iso_now, read_text, run_collector

SOURCE = "honeypot"


def parse_file(path: Path) -> list[dict]:
    raw = read_text(path)
    now = iso_now()
    recs = parse_honeypot(path, raw, now)
    return list(recs or [])


def main() -> None:
    run_collector(SOURCE, (".jsonl", ".json"), parse_file)


if __name__ == "__main__":
    main()
