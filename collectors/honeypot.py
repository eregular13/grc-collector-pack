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


def _is_demo(path: Path, raw: str) -> bool:
    if "DEMO — not a client estate" in raw or "DEMO -- not a client estate" in raw:
        return True
    if "SAMPLE/DEMO" in raw or "SAMPLE — " in raw:
        return True
    if (path.parent / "SAMPLE.txt").is_file():
        return True
    return '"demo": true' in raw or '"demo":true' in raw


def _stamp_demo(records: list[dict], demo: bool) -> None:
    if not demo:
        return
    for rec in records:
        labels = rec.setdefault("labels", [])
        if "demo" not in labels:
            labels.append("demo")
        if "SAMPLE" not in labels:
            labels.append("SAMPLE")


def parse_file(path: Path) -> list[dict]:
    raw = read_text(path)
    now = iso_now()
    recs = list(parse_honeypot(path, raw, now) or [])
    _stamp_demo(recs, _is_demo(path, raw))
    return recs


def main() -> None:
    run_collector(SOURCE, (".jsonl", ".json"), parse_file)


if __name__ == "__main__":
    main()
