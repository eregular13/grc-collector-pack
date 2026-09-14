#!/usr/bin/env python3
"""Write OpenGRC Data Manager CSVs from the CISO intermediate. No sockets."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from exporters.opengrc import write_opengrc


def main() -> None:
    stamp = write_opengrc()
    print(json.dumps(stamp, indent=2, default=str))
    print(stamp.get("dir"))


if __name__ == "__main__":
    main()
