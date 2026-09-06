"""python -m keep lab — KEEP-chain parse + Eval handoff."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"lab", "keep-lab"}:
        from keep.lab import main as lab_main

        return lab_main()
    print("usage: python -m keep lab", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
