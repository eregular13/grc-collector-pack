"""python -m keep lab — SAMPLE KEEP-chain → CISO Assistant CSVs (+ Eval handoff)."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"lab", "keep-lab", "ciso"} or args[0].startswith("-"):
        from keep.lab import main as lab_main

        rest = args[1:] if args and args[0] in {"lab", "keep-lab", "ciso"} else args
        return lab_main(rest)
    print(
        "usage: python -m keep lab [--pack-in DIR] [--work DIR]\n"
        "       # fixtures/keep-samples → keep/work/out/ciso-assistant\n"
        "       # DESKTOP dry-run: DRY_RUN=1 CISO_PUSH=0 (see docs/DESKTOP_DRY_RUN.md)",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
