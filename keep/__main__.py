"""python -m keep lab — SAMPLE KEEP-chain → CISO Assistant CSVs (+ Eval handoff)."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"lab", "keep-lab", "ciso"} or args[0].startswith("-"):
        from keep.lab import main as lab_main

        rest = args[1:] if args and args[0] in {"lab", "keep-lab", "ciso"} else args
        return lab_main(rest)
    if args[0] in {"verify", "honesty"}:
        from keep.ciso_import import verify_main

        return verify_main(args[1:])
    print(
        "usage: python -m keep lab [--pack-in DIR] [--work DIR]\n"
        "       python -m keep verify --ciso keep/work/out/ciso-assistant\n"
        "       # fixtures/keep-samples → keep/work/out/ciso-assistant\n"
        "       # one command: scripts/sample_to_sor.sh (or sample_to_sor.ps1)\n"
        "       # DESKTOP dry-run: DRY_RUN=1 CISO_PUSH=0 (see docs/DESKTOP_DRY_RUN.md)",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
