"""python -m dropbox.new_engagement and python -m dropbox.package_engagement."""
from __future__ import annotations

import sys


def main() -> int:
    print("use: python -m dropbox.new_engagement --slug litware-lab", file=sys.stderr)
    print("     python -m dropbox.package_engagement --slug litware-lab", file=sys.stderr)
    print("     python -m dropbox.archive_out [--client NAME] [--clear]", file=sys.stderr)
    print("     python -m dropbox.import_grc --target all --dry-run", file=sys.stderr)
    print("     python -m dropbox.product_demo --help", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
