"""Zip engagements/<slug>/ excluding .env and tokens. Never invent prices."""
from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from dropbox.new_engagement import engagement_root

SKIP_NAMES = {".env", ".env.local", ".env.production"}
SKIP_GLOBS = ("*.env", "*token*", "*secret*", "*.pem", "*.p12")


def _skip(rel: str, name: str) -> bool:
    lowered = name.lower()
    if name in SKIP_NAMES or lowered in SKIP_NAMES:
        return True
    if lowered.endswith(".env"):
        return True
    for pat in SKIP_GLOBS:
        if fnmatch.fnmatch(name.lower(), pat.lower()) or fnmatch.fnmatch(rel.lower().replace("\\", "/"), pat.lower()):
            return True
    return False


def package_slug(slug: str) -> Path:
    root = engagement_root()
    src = root / slug
    if not src.is_dir():
        raise SystemExit(f"missing engagement {src}")
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    dest = root / f"engagement-{slug}-{day}.zip"
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in src.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(src).as_posix()
            if _skip(rel, path.name):
                continue
            zf.write(path, f"{slug}/{rel}")
    return dest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Zip an engagement kit; exclude .env/tokens.")
    parser.add_argument("--slug", required=True)
    args = parser.parse_args(argv)
    path = package_slug(args.slug)
    print(json.dumps({"zip": str(path), "bytes": path.stat().st_size}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
