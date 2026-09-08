"""Zip engagements/<slug>/ excluding .env and tokens. Never invent prices."""
from __future__ import annotations

import argparse
import fnmatch
import json
import shutil
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


def slug_zip_text(zpath: Path, slug: str, rel: str) -> str:
    """UTF-8 text of one engagement zip member. Missing member raises KeyError."""
    member = f"{slug}/{rel.lstrip('/').replace('\\', '/')}"
    with zipfile.ZipFile(zpath) as zf:
        return zf.read(member).decode("utf-8")


def slug_zip_poam(zpath: Path, slug: str) -> str:
    """POA&M CSV text from a packaged engagement zip. Missing member raises KeyError."""
    return slug_zip_text(zpath, slug, "out/poam/poam.csv")


def slug_zip_simplerisk(zpath: Path, slug: str) -> str:
    """SimpleRisk leave-behind CSV from a packaged engagement zip."""
    return slug_zip_text(zpath, slug, "out/simplerisk/risks_import.csv")


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
    ready = root / f"engagement-{slug}-ready.zip"
    shutil.copyfile(dest, ready)
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
