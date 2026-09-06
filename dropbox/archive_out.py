"""Archive leftover dropbox/out so a new SCOPE does not silently clobber another client."""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PACK = Path(__file__).resolve().parents[1]
DROPBOX_OUT = PACK / "dropbox" / "out"
SKIP_NAMES = {".env", ".env.local", ".env.production"}
SKIP_GLOBS = ("*.env", "*token*", "*secret*", "*.pem", "*.p12")
CLIENT_SLUG = re.compile(r"[^a-z0-9]+")


def engagement_root() -> Path:
    raw = os.environ.get("ENGAGEMENT_ROOT")
    return Path(raw).resolve() if raw else (PACK / "engagements")


def _skip(rel: str, name: str) -> bool:
    lowered = name.lower()
    if name in SKIP_NAMES or lowered in SKIP_NAMES:
        return True
    if lowered.endswith(".env"):
        return True
    for pat in SKIP_GLOBS:
        if fnmatch.fnmatch(lowered, pat.lower()) or fnmatch.fnmatch(rel.lower().replace("\\", "/"), pat.lower()):
            return True
    return False


def leftover_client(dest: Path) -> str:
    path = dest / "discover.json"
    if not path.is_file():
        return ""
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(blob, dict):
        return ""
    return str(blob.get("client") or "").strip()


def archive_dropbox_out(
    dest: Path | None = None,
    *,
    current_client: str = "",
    clear: bool = False,
) -> dict[str, Any]:
    dest = dest or DROPBOX_OUT
    dest = Path(dest)
    if not dest.is_dir():
        return {"archived": False, "reason": "no_out", "leftover_client": ""}
    client = leftover_client(dest)
    if current_client and client and client == current_client.strip():
        return {"archived": False, "reason": "same_client", "leftover_client": client}
    label = client or "unstamped"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = CLIENT_SLUG.sub("-", label.lower()).strip("-")[:48] or "unstamped"
    archive = engagement_root() / "_archive" / f"{slug}-{stamp}"
    archive.mkdir(parents=True, exist_ok=True)
    copied = 0
    for path in dest.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(dest).as_posix()
        if _skip(rel, path.name):
            continue
        if path.parent.name == "workers" and path.name.endswith(".alive"):
            continue
        target = archive / path.relative_to(dest)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        copied += 1
    rec = {
        "archived": True,
        "path": str(archive),
        "leftover_client": client,
        "current_client": current_client,
        "files": copied,
        "cleared": False,
        "client_facing_ready": False,
        "note": "Leftover estate archived. Not a customer pack. Not a paying-day PASS.",
    }
    (archive / "ARCHIVE.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")
    if clear:
        for name in ("discover.json", "deepen.json", "plan.json", "grc_export.json"):
            try:
                (dest / name).unlink(missing_ok=True)
            except OSError:
                pass
        rec["cleared"] = True
    rec["client_facing_ready"] = False
    return rec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Archive leftover dropbox/out (does not live-scan).")
    parser.add_argument("--client", default="", help="Current SCOPE client; skip if leftover matches.")
    parser.add_argument("--clear", action="store_true", help="Remove leftover discover/deepen after copy.")
    args = parser.parse_args(argv)
    rec = archive_dropbox_out(current_client=args.client, clear=args.clear)
    print(json.dumps(rec, indent=2))
    return 0 if rec.get("archived") or rec.get("reason") in {"same_client", "no_out"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
