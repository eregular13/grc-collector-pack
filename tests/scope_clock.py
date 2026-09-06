"""Lab consent windows relative to now. Do not bake another Saturday."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

PACK = Path(__file__).resolve().parents[1]
PT = timezone(timedelta(hours=-7))
EXPIRED_START = "2026-09-03T00:00:00-07:00"
EXPIRED_END = "2026-09-05T09:00:00-07:00"


def _fmt(dt: datetime) -> str:
    return dt.astimezone(PT).strftime("%Y-%m-%dT%H:%M:%S-07:00")


def open_stamps(now: datetime | None = None) -> tuple[str, str]:
    clock = now or datetime.now(PT)
    return _fmt(clock - timedelta(days=1)), _fmt(clock + timedelta(days=30))


def closed_stamps(now: datetime | None = None) -> tuple[str, str]:
    clock = now or datetime.now(PT)
    return _fmt(clock - timedelta(days=2)), _fmt(clock - timedelta(hours=1))


OPEN_START, OPEN_END = open_stamps()
LAB_SCOPE = PACK / "dropbox" / "SCOPE.lab.yaml"
LAB_EXTERNAL = PACK / "dropbox" / "SCOPE.external.lab.yaml"


def with_open_window(text: str) -> str:
    return text.replace(EXPIRED_END, OPEN_END).replace(EXPIRED_START, OPEN_START)


def write_lab_scopes(pack: Path | None = None) -> None:
    root = pack or PACK
    drop = root / "dropbox"
    start, end = open_stamps()
    example = (drop / "SCOPE.example.yaml").read_text(encoding="utf-8")
    lab = example.replace(EXPIRED_START, start).replace(EXPIRED_END, end)
    header = (
        "# Lab-only SCOPE. Generated window (now-1d .. now+30d). Not a customer pack.\n"
        "# allow_live_exec stays false. Do not treat as live-eligible.\n"
    )
    if not lab.startswith("# Lab-only"):
        lab = header + lab
    (drop / "SCOPE.lab.yaml").write_text(lab, encoding="utf-8")
    external = (drop / "SCOPE.external.yaml").read_text(encoding="utf-8")
    ext = external.replace(EXPIRED_START, start).replace(EXPIRED_END, end)
    (drop / "SCOPE.external.lab.yaml").write_text(
        "# Lab-only external SCOPE. Generated window. Not a customer pack.\n" + ext,
        encoding="utf-8",
    )
