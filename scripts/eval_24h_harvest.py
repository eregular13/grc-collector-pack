"""Harvest loopback eval-estate headers. Not a LAN scan. Not 192.168.10.0/24."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PT = timezone(timedelta(hours=-7))
PACK = Path(__file__).resolve().parents[1]
OUT = PACK.parent / "product-lab" / "24h" / "eval"
URLS = (
    "http://127.0.0.1:18181/",
    "http://127.0.0.1:18182/",
    "http://127.0.0.1:18183/",
    "https://127.0.0.1:18143/",
    "http://127.0.0.1:18180/health",
    "http://127.0.0.1:18081/",
    "http://127.0.0.1:18082/",
    "https://127.0.0.1:18443/",
)


def _head(url: str) -> dict[str, object]:
    exe = "curl.exe" if sys.platform.startswith("win") else "curl"
    cmd = [exe, "-sS", "-I", "--max-time", "5", "--max-redirs", "0"]
    if url.lower().startswith("https://"):
        cmd.append("-k")
    cmd.extend(["--", url])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False, shell=False)
    return {
        "url": url,
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "")[:2000],
        "stderr": (proc.stderr or "")[:500],
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    rec = {
        "clock": datetime.now(PT).strftime("%Y-%m-%dT%H:%M:%S-07:00"),
        "note": "loopback harvest only; not 192.168.10.0/24; not c11",
        "probes": [_head(u) for u in URLS],
    }
    path = OUT / "harvest.json"
    path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "path": str(path), "n": len(rec["probes"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
