"""CISO Assistant: Extra Import CSVs; live assets+evidences only with dual gate."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from push.common import PACK, refuse_live_without_gate

CISO_DIR = PACK / "out" / "ciso-assistant"
AUTO = ("assets.csv", "evidences.csv")
HITL = (
    "applied_controls.csv",
    "findings.csv",
    "vulnerabilities.csv",
    "risk_scenarios.csv",
)
IMPORTER = "/api/importer/"


def _url() -> str:
    return os.environ.get("CISO_URL", "http://127.0.0.1:8000").rstrip("/")


def plan() -> dict[str, Any]:
    files = [p.name for p in CISO_DIR.glob("*.csv")] if CISO_DIR.is_dir() else []
    return {
        "target": "ciso",
        "dry_run": True,
        "endpoint": _url() + IMPORTER,
        "method": "POST multipart file= (assets.csv, evidences.csv only)",
        "auto_files": [str(CISO_DIR / n) for n in AUTO],
        "hitl_files": [str(CISO_DIR / n) for n in HITL],
        "poam": str(PACK / "out" / "poam" / "poam.csv"),
        "csv_present": files,
        "note": "Findings Extra Import / clica. Do not invent FindingsAssessment UUIDs. No findings POST.",
        "http": False,
    }


def _post_file(url: str, token: str, path: Path) -> int:
    data = path.read_bytes()
    boundary = "----grcpackciso"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        "Content-Type: text/csv\r\n\r\n"
    ).encode("utf-8") + data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    req = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Token {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    with urlopen(req, timeout=20) as resp:
        return int(resp.status)


def live() -> dict[str, Any]:
    refuse_live_without_gate("ciso")
    token = (os.environ.get("CISO_TOKEN") or "").strip()
    url = (os.environ.get("CISO_URL") or "").strip()
    if not token or not url:
        raise SystemExit(2)
    posted: list[str] = []
    for name in AUTO:
        path = CISO_DIR / name
        if not path.is_file():
            continue
        _post_file(_url() + IMPORTER, token, path)
        posted.append(name)
    rec = plan()
    rec["dry_run"] = False
    rec["http"] = True
    rec["posted"] = posted
    rec["hitl_remaining"] = list(HITL)
    return rec
