from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = (ROOT / ".env.example").read_text(encoding="utf-8")


def test_push_flags_default_zero() -> None:
    assert "CISO_PUSH=0" in ENV
    assert "RISKREADY_PUSH=0" in ENV
    assert "GRC_LIVE_SCAN=0" in ENV
    assert "DRY_RUN=1" in ENV


def test_no_post_api_risks() -> None:
    paths = [
        ROOT / "push_ciso.sh",
        ROOT / "push_riskready.sh",
        ROOT / "product" / "server.py",
        ROOT / "scripts" / "preview_probo.py",
        ROOT / "scripts" / "preview_rr.py",
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"curl[^\n]*/api/risks", text)
        assert "${API}/risks" not in text
        assert 'POST "/api/risks"' not in text


def test_collectors_do_not_open_sockets() -> None:
    banned = ("socket.socket", "urllib.request", "http.client", "requests.get", "httpx.")
    for py in (ROOT / "collectors").glob("*.py"):
        src = py.read_text(encoding="utf-8")
        for token in banned:
            assert token not in src, f"{py.name} contains {token}"


def test_outputs_redact_when_present() -> None:
    out = ROOT / "out"
    if not out.exists():
        return
    pat = re.compile(r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----")
    for path in out.rglob("*"):
        if path.is_file() and path.suffix in {".csv", ".json", ".jsonl", ".md"}:
            text = path.read_text(encoding="utf-8", errors="replace")
            assert not pat.search(text), path
