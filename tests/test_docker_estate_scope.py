from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_estate_cidr_is_not_lan_10() -> None:
    text = (ROOT / "dropbox" / "SCOPE.docker-estate.yaml").read_text(encoding="utf-8")
    assert "192.168.10.0/24" not in text
    assert "172.28.90.0/24" in text
    assert "pve2" not in text.lower()
    assert "allow_live_exec: true" in text
    assert "Evergreen Docker Estate LLC" in text
    assert "https://127.0.0.1:18443/" in text
    assert "http://127.0.0.1:18081/" in text


def test_estate_tls_sidecar_loopback_only() -> None:
    text = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "127.0.0.1:18443:443" in text
    assert "0.0.0.0:18443" not in text
    assert "estate-tls" in text
    conf = (ROOT / "estate" / "tls" / "default.conf").read_text(encoding="utf-8")
    assert "listen 443 ssl" in conf


def test_example_scope_still_not_live() -> None:
    text = (ROOT / "dropbox" / "SCOPE.example.yaml").read_text(encoding="utf-8")
    assert "allow_live_exec: true" not in text
    assert "allow_live_exec: false" in text
    assert "2026-09-05T09:00:00-07:00" in text


def test_push_scripts_still_wrap_dead() -> None:
    ps1 = (ROOT / "push_riskready.ps1").read_text(encoding="utf-8")
    assert "WRAP_DEAD" in ps1
    code = "\n".join(ln for ln in ps1.splitlines() if not ln.lstrip().startswith("#")).lower()
    assert "/api/risks" not in code
    sh = (ROOT / "push_riskready.sh").read_text(encoding="utf-8")
    assert "WRAP_DEAD" in sh
    sh_code = "\n".join(ln for ln in sh.splitlines() if not ln.lstrip().startswith("#")).lower()
    assert "/api/risks" not in sh_code
    ciso = (ROOT / "push_ciso.ps1").read_text(encoding="utf-8")
    assert "POST /api/risks" not in ciso
    assert "findings.csv" in ciso
    assert "HITL" in ciso or "clica" in ciso.lower()
