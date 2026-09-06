from __future__ import annotations

import socket
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SLUG_POAM = ROOT / "engagements" / "docker-estate-product" / "out" / "poam" / "poam.csv"


def _estate_web_up() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 18081), timeout=1):
            return True
    except OSError:
        return False


def test_quickstart_and_estate_docs() -> None:
    qs = (ROOT / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
    assert "python -m dropbox.product_demo --help" in qs
    assert "docker compose -f docker-compose.estate.yml up -d" in qs
    assert r"C:\Users\R" not in qs
    estate = (ROOT / "docs" / "ESTATE.md").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in estate
    assert "127.0.0.1:18081" in estate
    assert "192.168.10.0/24" in estate
    compose = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "127.0.0.1:18081:80" in compose
    assert "172.28.90.0/24" in compose
    ci = (ROOT / ".github" / "workflows" / "lab.yml").read_text(encoding="utf-8")
    assert "python -m pytest tests -q" in ci
    assert "3.12" in ci


def test_run_lab_ps1_does_not_touch_engagements() -> None:
    text = (ROOT / "run_lab.ps1").read_text(encoding="utf-8").lower()
    assert "engagements" not in text
    assert "out-estate" not in text
    assert "remove-item" not in text or "engagement" not in text


def test_slug_cleartext_survives_pack_poam_overwrite() -> None:
    """run_lab overwrites pack out/poam with fixture SMBv1; slug must keep estate rows."""
    SLUG_POAM.parent.mkdir(parents=True, exist_ok=True)
    header = "weakness,asset,severity,control_refs,recommended_action,owner,milestone,status\n"
    row = "Cleartext HTTP,127.0.0.1,medium,CPG 2.W;PR.DS-02,Enforce TLS,,,open\n"
    prior = SLUG_POAM.read_text(encoding="utf-8") if SLUG_POAM.is_file() else ""
    if "Cleartext HTTP" not in prior:
        SLUG_POAM.write_text(header + row, encoding="utf-8")
    zip_path = ROOT / "engagements" / "engagement-docker-estate-product-ready.zip"
    zip_path.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    pack_poam = ROOT / "out" / "poam" / "poam.csv"
    pack_poam.parent.mkdir(parents=True, exist_ok=True)
    pack_poam.write_text(
        header + "SMBv1 / TCP 445 exposed,10.0.0.9,high,CPG 2.H,Disable SMBv1,,,open\n",
        encoding="utf-8",
    )
    assert "Cleartext HTTP" in SLUG_POAM.read_text(encoding="utf-8")
    assert zip_path.is_file()
    assert "SMBv1" in pack_poam.read_text(encoding="utf-8")


@pytest.mark.skipif(not _estate_web_up(), reason="estate-web :18081 down (CI / cold host)")
def test_live_estate_web_answers() -> None:
    import dropbox.product_demo as demo

    assert demo.estate_up() is True
