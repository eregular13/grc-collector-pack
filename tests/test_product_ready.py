from __future__ import annotations

import socket
from pathlib import Path

import pytest

from tests.test_product import ESTATE_MAPPED_CLASSES, _assert_simplerisk_estate_rows

ROOT = Path(__file__).resolve().parents[1]
SLUG_POAM = ROOT / "engagements" / "docker-estate-product" / "out" / "poam" / "poam.csv"
READY_ZIP = ROOT / "engagements" / "engagement-docker-estate-product-ready.zip"


def _estate_web_up() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 18081), timeout=1):
            return True
    except OSError:
        return False


def test_quickstart_and_estate_docs() -> None:
    qs = (ROOT / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
    assert "dropbox.product_demo --help" in qs
    assert ".venv\\Scripts\\python.exe" in qs or '.venv/Scripts/python.exe' in qs
    assert "docker compose -f docker-compose.estate.yml up -d" in qs
    assert r"C:\Users\R" not in qs
    assert "skip `docker compose -f docker-compose.estate.yml up -d`" in qs
    assert "192.168.10.0/24" in qs
    assert "Never compose c11" in qs
    assert r"C:\GRC Collector\grc-collector-pack" not in qs
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
    """run_lab overwrites pack out/poam with fixture SMBv1; slug dir+zip keep estate rows."""
    SLUG_POAM.parent.mkdir(parents=True, exist_ok=True)
    header = "weakness,asset,severity,control_refs,recommended_action,owner,milestone,status\n"
    prior = SLUG_POAM.read_text(encoding="utf-8") if SLUG_POAM.is_file() else ""
    if "Cleartext HTTP" not in prior:
        rows = "".join(
            f"{name},127.0.0.1,medium,CPG 2.W;PR.DS-02,fix,,,open\n" for name in ESTATE_MAPPED_CLASSES
        )
        SLUG_POAM.write_text(header + rows, encoding="utf-8")
    slug_before = SLUG_POAM.read_text(encoding="utf-8")
    ready_before = READY_ZIP.read_bytes() if READY_ZIP.is_file() else None
    dated = {
        p: p.read_bytes()
        for p in (ROOT / "engagements").glob("engagement-docker-estate-product-20*.zip")
        if p.is_file()
    }
    pack_poam = ROOT / "out" / "poam" / "poam.csv"
    pack_poam.parent.mkdir(parents=True, exist_ok=True)
    pack_poam.write_text(
        header + "SMBv1 / TCP 445 exposed,10.0.0.9,high,CPG 2.H,Disable SMBv1,,,open\n",
        encoding="utf-8",
    )
    after = SLUG_POAM.read_text(encoding="utf-8")
    assert after == slug_before
    assert "Cleartext HTTP" in after
    assert "SMBv1" not in after
    for name in ESTATE_MAPPED_CLASSES:
        if name in slug_before:
            assert name in after
    if ready_before is not None:
        assert READY_ZIP.read_bytes() == ready_before
    for path, blob in dated.items():
        assert path.read_bytes() == blob
    assert "SMBv1" in pack_poam.read_text(encoding="utf-8")


def test_live_slug_zip_simplerisk_has_folded_rows() -> None:
    """Host lab: newest/ready zip SimpleRisk CSV has folded classes. Skip on CI with no zip."""
    from dropbox.package_engagement import slug_zip_simplerisk

    dated = sorted(
        p
        for p in (ROOT / "engagements").glob("engagement-docker-estate-product-20*.zip")
        if p.is_file() and p.stat().st_size > 64
    )
    if READY_ZIP.is_file() and READY_ZIP.stat().st_size > 64:
        zpath = READY_ZIP
    elif dated:
        zpath = dated[-1]
    else:
        pytest.skip("no slug zip on disk")
    try:
        blob = slug_zip_simplerisk(zpath, "docker-estate-product")
    except KeyError:
        pytest.skip("zip has no simplerisk CSV")
    _assert_simplerisk_estate_rows(blob)
    slug_sr = ROOT / "engagements" / "docker-estate-product" / "out" / "simplerisk" / "risks_import.csv"
    if slug_sr.is_file():
        _assert_simplerisk_estate_rows(slug_sr.read_text(encoding="utf-8"))


def test_live_slug_zip_poam_has_folded_rows() -> None:
    """Host lab: newest/ready zip POA&M has folded classes. Skip on CI with no zip."""
    from dropbox.package_engagement import slug_zip_poam

    dated = sorted(
        p
        for p in (ROOT / "engagements").glob("engagement-docker-estate-product-20*.zip")
        if p.is_file() and p.stat().st_size > 64
    )
    if READY_ZIP.is_file() and READY_ZIP.stat().st_size > 64:
        zpath = READY_ZIP
    elif dated:
        zpath = dated[-1]
    else:
        pytest.skip("no slug zip on disk")
    try:
        poam = slug_zip_poam(zpath, "docker-estate-product")
    except KeyError:
        pytest.skip("zip has no poam.csv")
    for name in ESTATE_MAPPED_CLASSES:
        assert name in poam
    assert "SMBv1" not in poam
    assert "UNMAPPED" not in poam


@pytest.mark.skipif(not _estate_web_up(), reason="estate-web :18081 down (CI / cold host)")
def test_live_estate_web_answers() -> None:
    import dropbox.product_demo as demo

    assert demo.estate_up() is True
