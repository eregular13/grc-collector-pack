"""Generated client leave-behinds must not carry Pentera marketing or RiskReady.

Cold-review-4 leftovers lived in the console, drop zip README, product-lab/drop,
and DEMO simplerisk/lab-report templates. CHANGELOG historical notes stay.
LAB/SAMPLE/DEMO honesty banners and 'Do not POST /api/risks' stay.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from collectors import grc_loader
from product.server import build_drop_zip

ROOT = Path(__file__).resolve().parents[1]
DROP = ROOT / "product-lab" / "drop"

CLIENT_SOURCES = (
    ROOT / "product" / "static" / "index.html",
    ROOT / "product" / "server.py",
    ROOT / "scripts" / "refresh_product_lab_drop_sinks.py",
    ROOT / "dropbox" / "EXECUTIVE.md",
    ROOT / "product-lab" / "drop" / "README.md",
    ROOT / "product-lab" / "drop" / "MANIFEST",
    ROOT / "product-lab" / "drop" / "poam" / "poam.md",
    ROOT / "collectors" / "grc_loader.py",
)


def test_listed_client_sources_have_no_pentera_slogan() -> None:
    for path in CLIENT_SOURCES:
        text = path.read_text(encoding="utf-8")
        assert "Pentera" not in text, path
        assert "Evergreen maps it" not in text, path


def test_packaged_drop_client_paths_have_no_pentera_or_riskready() -> None:
    """Narrative leave-behinds in the packaged drop (not operator STATUS/CHANGELOG)."""
    paths = [
        DROP / "README.md",
        DROP / "MANIFEST",
        DROP / "poam" / "poam.md",
        DROP / "opengrc" / "README.md",
        DROP / "probo" / "README.md",
    ]
    hits: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if "Pentera" in text or "RiskReady" in text:
            hits.append(str(path.relative_to(ROOT)))
    assert hits == []


def test_loader_simplerisk_and_lab_report_omit_riskready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    rec = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-demo-21",
        "name": "FTP exposed",
        "description": "open TCP/21",
        "severity": "high",
        "category": "exposure",
        "assets": ["lab-host"],
        "labels": ["nmap"],
        "extra": {"port": "21", "service": "ftp"},
    }
    asset = {
        "kind": "asset",
        "source": "inventory-nmap",
        "ref_id": "asset-lab-host",
        "name": "lab-host",
        "description": "lab host",
        "severity": "info",
        "category": "host",
        "assets": ["lab-host"],
        "labels": ["nmap"],
        "extra": {"asset_type": "PR"},
    }
    with (out / "canonical" / "inventory-nmap.jsonl").open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(asset) + "\n")
        fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "DEMO")
    importlib.reload(grc_loader)
    grc_loader.load()
    sr = (out / "simplerisk" / "README.md").read_text(encoding="utf-8")
    report = (out / "evidence" / "lab-report.md").read_text(encoding="utf-8")
    assert "DEMO" in sr or "NOT A CLIENT" in sr
    assert "Never POST /api/risks" in sr
    assert "Never POST /api/risks" in report or "No /api/risks POST" in report
    for text, label in ((sr, "simplerisk/README.md"), (report, "evidence/lab-report.md")):
        assert "Pentera" not in text, label
        assert "RiskReady" not in text, label


def test_export_zip_readme_omits_pentera_and_riskready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "summary.json").write_text('{"lab": true}', encoding="utf-8")
    monkeypatch.setenv("OUT_DIR", str(out))
    import zipfile
    from io import BytesIO

    blob = build_drop_zip()
    with zipfile.ZipFile(BytesIO(blob)) as zf:
        readme = zf.read("IMPORT.md").decode("utf-8")
    assert "Do not POST /api/risks" in readme
    assert "Pentera" not in readme
    assert "RiskReady" not in readme
    assert "Evergreen maps it" not in readme
