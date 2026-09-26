"""product-lab/drop ships OpenGRC CSVs + Probo drafts (file-true, posted=false).

The packaged copy must match /export.zip sinks. Demo fixtures ≠ LAB dest_in ≠ client.
Never POST /api/risks. Not live OpenGRC/Probo import.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from product.server import build_drop_zip

ROOT = Path(__file__).resolve().parents[1]
DROP = ROOT / "product-lab" / "drop"
MANIFEST = DROP / "MANIFEST"
ROW = re.compile(r"\|\s*(\S+\.\S+)\s*\|\s*(\d+|draft)\s*\|\s*`([0-9a-f]{64})`\s*\|")


def test_product_lab_drop_has_opengrc_wizard_csvs_posted_false() -> None:
    dest = DROP / "opengrc"
    for name in ("risks.csv", "assets.csv", "implementations.csv", "MANIFEST.json", "README.md"):
        assert (dest / name).is_file(), name
    manifest = json.loads((dest / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["posted"] is False
    assert manifest["http"] is False
    assert manifest["client"] is False
    assert manifest["paying_day"] == "FAIL"
    assert manifest["sink"] == "opengrc"
    assert manifest["counts"]["risks"] >= 1
    assert manifest["counts"]["assets"] >= 1
    assert manifest["counts"]["implementations"] >= 1
    # Packaged drop is demo fixtures (empty in/), not a LAB dest_in prove.
    assert manifest.get("sample") is True
    assert manifest.get("lab") in {False, None}
    with (dest / "risks.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows
    assert "code" in rows[0]
    assert "name" in rows[0]
    assert rows[0]["status"] == "Not Assessed"
    readme = (dest / "README.md").read_text(encoding="utf-8")
    assert "posted=false" in readme.lower()
    assert "/api/risks" not in readme
    assert "SAMPLE/DEMO" in readme
    assert "LAB/DEMO" not in readme
    risks_blob = (dest / "risks.csv").read_text(encoding="utf-8")
    assert "/api/risks" not in risks_blob
    assert "SAMPLE/DEMO" in risks_blob


def test_product_lab_drop_has_probo_drafts_posted_false() -> None:
    path = DROP / "import_preview" / "probo.json"
    assert path.is_file()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["posted"] is False
    assert payload["http"] is False
    assert payload["client"] is False
    assert payload["paying_day"] == "FAIL"
    assert payload["organization_id"] is None
    assert payload["documentation_only"] is True
    assert payload.get("sample") is True
    assert payload.get("lab") in {False, None}
    assert payload["counts"]["addFinding"] >= 1
    assert all(row.get("posted") is False for row in payload.get("addFinding") or [])
    assert all(row.get("organization_id") is None for row in payload.get("addFinding") or [])
    assert (DROP / "probo" / "README.md").is_file()
    text = path.read_text(encoding="utf-8")
    assert "/api/risks" not in text
    readme = (DROP / "probo" / "README.md").read_text(encoding="utf-8")
    assert "posted=false" in readme.lower()
    assert "/api/risks" not in readme


def test_product_lab_drop_manifest_lists_opengrc_probo_hashes() -> None:
    text = MANIFEST.read_text(encoding="utf-8")
    assert "opengrc/risks.csv" in text
    assert "opengrc/assets.csv" in text
    assert "opengrc/implementations.csv" in text
    assert "import_preview/probo.json" in text
    assert "posted=false" in text.lower() or "posted=false" in text.replace(" ", "").lower()
    assert "/api/risks" in text  # stay-out line
    rows = {rel: (count, digest) for rel, count, digest in ROW.findall(text)}
    for rel in (
        "opengrc/risks.csv",
        "opengrc/assets.csv",
        "opengrc/implementations.csv",
        "import_preview/probo.json",
    ):
        assert rel in rows, rel
        path = DROP / rel
        assert path.is_file(), rel
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        assert got == rows[rel][1], f"{rel} hash drift vs MANIFEST"


def test_product_lab_drop_readme_documents_opengrc_probo() -> None:
    readme = (DROP / "README.md").read_text(encoding="utf-8")
    assert "opengrc" in readme.lower()
    assert "probo" in readme.lower()
    assert "posted=false" in readme.lower()
    assert "/api/risks" in readme
    assert "not live" in readme.lower() or "file-true" in readme.lower() or "file-only" in readme.lower()
    op = (ROOT / "product-lab" / "OPERATOR.md").read_text(encoding="utf-8")
    assert "opengrc" in op.lower()
    assert "probo" in op.lower()
    assert "posted=false" in op.lower()


def test_drop_zip_includes_packaged_opengrc_when_out_lacks_sinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LAB run: offline packaged copy rides in /export.zip under product-lab/drop/.

    Non-LAB runs fail closed (tests/test_console_sink_failclosed.py).
    """
    out = tmp_path / "empty-out"
    out.mkdir()
    (out / "summary.json").write_text('{"lab": true}', encoding="utf-8")
    monkeypatch.setenv("OUT_DIR", str(out))
    blob = build_drop_zip()
    assert blob[:2] == b"PK"
    with zipfile.ZipFile(BytesIO(blob)) as zf:
        names = set(zf.namelist())
        import_md = zf.read("IMPORT.md").decode("utf-8")
    assert "product-lab/drop/opengrc/risks.csv" in names
    assert "product-lab/drop/opengrc/assets.csv" in names
    assert "product-lab/drop/opengrc/implementations.csv" in names
    assert "product-lab/drop/import_preview/probo.json" in names
    assert "OpenGRC" in import_md
    assert "Probo" in import_md
    assert "Do not POST /api/risks" in import_md
    assert "posted=false" in import_md.lower()
