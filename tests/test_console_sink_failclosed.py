"""CONSOLE_SINK_FAILCLOSED: packaged product-lab/drop sinks never pass as a run's own.

- The SAMPLE packaged pill shows whenever any sink source is product-lab/drop
  (lab or not).
- /export.zip only ships packaged product-lab/drop files for LAB runs; a
  non-LAB run fails closed and IMPORT.md says so.
"""

from __future__ import annotations

import json
import re
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from product.server import ROOT, build_drop_zip, estate

JS = ROOT / "product" / "static" / "app.js"


def _pill_fn() -> str:
    js = JS.read_text(encoding="utf-8")
    match = re.search(r"function applySinkSamplePill\(estate\) \{(.*?)\n\}", js, re.S)
    assert match, "applySinkSamplePill missing"
    return match.group(1)


def test_sample_pill_not_gated_on_lab() -> None:
    body = _pill_fn()
    assert "product-lab/drop" in body
    assert "estate.lab" not in body, "pill must show for packaged sinks even when estate.lab is false"
    assert re.search(r"const show = packaged;", body), body


def _names(blob: bytes) -> tuple[set[str], str]:
    with zipfile.ZipFile(BytesIO(blob)) as zf:
        return set(zf.namelist()), zf.read("IMPORT.md").decode("utf-8")


def test_non_lab_export_zip_excludes_packaged_drop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "summary.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["lab"] is False
    # Console still falls back for KPIs, but labels the source packaged (pill shows).
    assert data["opengrc"]["source"] == "product-lab/drop"
    names, import_md = _names(build_drop_zip())
    assert not [n for n in names if n.startswith("product-lab/")], sorted(names)
    assert "packaged SAMPLE sinks excluded" in import_md


def test_sample_run_export_zip_excludes_packaged_drop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "summary.json").write_text(json.dumps({"sample": True, "demo": True}), encoding="utf-8")
    monkeypatch.setenv("OUT_DIR", str(out))
    names, _ = _names(build_drop_zip())
    assert not [n for n in names if n.startswith("product-lab/")]


def test_lab_export_zip_keeps_packaged_drop_labeled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "summary.json").write_text(json.dumps({"lab": True}), encoding="utf-8")
    monkeypatch.setenv("OUT_DIR", str(out))
    names, import_md = _names(build_drop_zip())
    assert "product-lab/drop/opengrc/risks.csv" in names
    assert "SAMPLE packaged" in import_md
