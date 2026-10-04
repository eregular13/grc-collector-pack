"""Pack text writers must not use platform newlines.

MANIFEST / .md / ESTATE.txt / json stay LF so ``sha256sum -c MANIFEST``
and ``python scripts/verify_manifest.py`` agree on Windows and Linux.
CSVs keep the csv module terminator the pack already emits on Linux (LF
via lineterminator='\\n' + open newline='').
"""

from __future__ import annotations

import ast
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.verify_manifest import verify_manifest
from shared.asset_ledger import AssetLedger
from shared.estate_pages import (
    EstateStamp,
    PageContext,
    write_client_pages,
    write_estate_sidecar,
    write_export_manifest,
)
from shared.io_util import write_json, write_text
from shared.poam_ledger import empty_ledger, persist_ledger

ROOT = Path(__file__).resolve().parents[1]

PACK_WRITER_MODULES = (
    ROOT / "shared" / "io_util.py",
    ROOT / "shared" / "estate_pages.py",
    ROOT / "shared" / "poam_ledger.py",
    ROOT / "shared" / "asset_ledger.py",
    ROOT / "shared" / "drop_manifest.py",
    ROOT / "shared" / "kev.py",
    ROOT / "collectors" / "grc_loader.py",
    ROOT / "exporters" / "opengrc.py",
    ROOT / "exporters" / "probo.py",
    ROOT / "scripts" / "prove_ciso.py",
    ROOT / "scripts" / "refresh_product_lab_drop_sinks.py",
    ROOT / "scripts" / "verify_manifest.py",
)


def _write_text_calls_missing_newline(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "write_text":
            continue
        names = {kw.arg for kw in node.keywords if kw.arg}
        if "newline" not in names:
            hits.append(f"{path.name}:{node.lineno}")
    return hits


def test_pack_write_text_calls_set_newline() -> None:
    missing: list[str] = []
    for path in PACK_WRITER_MODULES:
        assert path.is_file(), path
        missing.extend(_write_text_calls_missing_newline(path))
    assert missing == [], f"pack writers missing newline=: {missing}"


def test_writers_stay_lf_when_linesep_is_crlf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "linesep", "\r\n")
    out = tmp_path / "out"
    out.mkdir()
    stamp = EstateStamp(
        kind="LAB",
        label="LAB: TEST ENVIRONMENT",
        sentence="From scans of an Evergreen-controlled test environment.",
    )
    write_text(out / "LAB.txt", "LAB/DEMO -- not a client estate.\n")
    write_json(out / "summary.json", {"lab": True, "poam": 1})
    write_estate_sidecar(out / "ciso-assistant", stamp)
    ctx = PageContext(
        stamp=stamp,
        records=[],
        findings=[],
        poam_rows=[],
        mapped_by_ref={},
        findings_csv_n=0,
        vuln_n=0,
        risk_n=0,
        poam_n=0,
        merged="0",
        generated_at=datetime(2026, 10, 3, 20, 30, tzinfo=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    )
    write_client_pages(out, ctx)
    persist_ledger(empty_ledger(), out)
    AssetLedger().save(out / "assets" / "asset-ledger.json")
    (out / "ciso-assistant").mkdir(exist_ok=True)
    write_export_manifest(out)

    for path in (
        out / "LAB.txt",
        out / "summary.json",
        out / "ciso-assistant" / "ESTATE.txt",
        out / "EXECUTIVE_SUMMARY.md",
        out / "SCOPE_AND_TRUST.md",
        out / "MANIFEST",
        out / "poam" / "poam-ledger.json",
        out / "assets" / "asset-ledger.json",
    ):
        raw = path.read_bytes()
        assert raw, path
        assert b"\r\n" not in raw, f"{path.name} used platform CRLF"
        assert b"\n" in raw

    ok = verify_manifest(out)
    assert ok
    assert any(line.endswith(": OK") for line in ok)


def test_csv_writer_keeps_linux_lf_terminator(tmp_path: Path) -> None:
    from collectors.grc_loader import _write_csv

    path = tmp_path / "row.csv"
    _write_csv(path, ["a", "b"], [["1", "2"]])
    raw = path.read_bytes()
    assert raw == b"a,b\n1,2\n"
    assert b"\r\n" not in raw
