"""Risk-register + POA&M shape: columns, not CSV counts. SAMPLE != client."""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.ciso_shape import (
    CISO_HEADERS,
    FINDING_SEV,
    POAM_HEADER,
    REGISTER_CSVS,
    REGISTER_OK_LINE,
    RegisterShapeError,
    assert_poam_for_findings,
    assert_risk_register_and_poam,
    write_minimal_register,
)

ROOT = Path(__file__).resolve().parents[1]


def test_register_ok_line_is_ascii_cp1252() -> None:
    assert REGISTER_OK_LINE.isascii()
    REGISTER_OK_LINE.encode("cp1252")
    assert "\u2260" not in REGISTER_OK_LINE
    assert "\u2192" not in REGISTER_OK_LINE


def test_write_minimal_register_matches_schema_headers(tmp_path: Path) -> None:
    ciso = tmp_path / "out" / "ciso-assistant"
    write_minimal_register(ciso)
    shape = assert_risk_register_and_poam(tmp_path / "out")
    assert shape["ok"] is True
    assert shape["findings"] == 1
    assert shape["poam_rows"] == 1
    for name in REGISTER_CSVS:
        first = (ciso / name).read_text(encoding="utf-8").splitlines()[0].strip()
        assert first == CISO_HEADERS[name]
    poam = (tmp_path / "out" / "poam" / "poam.csv").read_text(encoding="utf-8")
    assert poam.splitlines()[0].strip() == POAM_HEADER


def test_assert_poam_fails_when_findings_exist_and_poam_empty(tmp_path: Path) -> None:
    ciso = tmp_path / "out" / "ciso-assistant"
    write_minimal_register(ciso, with_poam=True)
    poam = tmp_path / "out" / "poam" / "poam.csv"
    poam.write_text(POAM_HEADER + "\n", encoding="utf-8")
    with pytest.raises(RegisterShapeError, match="0 rows"):
        assert_poam_for_findings(tmp_path / "out", findings_count=1)


def test_assert_register_fails_on_count_only_theater(tmp_path: Path) -> None:
    """A CSV that merely exists (wrong columns) is not a risk register."""
    ciso = tmp_path / "out" / "ciso-assistant"
    ciso.mkdir(parents=True)
    for name in REGISTER_CSVS:
        (ciso / name).write_text("ref_id,name\nDEMO-1,sample\n", encoding="utf-8")
    with pytest.raises(RegisterShapeError, match="header mismatch"):
        assert_risk_register_and_poam(tmp_path / "out")


def test_schema_doc_lists_register_and_poam_columns() -> None:
    doc = (ROOT / "schemas" / "ciso-assistant.md").read_text(encoding="utf-8")
    for header in (
        CISO_HEADERS["assets.csv"],
        CISO_HEADERS["findings.csv"],
        CISO_HEADERS["vulnerabilities.csv"],
        CISO_HEADERS["applied_controls.csv"],
        POAM_HEADER,
    ):
        assert header in doc
    assert FINDING_SEV == {"low", "medium", "high", "critical"}
