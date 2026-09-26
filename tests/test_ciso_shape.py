"""Risk-register + POA&M shape: columns, not CSV counts. SAMPLE != client."""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.ciso_shape import (
    CISO_HEADERS,
    CVE_CLASS_CSV,
    FINDING_SEV,
    MUST_EXIST_CSVS,
    POAM_HEADER,
    REGISTER_CSVS,
    REGISTER_OK_LINE,
    RegisterShapeError,
    assert_ciso_register,
    assert_poam_for_findings,
    assert_risk_register_and_poam,
    first_nonempty_line,
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
    for name in MUST_EXIST_CSVS:
        first = first_nonempty_line(ciso / name)
        assert first == CISO_HEADERS[name]
    poam = tmp_path / "out" / "poam" / "poam.csv"
    assert first_nonempty_line(poam) == POAM_HEADER
    assert (tmp_path / "out" / "poam" / "poam.md").is_file()
    assert "risk_scenarios.csv" in REGISTER_CSVS
    assert CVE_CLASS_CSV not in REGISTER_CSVS


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
    for name in MUST_EXIST_CSVS:
        (ciso / name).write_text("ref_id,name\nDEMO-1,sample\n", encoding="utf-8")
    with pytest.raises(RegisterShapeError, match="header mismatch"):
        assert_risk_register_and_poam(tmp_path / "out")


def test_assert_register_fails_when_findings_without_risk_scenarios(tmp_path: Path) -> None:
    ciso = tmp_path / "out" / "ciso-assistant"
    write_minimal_register(ciso, with_poam=True)
    (ciso / "risk_scenarios.csv").write_text(
        CISO_HEADERS["risk_scenarios.csv"] + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RegisterShapeError, match="risk_scenarios"):
        assert_ciso_register(ciso)


def test_header_only_vulns_are_allowed_cve_class_gap(tmp_path: Path) -> None:
    """pack_drop exposure is not CVE-class. Vulns may be header-only; scenarios are the register."""
    ciso = tmp_path / "out" / "ciso-assistant"
    write_minimal_register(ciso, with_poam=True)
    (ciso / CVE_CLASS_CSV).write_text(CISO_HEADERS[CVE_CLASS_CSV] + "\n", encoding="utf-8")
    shape = assert_risk_register_and_poam(tmp_path / "out")
    assert shape["vulnerabilities"] == 0
    assert shape["risk_scenarios"] >= 1
    assert shape["findings"] >= 1
    assert shape["vulns_cve_class_only"] is True


def test_schema_doc_lists_register_and_poam_columns() -> None:
    doc = (ROOT / "schemas" / "ciso-assistant.md").read_text(encoding="utf-8")
    for header in (
        CISO_HEADERS["assets.csv"],
        CISO_HEADERS["findings.csv"],
        CISO_HEADERS["vulnerabilities.csv"],
        CISO_HEADERS["applied_controls.csv"],
        CISO_HEADERS["risk_scenarios.csv"],
        POAM_HEADER,
    ):
        assert header in doc
    assert FINDING_SEV == {"low", "medium", "high", "critical"}
    assert "header-only" in doc
    assert "findings.csv` + `risk_scenarios.csv" in doc or "findings.csv + risk_scenarios.csv" in doc
