"""prior-unit: deterministic run_id stamp (synthetic 10.0.0.x inputs only)."""
from __future__ import annotations

from pathlib import Path

import shared.estate_pages as ep
from shared.estate_pages import classify_estate, NOT_RECORDED


def test_deterministic_run_id_from_inputs_stable(tmp_path: Path) -> None:
    assert hasattr(ep, "deterministic_run_id_from_inputs"), "run_id producer missing"
    fn = ep.deterministic_run_id_from_inputs
    d = tmp_path / "in"
    (d / "nmap").mkdir(parents=True)
    (d / "nmap" / "scan.xml").write_text(
        '<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.9"/></host></nmaprun>\n',
        encoding="utf-8",
    )
    (d / "LAB.txt").write_text("LAB/DEMO synthetic\n", encoding="utf-8")
    a = fn(d, collected_at="2026-01-01T00:00:00Z")
    b = fn(d, collected_at="2026-01-01T00:00:00Z")
    assert a != NOT_RECORDED
    assert a == b
    assert len(a) == 12
    assert all(c in "0123456789abcdef" for c in a)
    # different content → different id
    (d / "nmap" / "scan.xml").write_text(
        '<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.10"/></host></nmaprun>\n',
        encoding="utf-8",
    )
    c = fn(d, collected_at="2026-01-01T00:00:00Z")
    assert c != a
    # classify_estate honors explicit run_id
    stamp = classify_estate([], run_id=a)
    assert stamp.run_id == a
