"""Behavior FBPA: pr-b testssl PQ-2 grade rows must not emit as findings.

Tip entrypoint: shared.testssl._emit — synthetic dict only (no lab data).
Fail-before = overall_grade still emitted; not ImportError/symbol presence.
"""
from __future__ import annotations

from shared.testssl import _emit


def test_overall_grade_row_is_dropped() -> None:
    row = {
        "id": "overall_grade",
        "severity": "high",
        "finding": "A+",
        "ip": "203.0.113.20",
        "targetHost": "dev-api.example.com",
    }
    out = _emit(row, "dev-api.example.com", ip="203.0.113.20")
    assert out is None, f"overall_grade must be dropped at emit, got={out!r}"


def test_real_vuln_id_still_emits() -> None:
    row = {
        "id": "heartbleed",
        "severity": "high",
        "finding": "vulnerable",
        "ip": "203.0.113.20",
        "targetHost": "dev-api.example.com",
    }
    out = _emit(row, "dev-api.example.com", ip="203.0.113.20")
    assert out is not None
    assert out.get("id") == "heartbleed"
