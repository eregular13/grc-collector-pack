"""Fail-before/pass-after: pq6 ELAPSED START is clock-safe (pr-pq6-test-uptime).

After a-pq6-behavior-tests, the helper hardcodes a large START that fails on
hosts with short uptime when scripts use CLOCK_MONOTONIC semantics. Unit
defaults START from time.perf_counter so nested-quote paths still trip tip
bugs without requiring multi-day uptime.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pq6_behavior_helper_uses_clock_safe_default_start() -> None:
    path = ROOT / "tests" / "test_pr_a_pq6_behavior.py"
    assert path.is_file(), f"missing {path} (need a-pq6-behavior-tests prefix)"
    text = path.read_text(encoding="utf-8")
    assert "import time" in text or "from time import" in text, (
        "expected time import for clock-safe START default"
    )
    # Default start must come from perf_counter (not only a huge hardcode)
    assert "perf_counter" in text, (
        "expected time.perf_counter-based default START after pq6-uptime unit"
    )
    # Must not require the historic multi-day hardcode as the only path
    assert re.search(r"start\s*=\s*None|if start is None", text), (
        "expected optional/None start defaulting to clock-safe value"
    )
