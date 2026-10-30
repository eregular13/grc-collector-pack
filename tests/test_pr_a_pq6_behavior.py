"""Behavior: sample_to_sor.sh ELAPSED path must compute with START (pr-a pq6). No source-text grep."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]


def _elapsed_lines(script: Path) -> list[str]:
    lines = []
    for ln in script.read_text(encoding="utf-8").splitlines():
        if re.match(r"^\s*ELAPSED=", ln):
            lines.append(ln)
    return lines


def _run_elapsed(script: Path, start: str | None = None) -> subprocess.CompletedProcess[str]:
    # CLOCK_MONOTONIC ~ uptime; hardcoding 231659 fails on hosts up < ~2.7d.
    # Keep many-decimal string so nested-quote / expansion paths still trip tip bug.
    if start is None or start == "":
        start = f"{(time.perf_counter() - 0.25):.12f}"
    els = _elapsed_lines(script)
    assert els, f"no ELAPSED= assignment in {script}"
    elapsed_line = els[-1]
    bash = f"""set -euo pipefail
PYTHON="${{PYTHON:-python3}}"
START="{start}"
{elapsed_line}
ELAPSED_VAL="$ELAPSED"
echo "ELAPSED_OUT=$ELAPSED_VAL"
python3 -c 'import sys
v=sys.argv[1]
float(v)
assert float(v) >= 0.0
print("PARSED_OK", v)' "$ELAPSED_VAL"
"""
    env = dict(os.environ)
    env.setdefault("PYTHON", "python3")
    return subprocess.run(
        ["bash", "-c", bash],
        cwd=str(ROOT),
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )


def test_sample_to_sor_elapsed_line_executes_with_start() -> None:
    """Execute the script's ELAPSED assignment with a START that trips nested-quote bug."""
    script = ROOT / "scripts" / "sample_to_sor.sh"
    assert script.is_file()
    r = _run_elapsed(script)  # clock-safe multi-decimal START
    assert r.returncode == 0, (
        f"ELAPSED path failed rc={r.returncode}\n"
        f"stdout={r.stdout!r}\nstderr={r.stderr!r}\n"
        f"(tip nested float('$START') breaks; pr-a sys.argv form must pass)"
    )
    assert "ELAPSED_OUT=" in r.stdout
    assert "PARSED_OK" in r.stdout


def test_farm_drop_to_sor_elapsed_line_executes_with_start() -> None:
    script = ROOT / "scripts" / "farm_drop_to_sor.sh"
    assert script.is_file()
    r = _run_elapsed(script)  # clock-safe START; "99.001" failed on hosts up < ~99 s
    assert r.returncode == 0, (
        f"farm ELAPSED path failed rc={r.returncode}\n"
        f"stdout={r.stdout!r}\nstderr={r.stderr!r}"
    )
    assert "PARSED_OK" in r.stdout


def test_run_elapsed_default_is_clock_safe_not_hardcoded_uptime() -> None:
    """Pin pq6-test-uptime: default START must be clock-derived."""
    path = ROOT / "tests" / "test_pr_a_pq6_behavior.py"
    assert path.is_file(), path
    text = path.read_text(encoding="utf-8")
    head, _, _ = text.partition("def test_run_elapsed_default_is_clock_safe")
    bad = "start=\"" + "231659.507327568" + "\""
    assert bad not in head, (
        "hardcoded multi-day START still present "
        "(fails on hosts with CLOCK_MONOTONIC uptime < ~2.7d)"
    )
    clock = ("time." + "perf_counter") in head or ("time." + "monotonic") in head
    assert clock, "expected clock-safe START via time.perf_counter/monotonic"


def test_elapsed_line_uses_sys_argv_not_nested_start_float() -> None:
    """Pin the pq6 form: ELAPSED python must take START via sys.argv, not float('$START')."""
    for rel in ("scripts/sample_to_sor.sh", "scripts/farm_drop_to_sor.sh"):
        script = ROOT / rel
        assert script.is_file(), rel
        joined = "\n".join(_elapsed_lines(script))
        assert "sys.argv" in joined, f"{rel}: ELAPSED must use sys.argv (pq6 form)\n{joined}"
        assert "float('$START')" not in joined and 'float("$START")' not in joined, (
            f"{rel}: nested float('$START') still present (pre-pq6 bug)\n{joined}"
        )


def test_run_elapsed_default_is_clock_safe_not_hardcoded_uptime() -> None:
    """Pin pq6-test-uptime: default START must be clock-derived."""
    path = ROOT / "tests" / "test_pr_a_pq6_behavior.py"
    assert path.is_file(), path
    text = path.read_text(encoding="utf-8")
    head, _, _ = text.partition("def test_run_elapsed_default_is_clock_safe")
    bad = "start=\"" + "231659.507327568" + "\""
    assert bad not in head, (
        "hardcoded multi-day START still present "
        "(fails on hosts with CLOCK_MONOTONIC uptime < ~2.7d)"
    )
    clock = ("time." + "perf_counter") in head or ("time." + "monotonic") in head
    assert clock, "expected clock-safe START via time.perf_counter/monotonic"

