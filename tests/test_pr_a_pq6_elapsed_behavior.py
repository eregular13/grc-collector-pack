"""Fail-before/pass-after: sample/farm ELAPSED path (pr-a-pq6).

Tip nested float('$START') breaks under bare python3 when START has decimals.
Force PYTHON=python3 in the ELAPSED subprocess so the tip bug is observable
(runner env may otherwise point PYTHON at a full venv path that masks nesting).
After pr-a-pq6, sys.argv form must pass under the same PYTHON=python3.

START is derived from the live perf_counter (CLOCK_MONOTONIC on Linux, which
tracks uptime) instead of a hard-coded value, so the ELAPSED >= 0 assertion
holds on any host uptime, including a freshly booted CI runner. A hard-coded
START such as 231659.5 fails on any host up less than ~2.7 days.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _elapsed_lines(script: Path) -> list[str]:
    lines = []
    for ln in script.read_text(encoding="utf-8").splitlines():
        if re.match(r"^\s*ELAPSED=", ln):
            lines.append(ln)
    return lines


def _clock_start(back: float = 0.25) -> str:
    """Multi-decimal START taken from the same clock the script reads.

    Slightly in the past so ELAPSED is positive; clamped at 0 for hosts with
    near-zero monotonic time. Many decimals keep the tip nested-quote bug
    reachable.
    """
    start = f"{max(time.perf_counter() - back, 0.0):.9f}"
    assert "." in start
    return start


def _run_elapsed(script: Path, start: str | None = None) -> subprocess.CompletedProcess[str]:
    if not start:
        start = _clock_start()
    els = _elapsed_lines(script)
    assert els, f"no ELAPSED= assignment in {script}"
    elapsed_line = els[-1]
    # Bare python3 reproduces tip nested-quote SyntaxError; full venv path can mask it.
    bash = f"""set -euo pipefail
PYTHON="python3"
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
    env["PYTHON"] = "python3"
    return subprocess.run(
        ["bash", "-c", bash],
        cwd=str(ROOT),
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )


def test_sample_to_sor_elapsed_line_executes_with_start() -> None:
    """Execute sample_to_sor ELAPSED with a clock-derived START that trips nested-quote bug."""
    script = ROOT / "scripts" / "sample_to_sor.sh"
    assert script.is_file()
    r = _run_elapsed(script)
    assert r.returncode == 0, (
        f"ELAPSED path failed rc={r.returncode}\n"
        f"stdout={r.stdout!r}\nstderr={r.stderr!r}\n"
        f"(tip nested float('$START') breaks under PYTHON=python3; "
        f"pr-a sys.argv form must pass)"
    )
    assert "ELAPSED_OUT=" in r.stdout
    assert "PARSED_OK" in r.stdout


def test_farm_drop_to_sor_elapsed_line_executes_with_start() -> None:
    script = ROOT / "scripts" / "farm_drop_to_sor.sh"
    assert script.is_file()
    r = _run_elapsed(script)
    assert r.returncode == 0, (
        f"farm ELAPSED path failed rc={r.returncode}\n"
        f"stdout={r.stdout!r}\nstderr={r.stderr!r}"
    )
    assert "PARSED_OK" in r.stdout
