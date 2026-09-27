"""Cron-safe full pytest runner for H4 Windows triage.

Writes junitxml + a JSON summary of pass/fail/skip and each failure's
nodeid + first assertion/error line. Never uses python -c.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PHASE = sys.argv[1] if len(sys.argv) > 1 else "baseline"
OUT = HERE / PHASE
OUT.mkdir(parents=True, exist_ok=True)

junit = OUT / "junit.xml"
stdout_path = OUT / "pytest-stdout.txt"
summary_path = OUT / "summary.json"

env = os.environ.copy()
env["PYTHONUTF8"] = "1"
env["PYTHONIOENCODING"] = "utf-8"

cmd = [
    sys.executable,
    "-m",
    "pytest",
    "tests",
    "-q",
    "--tb=line",
    f"--junitxml={junit}",
]
started = time.time()
stamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
proc = subprocess.run(
    cmd,
    cwd=str(ROOT),
    env=env,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
)
elapsed = time.time() - started
combined = (proc.stdout or "") + ("\n" if proc.stderr else "") + (proc.stderr or "")
stdout_path.write_text(combined, encoding="utf-8")

passed = failed = skipped = errors = 0
failures: list[dict] = []
if junit.exists():
    tree = ET.parse(junit)
    root = tree.getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    for suite in suites:
        passed += int(suite.attrib.get("tests", "0"))
        failed += int(suite.attrib.get("failures", "0"))
        errors += int(suite.attrib.get("errors", "0"))
        skipped += int(suite.attrib.get("skipped", "0"))
        for case in suite.findall("testcase"):
            nodeid = f"{case.attrib.get('classname', '')}::{case.attrib.get('name', '')}"
            fail_el = case.find("failure")
            err_el = case.find("error")
            skip_el = case.find("skipped")
            if fail_el is not None or err_el is not None:
                el = fail_el if fail_el is not None else err_el
                msg = (el.attrib.get("message") or "").strip()
                text = (el.text or "").strip()
                first = (msg or text).splitlines()[0] if (msg or text) else ""
                failures.append(
                    {
                        "nodeid": nodeid,
                        "file": case.attrib.get("file", ""),
                        "kind": "error" if err_el is not None else "failure",
                        "message": first[:500],
                    }
                )

# junit "tests" is total cases; passed = tests - failures - errors - skipped
total = passed
real_failed = failed
real_errors = errors
real_skipped = skipped
real_passed = total - real_failed - real_errors - real_skipped

summary = {
    "phase": PHASE,
    "stamp": stamp,
    "cwd": str(ROOT),
    "python": sys.executable,
    "python_version": sys.version,
    "platform": platform.platform(),
    "os_name": os.name,
    "cmd": cmd,
    "exit_code": proc.returncode,
    "elapsed_sec": round(elapsed, 1),
    "passed": real_passed,
    "failed": real_failed,
    "errors": real_errors,
    "skipped": real_skipped,
    "total": total,
    "failures": failures,
}
summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(
    json.dumps(
        {
            "phase": PHASE,
            "exit_code": proc.returncode,
            "passed": real_passed,
            "failed": real_failed,
            "errors": real_errors,
            "skipped": real_skipped,
            "total": total,
            "elapsed_sec": round(elapsed, 1),
            "failure_count": len(failures),
            "stdout": str(stdout_path),
            "junit": str(junit),
            "summary": str(summary_path),
        }
    )
)
sys.exit(0)
