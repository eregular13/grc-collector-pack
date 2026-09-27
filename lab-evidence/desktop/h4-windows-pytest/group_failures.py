"""Group H4 pytest failures from summary.json by root-cause bucket."""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
phase = sys.argv[1] if len(sys.argv) > 1 else "baseline"
summary_path = HERE / phase / "summary.json"
stdout_path = HERE / phase / "pytest-stdout.txt"
out_path = HERE / phase / "grouped.json"

data = json.loads(summary_path.read_text(encoding="utf-8"))
stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""

BUCKETS = [
    ("python3_alias", re.compile(r"python3|WinError 2|The system cannot find the file specified", re.I)),
    ("bin_bash", re.compile(r"/bin/bash|bash: |'bash'|\"bash\"|WinError 2.*bash|No such file or directory: 'bash'", re.I)),
    ("symlink", re.compile(r"symlink|WinError 1314|privilege|symbolic link", re.I)),
    ("path_sep", re.compile(r"\\\\|posixpath|ntpath|expected '/'|mixed (?:path|slash)", re.I)),
    ("encoding_cp1252", re.compile(r"charmap|cp1252|codec can't|UnicodeDecode|UnicodeEncode|utf-8", re.I)),
    ("crlf", re.compile(r"\\r\\n|CRLF|sha256|eol|newline", re.I)),
    ("timing", re.compile(r"timeout|timed out|too slow|sleep", re.I)),
    ("permission", re.compile(r"PermissionError|WinError 5|access is denied", re.I)),
]


def bucket_for(msg: str, nodeid: str) -> str:
    hay = f"{nodeid} {msg}"
    for name, rx in BUCKETS:
        if rx.search(hay):
            return name
    return "other"


groups: dict[str, list[dict]] = defaultdict(list)
for item in data.get("failures", []):
    groups[bucket_for(item.get("message", ""), item.get("nodeid", ""))].append(item)

# Also scrape FAILED lines from stdout for nodeids pytest short form
failed_lines = [ln for ln in stdout.splitlines() if ln.startswith("FAILED ") or ln.startswith("ERROR ")]

report = {
    "phase": phase,
    "passed": data.get("passed"),
    "failed": data.get("failed"),
    "errors": data.get("errors"),
    "skipped": data.get("skipped"),
    "total": data.get("total"),
    "groups": {k: [{"nodeid": i["nodeid"], "message": i["message"]} for i in v] for k, v in sorted(groups.items())},
    "group_counts": {k: len(v) for k, v in sorted(groups.items())},
    "failed_stdout_lines": failed_lines[:200],
}
out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"grouped": str(out_path), "counts": report["group_counts"], "n": sum(report["group_counts"].values())}))
