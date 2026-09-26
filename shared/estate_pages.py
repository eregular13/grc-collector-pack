"""Estate banner + one-page executive summary + SCOPE_AND_TRUST.md.

Argus drafts (2026-09-25) are the spec. Exactly one allowed label. Fail
closed to the most restrictive when unsure. SAMPLE/DEMO/LAB and any
product-lab/drop fallback cannot be suppressed and cannot become CLIENT.
Missing values print "not recorded". Human narrative slots stay marked
placeholders. No cycle/CoS/adapter-list/agent notes on client pages.
"""

from __future__ import annotations

import csv
import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from shared.scan_time import extra_scan_raw, format_detection_date

NOT_RECORDED = "not recorded"

# Most restrictive first. Unsure → SAMPLE (never CLIENT).
KIND_ORDER = ("MIXED", "SAMPLE", "DEMO", "LAB", "CLIENT")

LABEL_FOR_KIND = {
    "SAMPLE": "SAMPLE DATA: NOT A CLIENT",
    "DEMO": "DEMO: NOT A CLIENT",
    "LAB": "LAB: TEST ENVIRONMENT",
    "MIXED": "MIXED: REVIEW BEFORE USE",
}

SENTENCE_FOR_KIND = {
    "SAMPLE": (
        "Every finding below comes from bundled example files. "
        "None describes any real organization."
    ),
    "DEMO": (
        "Built from demo fixtures because no scanner output was supplied. "
        "None describes any real organization."
    ),
    "LAB": (
        "From scans of an Evergreen-controlled test environment. "
        "It does not describe your organization."
    ),
    "CLIENT": "From scanner output collected under the scope below.",
    "MIXED": (
        "Some outputs came from bundled sample files ({fallback_files}). "
        "Do not forward until they are removed."
    ),
}

# Human-written slots — never generated prose.
REVIEWER_WHAT_WE_FOUND = (
    "[reviewer: one to three plain sentences — not generated]"
)
REVIEWER_WHY_IT_MATTERS = (
    "[reviewer: one-sentence business impact — not generated]"
)
REVIEWER_NEXT_STEP = "[reviewer: one sentence — not generated]"
REVIEWER_NOT_REVIEWED = "not human-reviewed"

SAMPLE_AUTH = "No client authorization applies. No client systems were touched."

CLIENT_PAGE_FORBIDDEN = (
    "cycle ",
    "CoS #",
    "COS4",
    "COS48",
    "adapter list",
    "agent process",
    "overnight",
    "pytest",
    "E2E_PROVEN",
    "list every collector folder",
    "if no one did, print",
    'print "not human-reviewed"',
    "print 'not human-reviewed'",
    "fell back to fixtures, by name",
)

# Generator instructions / unfilled template holes. [reviewer: …] slots stay.
INSTRUCTION_LEAKS = (
    "list every collector folder",
    "if no one did, print",
    'print "not human-reviewed"',
    "print 'not human-reviewed'",
    "fell back to fixtures, by name",
    "collected by not recorded",
    "[insert ",
    "[fill in",
    "{{",
    "todo:",
    "fixme",
)

CLIENT_FACING_RELS = (
    "EXECUTIVE_SUMMARY.md",
    "SCOPE_AND_TRUST.md",
    "poam/poam.md",
    "poam/ESTATE.txt",
    "ciso-assistant/ESTATE.txt",
    "opengrc/ESTATE.txt",
    "opengrc/README.md",
    "probo/ESTATE.txt",
    "probo/README.md",
    "MANIFEST",
)

# GNU coreutils: "<hash><two spaces><path>" (text) or "<hash><space>*<path>" (binary).
SHA256SUM_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")
