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
    "print \"not human-reviewed\"",
    "print 'not human-reviewed'",
    "fell back to fixtures, by name",
)

# Generator instructions / unfilled template holes. [reviewer: …] slots stay.
INSTRUCTION_LEAKS = (
    "list every collector folder",
    "if no one did, print",
    "print \"not human-reviewed\"",
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

COLLECTOR_AREAS = {
    "cloud": "Cloud configuration",
    "cloud-prowler": "Cloud configuration",
    "nmap": "Host / network exposure",
    "inventory-nmap": "Host / network exposure",
    "vuln": "Vulnerability scan",
    "vuln-scan": "Vulnerability scan",
    "wazuh": "Host coverage",
    "host-wazuh": "Host coverage",
    "mdm": "MDM inventory",
    "identity": "Identity",
    "identity-ad": "Identity",
    "easm": "External exposure",
    "k8s": "Kubernetes",
    "k8s-kubescape": "Kubernetes",
    "code": "Code secrets",
    "code-secrets": "Code secrets",
    "saas": "SaaS / identity",
    "saas-idp": "SaaS / identity",
    "honeypot": "Deception sensors",
    "dns_email": "DNS / email",
    "dns-email": "DNS / email",
}

AREA_HINTS = (
    ("identity", ("identity", "saas", "idp", "ad", "entra", "okta")),
    ("external exposure", ("easm", "nmap", "exposure", "honeypot", "dns")),
    ("cloud configuration", ("cloud", "prowler", "k8s", "kubescape")),
    ("code secrets", ("code", "secret", "gitleaks", "truffle", "sast")),
)

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_TABLE = ("critical", "high", "medium", "low", "info")

MAX_EXEC_BODY_ROWS = {
    "top_n": 5,
    "areas": 4,
}
# One printed page: keep banner + limits; cut table rows if needed.
MAX_PAGE_LINES = 58
MAX_COVERAGE_GAP_ROWS = 4
COVERAGE_GAPS_NONE = "None. Every sensor that received input was assessed."
COVERAGE_GAPS_HEADING = "### Coverage gaps"

EXPORT_CSV_REL = (
    "poam/poam.csv",
    "poam/excluded.csv",
    "ciso-assistant/assets.csv",
    "ciso-assistant/applied_controls.csv",
    "ciso-assistant/evidences.csv",
    "ciso-assistant/findings.csv",
    "ciso-assistant/vulnerabilities.csv",
    "ciso-assistant/risk_scenarios.csv",
    "opengrc/risks.csv",
    "opengrc/assets.csv",
    "opengrc/implementations.csv",
)
EXPORT_MD_REL = (
    "EXECUTIVE_SUMMARY.md",
    "SCOPE_AND_TRUST.md",
    "poam/poam.md",
    "poam/ESTATE.txt",
    "ciso-assistant/ESTATE.txt",
    "opengrc/ESTATE.txt",
    "opengrc/README.md",
    "probo/ESTATE.txt",
    "probo/README.md",
)
EXPORT_OTHER_REL = (
    "import_preview/probo.json",
)


def recorded(value: Any) -> str:
    """Fill a placeholder from run data. Missing → 'not recorded'. Never invent."""
    if value is None:
        return NOT_RECORDED
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value).strip()
    if not text:
        return NOT_RECORDED
    if text.lower() in {"none", "null", "unknown", "n/a", "na", "-"}:
        return NOT_RECORDED
    return text


def _artifact_scan_stamp(rec: dict) -> str:
    """Artifact scan calendar day, or 'not recorded'. Never collected_at / pack now."""
    raw = extra_scan_raw(rec)
    if raw in (None, ""):
        return NOT_RECORDED
    return format_detection_date(raw)


def most_restrictive(*kinds: str) -> str:
    present = {k for k in kinds if k in KIND_ORDER}
    if not present:
        return "SAMPLE"
    for kind in KIND_ORDER:
        if kind in present:
            return kind
    return "SAMPLE"


def _env(env: dict[str, str] | None, key: str, default: str = "") -> str:
    src = env if env is not None else os.environ
    return str(src.get(key) or default).strip()


def _looks_non_client_name(name: str) -> bool:
    blob = name.strip().lower()
    if not blob:
        return True
    return any(tok in blob for tok in ("demo", "sample", "lab", "example", "not a client"))


def _client_name_from_scope() -> str:
    raw = _env(None, "GRC_CLIENT_NAME")
    if raw and not _looks_non_client_name(raw):
        return raw
    scope_path = _env(None, "GRC_SCOPE_PATH")
    candidates = []
    if scope_path:
        candidates.append(Path(scope_path))
    try:
        from shared.io_util import root_dir

        candidates.append(root_dir() / "dropbox" / "SCOPE.yaml")
    except Exception:
        pass
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            if line.strip().startswith("name:"):
                name = line.split(":", 1)[1].strip().strip("\"'")
                if name and not _looks_non_client_name(name):
                    return name
                return ""
    return ""


def pack_commit() -> str:
    raw = _env(None, "PACK_COMMIT") or _env(None, "GRC_PACK_COMMIT")
    if raw:
        return raw
    try:
        from shared.io_util import root_dir

        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(root_dir()),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return NOT_RECORDED
    out = (proc.stdout or "").strip()
    return out or NOT_RECORDED


def generated_at_local(iso_utc: str | None = None) -> str:
    raw = (iso_utc or "").strip()
    if raw:
        try:
            stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            local = stamp.astimezone()
            return local.strftime("%Y-%m-%d %H:%M %Z")
        except ValueError:
            pass
    now = datetime.now().astimezone()
    return now.strftime("%Y-%m-%d %H:%M %Z")


def run_id_from_records(records: list[dict] | None) -> str:
    raw = _env(None, "GRC_RUN_ID")
    if raw:
        return raw
    for rec in records or []:
        extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
        for key in ("run_id", "runId"):
            val = extra.get(key) or rec.get(key)
            if val:
                return str(val).strip()
    return NOT_RECORDED


def _marker_in(folder: Path | None, name: str) -> bool:
    if folder is None or not folder.is_dir():
        return False
    if (folder / name).is_file():
        return True
    try:
        return any(folder.rglob(name))
    except OSError:
        return False


def _fallback_from_records(records: list[dict]) -> list[str]:
    names: list[str] = []
    for rec in records:
        labels = [str(x).strip().lower() for x in (rec.get("labels") or [])]
        if "demo" not in labels and "sample" not in labels:
            continue
        src = str(rec.get("source") or "fixtures/demo").strip() or "fixtures/demo"
        if src not in names:
            names.append(src)
    return names


@dataclass
class EstateStamp:
    kind: str
    label: str
    sentence: str
    run_id: str = NOT_RECORDED
    generated_at_local: str = NOT_RECORDED
    pack_commit: str = NOT_RECORDED
    fallback_files: tuple[str, ...] = ()
    client_name: str = NOT_RECORDED

    def banner_md(self) -> str:
        return (
            f"> **{self.label}**: {self.sentence}\n"
            f"> Run `{self.run_id}` · generated {self.generated_at_local} · pack `{self.pack_commit}`"
        )

    def banner_lines(self) -> list[str]:
        return self.banner_md().splitlines()

    def banner_oneline(self) -> str:
        return f"{self.label}: {self.sentence}"

    def token(self) -> str:
        return f"estate_{self.kind.lower()}"
