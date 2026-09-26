"""HardeningKitty Audit CSV contract (scipag/HardeningKitty.psm1 @ da0976073caa).

Invoke-HardeningKitty -Mode Audit -Report writes an Export-Csv of the
ordered $ReportResult object (psm1 L2041–2052, write L3668–3671):

    ID, Category, Name, Severity, Result, Recommended, TestResult,
    SeverityFinding, DefaultValue, Filter

Result is the MEASURED value. Pass/fail lives in TestResult
(Passed | Failed). There is no host column. Hostname appears only in
the default report file name (psm1 L843, L868):

    hardeningkitty_report_<hostname>_<list>-<yyyyMMdd-HHmmss>.csv

Pack dest_in convention (runner writes this; parser reads it):

    hardeningkitty-<HOSTNAME>-<yyyyMMdd-HHmmss>.csv
    hardeningkitty-<HOSTNAME>-<yyyyMMddTHHmmssZ>.csv
    optional honesty suffix: -SYNTHETIC

HOSTNAME is $env:COMPUTERNAME (runner lower-cases, matching upstream).
FQDN is allowed; the trailing timestamp terminates the host token.

Operator overrides (file-specific first):
  1. sidecar `<csv>.host` or `HARDENINGKITTY.host` (one hostname)
  2. optional ComputerName/Hostname column (not official HK)
  3. filename convention (pack or upstream default)
  4. env HARDENINGKITTY_HOST (single-file fallback)

Never invent the literal default `windows-host`. When no host can be
determined, flag the row (`host_unresolved`) and use a unique
per-path token so two nameless files do not collapse onto one asset.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

# Exact Export-Csv header order from HardeningKitty.psm1 $ReportResult.
HK_AUDIT_COLUMNS: tuple[str, ...] = (
    "ID",
    "Category",
    "Name",
    "Severity",
    "Result",
    "Recommended",
    "TestResult",
    "SeverityFinding",
    "DefaultValue",
    "Filter",
)

HK_AUDIT_HEADER = ",".join(HK_AUDIT_COLUMNS)

# Pack dest_in: hardeningkitty-<HOSTNAME>-<timestamp>[-SYNTHETIC].csv
_PACK_NAME = re.compile(
    r"^hardeningkitty-(?P<host>.+)-"
    r"(?P<ts>\d{8}T\d{6}Z|\d{8}-\d{6})"
    r"(?:-SYNTHETIC)?$",
    re.IGNORECASE,
)
# Upstream default when -ReportFile is unset (psm1 L868).
_UPSTREAM_NAME = re.compile(
    r"^hardeningkitty_report_(?P<host>[^_]+)_.+-"
    r"(?P<ts>\d{8}-\d{6})$",
    re.IGNORECASE,
)

_HK_PASS = frozenset({"passed", "pass", "ok", "true", "compliant", "notapplicable", "n/a", "na"})
_HK_FAIL = frozenset({"failed", "fail", "warning", "warn", "noncompliant", "error"})

# Never emit this invented default. Real HK CSVs have no host column.
WINDOWS_HOST_DEFAULT = "windows-host"


def hk_row_failed(lower: dict[str, str]) -> tuple[str, bool]:
    """TestResult is authoritative. Result is the measured value.

    A row with TestResult=Passed never becomes a finding, whatever Result
    says. Legacy CSVs that put Passed|Failed in Result (no TestResult)
    still parse. Measured Result values (5, 0, No Auditing, …) are not
    pass/fail signals.
    """
    test = (lower.get("testresult") or "").strip().lower()
    result = (
        lower.get("result") or lower.get("status") or lower.get("outcome") or ""
    ).strip().lower()
    if test:
        if test in _HK_PASS:
            return test, False
        if test in _HK_FAIL:
            return test, True
        return test, False
    if result in _HK_PASS:
        return result, False
    if result in _HK_FAIL:
        return result, True
    return result, False


def hk_host_from_filename(name: str) -> str | None:
    """Return hostname from pack or upstream default file name, else None."""
    stem = Path(name).stem
    for pat in (_PACK_NAME, _UPSTREAM_NAME):
        match = pat.match(stem)
        if match:
            host = (match.group("host") or "").strip()
            if host:
                return host
    return None


def hk_host_from_sidecar(path: Path) -> str | None:
    """One-line hostname beside the CSV (`<csv>.host` or HARDENINGKITTY.host)."""
    dest = Path(path)
    candidates = (
        Path(str(dest) + ".host"),
        dest.with_suffix(dest.suffix + ".host"),
        dest.with_name(dest.name + ".host"),
        dest.with_suffix(".host"),
        dest.parent / "HARDENINGKITTY.host",
    )
    seen: set[Path] = set()
    for cand in candidates:
        try:
            resolved = cand.resolve()
        except OSError:
            resolved = cand
        if resolved in seen:
            continue
        seen.add(resolved)
        if not cand.is_file():
            continue
        text = cand.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
        for line in text.splitlines():
            host = line.strip()
            if host and not host.startswith("#"):
                return host
    return None


def hk_host_from_row(lower: dict[str, str]) -> str | None:
    """Optional operator-added column. Official HK CSV has none of these."""
    for key in ("computername", "hostname", "computer", "system"):
        val = (lower.get(key) or "").strip()
        if val:
            return val
    return None


def hk_host_from_env() -> str | None:
    raw = (os.environ.get("HARDENINGKITTY_HOST") or "").strip()
    return raw or None


def unresolved_hk_host(path: Path | None) -> str:
    """Unique per-path token. Never `windows-host`."""
    if path is None:
        return "unresolved-hardeningkitty"
    raw = str(path)
    try:
        raw = str(path.resolve())
    except OSError:
        pass
    token = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    return f"unresolved-{token}"


def resolve_hk_host(
    path: Path | None,
    lower: dict[str, str] | None = None,
) -> tuple[str, str, bool]:
    """Return (host, source, unresolved).

    source is sidecar | column | filename | env | unresolved.
    """
    if path is not None:
        sidecar = hk_host_from_sidecar(path)
        if sidecar:
            return sidecar, "sidecar", False
    row_host = hk_host_from_row(lower or {})
    if row_host:
        return row_host, "column", False
    if path is not None:
        named = hk_host_from_filename(path.name)
        if named:
            return named, "filename", False
    env_host = hk_host_from_env()
    if env_host:
        return env_host, "env", False
    return unresolved_hk_host(path), "unresolved", True
