"""Offline CISA KEV snapshot load, validate, and join. The pipeline NEVER fetches.

Reads ``in/kev/`` via ``in_dir()`` (``IN_DIR`` or ``<root>/in``). Pin by sha256.
Missing snapshot → ``kev_evaluated=false``; blank Z/AA must never read as
"checked, not in KEV". SHA mismatch or schema violation fails the run.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from shared.io_util import in_dir
from shared.finding_types import extra_dict
from shared.poam_fields import SLA_DAYS, _to_date, risk_rating
from shared.schema import ciso_finding_severity

CISA_KEV_JSON = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
# ^CVE-\d{4}-\d{4,7}$ semantics: no XCVE- prefix, no truncation of overlong IDs.
CVE_RE = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,7}(?![0-9])", re.I)
CVE_STRICT = re.compile(r"^CVE-\d{4}-\d{4,7}$")

KEV_JSON_NAME = "known_exploited_vulnerabilities.json"
KEV_SHA_NAME = "known_exploited_vulnerabilities.json.sha256"
KEV_PROV_NAME = "kev_provenance.json"

TOP_REQUIRED = ("catalogVersion", "dateReleased", "count", "vulnerabilities")
ENTRY_REQUIRED = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
)

STALE_WARN_DAYS = 7
STALE_FLAG_DAYS = 30

# BOD 26-04 Appendix A Table 1 (S20 text; BOD wording "forensic triage").
# Key: (publicly_exposed, in_kev, automatable, technical_impact)
# Value: (calendar_days or None, forensic_triage)
BOD_2604_TABLE: dict[tuple[bool, bool, bool, str], tuple[int | None, bool]] = {
    (True, True, True, "Total"): (3, True),
    (True, True, True, "Partial"): (3, False),
    (True, True, False, "Total"): (3, True),
    (True, True, False, "Partial"): (14, False),
    (True, False, True, "Total"): (3, False),
    (True, False, True, "Partial"): (14, False),
    (True, False, False, "Total"): (14, False),
    (True, False, False, "Partial"): (60, False),
    (False, True, True, "Total"): (3, True),
    (False, True, True, "Partial"): (14, False),
    (False, True, False, "Total"): (14, False),
    (False, True, False, "Partial"): (14, False),
    (False, False, True, "Total"): (60, False),
    (False, False, True, "Partial"): (60, False),
    (False, False, False, "Total"): (None, False),
    (False, False, False, "Partial"): (None, False),
}

HEADER_BOD_TRACKING = "Binding Operational Directive 22-01 tracking"
HEADER_BOD_DUE = "Binding Operational Directive 22-01 Due Date"
HEADER_CVE = "CVE"

CVE_CELL_SEP = "\n"
CVE_CSV_FALLBACK_SEP = ", "


class KevSnapshotError(Exception):
    """SHA mismatch or schema violation — fail the run."""


@dataclass
class KevEntry:
    cve_id: str
    date_added: str
    due_date: str
    forensic_triage: str
    ransomware: str
    raw: dict[str, Any]


@dataclass
class KevCatalog:
    kev_evaluated: bool
    reason: str = ""
    source_url: str = ""
    fetched_at_utc: str = ""
    catalog_version: str = ""
    date_released: str = ""
    count: int = 0
    sha256: str = ""
    stale: str | None = None
    warnings: list[str] = field(default_factory=list)
    by_cve: dict[str, KevEntry] = field(default_factory=dict)

    def provenance(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "kev_evaluated": self.kev_evaluated,
            "reason": self.reason,
            "source_url": self.source_url,
            "fetched_at_utc": self.fetched_at_utc,
            "catalogVersion": self.catalog_version,
            "dateReleased": self.date_released,
            "count": self.count,
            "sha256": self.sha256,
            "stale": self.stale,
            "warnings": list(self.warnings),
        }
        return doc


def kev_dir(root: Path | None = None) -> Path:
    return (root or in_dir()) / "kev"


def collect_cves(rec: dict[str, Any]) -> list[str]:
    """CVE IDs from extra.cve / extra.rule / extra.id / ref_id / extra.cves.

    Regex is the KEV schema pattern, case-insensitive, then upper-cased.
    """
    extra = extra_dict(rec)
    blobs: list[str] = [
        str(extra.get("cve") or ""),
        str(extra.get("rule") or ""),
        str(extra.get("id") or ""),
        str(rec.get("ref_id") or ""),
    ]
    found: list[str] = []
    seen: set[str] = set()

    def _add(raw: str) -> None:
        up = raw.strip().upper()
        if not up or up in seen:
            return
        if CVE_STRICT.fullmatch(up):
            seen.add(up)
            found.append(up)
            return
        for match in CVE_RE.findall(up):
            token = match.upper()
            if CVE_STRICT.fullmatch(token) and token not in seen:
                seen.add(token)
                found.append(token)

    for blob in blobs:
        _add(blob)
    cves_field = extra.get("cves")
    if isinstance(cves_field, (list, tuple)):
        for item in cves_field:
            _add(str(item or ""))
    elif cves_field:
        _add(str(cves_field))
    found.sort()
    return found


def format_cves(cves: Iterable[str], *, csv_fallback: bool = False) -> str:
    """§4.2: newline (Alt+Enter) inside the cell; ``, `` is the CSV fallback."""
    ordered = sorted({str(c).strip().upper() for c in cves if str(c).strip()})
    sep = CVE_CSV_FALLBACK_SEP if csv_fallback else CVE_CELL_SEP
    return sep.join(ordered)


def bod_2604_timeline(
    *,
    publicly_exposed: bool,
    in_kev: bool,
    automatable: bool,
    technical_impact: str,
) -> dict[str, Any]:
    """BOD 26-04 Table 1. Days are calendar days. Clock starts at KEV add or identification."""
    impact = "Total" if str(technical_impact).strip().lower() == "total" else "Partial"
    key = (bool(publicly_exposed), bool(in_kev), bool(automatable), impact)
    days, triage = BOD_2604_TABLE[key]
    if days is None:
        label = "Fix on system upgrade"
    elif triage:
        label = f"{days} days + forensic triage"
    else:
        label = f"{days} days"
    return {
        "days": days,
        "forensic_triage": triage,
        "timeline": label,
        "publicly_exposed": publicly_exposed,
        "in_kev": in_kev,
        "automatable": automatable,
        "technical_impact": impact,
    }


def template_due_date(detection: date, severity: Any) -> date:
    """FedRAMP R3.0 M formula: High/Critical +30, Moderate +90, Low +180. Not written to M."""
    rating = risk_rating(severity)
    if rating == "Critical":
        rating = "High"
    return detection + timedelta(days=SLA_DAYS[rating])


def effective_due(template: date | None, kev_due: date | None) -> date | None:
    """Internal due = earlier of template-derived due and earliest KEV dueDate."""
    dates = [d for d in (template, kev_due) if d is not None]
    return min(dates) if dates else None


def kev_overdue_on_detection(original: date | None, kev_due: date | None) -> bool:
    return bool(original and kev_due and kev_due < original)


def _parse_sha_file(text: str) -> str:
    token = (text or "").strip().split()[0] if text.strip() else ""
    token = token.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise KevSnapshotError(f"KEV_SNAPSHOT_SHA_MISMATCH: sha256 file is not a 64-hex digest: {token!r}")
    return token


def _parse_when(raw: str) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _validate_catalog(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise KevSnapshotError("KEV_SNAPSHOT_SCHEMA: catalog root must be an object")
    missing = [k for k in TOP_REQUIRED if k not in data]
    if missing:
        raise KevSnapshotError(f"KEV_SNAPSHOT_SCHEMA: missing top-level field(s) {missing}")
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise KevSnapshotError("KEV_SNAPSHOT_SCHEMA: vulnerabilities must be a list")
    try:
        count = int(data.get("count"))
    except (TypeError, ValueError) as exc:
        raise KevSnapshotError("KEV_SNAPSHOT_SCHEMA: count must be an integer") from exc
    if count != len(vulns):
        raise KevSnapshotError(
            f"KEV_SNAPSHOT_SCHEMA: count={count} != len(vulnerabilities)={len(vulns)}"
        )
    for i, row in enumerate(vulns):
        if not isinstance(row, dict):
            raise KevSnapshotError(f"KEV_SNAPSHOT_SCHEMA: entry {i} is not an object")
        absent = [k for k in ENTRY_REQUIRED if not str(row.get(k) or "").strip()]
        if absent:
            raise KevSnapshotError(
                f"KEV_SNAPSHOT_SCHEMA: entry {i} missing required field(s) {absent}"
            )
        cve = str(row.get("cveID") or "").strip().upper()
        if not CVE_STRICT.fullmatch(cve):
            raise KevSnapshotError(f"KEV_SNAPSHOT_SCHEMA: entry {i} cveID {cve!r} fails schema pattern")
    return data


def write_snapshot_files(
    dest: Path,
    catalog: dict[str, Any],
    *,
    source_url: str = CISA_KEV_JSON,
    fetched_at_utc: str = "",
    raw: bytes | None = None,
) -> dict[str, Any]:
    """Write json + sha256 + provenance. Used by tests and the explicit fetch helper."""
    dest.mkdir(parents=True, exist_ok=True)
    if raw is None:
        raw = (json.dumps(catalog, indent=2) + "\n").encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    (dest / KEV_JSON_NAME).write_bytes(raw)
    (dest / KEV_SHA_NAME).write_text(sha + "\n", encoding="utf-8")
    prov = {
        "source_url": source_url,
        "fetched_at_utc": fetched_at_utc,
        "catalogVersion": catalog.get("catalogVersion"),
        "dateReleased": catalog.get("dateReleased"),
        "count": catalog.get("count"),
        "sha256": sha,
    }
    (dest / KEV_PROV_NAME).write_text(json.dumps(prov, indent=2) + "\n", encoding="utf-8")
    return prov


def _stale_flag(date_released: str, now: datetime) -> str | None:
    released = _parse_when(date_released)
    if released is None:
        return None
    age = now - released
    if age > timedelta(days=STALE_FLAG_DAYS):
        return "KEV_STALE"
    if age > timedelta(days=STALE_WARN_DAYS):
        return "KEV_STALE_WARN"
    return None


def load_kev_catalog(
    *,
    in_root: Path | None = None,
    now: datetime | None = None,
) -> KevCatalog:
    """Load and verify the offline snapshot. Missing dir/files → not evaluated."""
    folder = kev_dir(in_root)
    json_path = folder / KEV_JSON_NAME
    sha_path = folder / KEV_SHA_NAME
    prov_path = folder / KEV_PROV_NAME
    present = json_path.is_file() or sha_path.is_file() or prov_path.is_file()
    if not present:
        return KevCatalog(kev_evaluated=False, reason="snapshot_missing")
    if not (json_path.is_file() and sha_path.is_file() and prov_path.is_file()):
        raise KevSnapshotError(
            "KEV_SNAPSHOT_SCHEMA: in/kev/ is incomplete — need "
            f"{KEV_JSON_NAME}, {KEV_SHA_NAME}, and {KEV_PROV_NAME}"
        )
    raw = json_path.read_bytes()
    computed = hashlib.sha256(raw).hexdigest()
    expected = _parse_sha_file(sha_path.read_text(encoding="utf-8"))
    if computed != expected:
        raise KevSnapshotError(
            f"KEV_SNAPSHOT_SHA_MISMATCH: file sha256={computed} != pinned {expected}"
        )
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KevSnapshotError(f"KEV_SNAPSHOT_SCHEMA: JSON is not parseable: {exc}") from exc
    data = _validate_catalog(data)
    try:
        prov = json.loads(prov_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise KevSnapshotError(f"KEV_SNAPSHOT_SCHEMA: provenance JSON is not parseable: {exc}") from exc
    if not isinstance(prov, dict):
        raise KevSnapshotError("KEV_SNAPSHOT_SCHEMA: provenance must be an object")
    for key in ("source_url", "fetched_at_utc", "catalogVersion", "dateReleased", "count", "sha256"):
        if key not in prov:
            raise KevSnapshotError(f"KEV_SNAPSHOT_SCHEMA: provenance missing {key}")
    if str(prov.get("sha256") or "").lower() != computed:
        raise KevSnapshotError(
            f"KEV_SNAPSHOT_SHA_MISMATCH: provenance sha256={prov.get('sha256')} != file {computed}"
        )
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    stale = _stale_flag(str(data.get("dateReleased") or ""), clock)
    warnings: list[str] = []
    if stale:
        warnings.append(stale)
    by_cve: dict[str, KevEntry] = {}
    for row in data["vulnerabilities"]:
        cve = str(row["cveID"]).strip().upper()
        by_cve[cve] = KevEntry(
            cve_id=cve,
            date_added=str(row.get("dateAdded") or ""),
            due_date=str(row.get("dueDate") or ""),
            forensic_triage=str(row.get("forensicTriage") or "No"),
            ransomware=str(row.get("knownRansomwareCampaignUse") or "Unknown"),
            raw=row,
        )
    return KevCatalog(
        kev_evaluated=True,
        reason="",
        source_url=str(prov.get("source_url") or CISA_KEV_JSON),
        fetched_at_utc=str(prov.get("fetched_at_utc") or ""),
        catalog_version=str(data.get("catalogVersion") or ""),
        date_released=str(data.get("dateReleased") or ""),
        count=int(data.get("count") or 0),
        sha256=computed,
        stale=stale,
        warnings=warnings,
        by_cve=by_cve,
    )


def join_kev(cves: Iterable[str], catalog: KevCatalog) -> dict[str, Any]:
    """Intersect finding CVEs with the snapshot. Blank Z/AA when not evaluated."""
    all_cves = sorted({str(c).strip().upper() for c in cves if str(c).strip()})
    if not catalog.kev_evaluated:
        return {
            "tracking": "",
            "due": "",
            "cves": all_cves,
            "kev_cves": [],
            "kev_due": None,
            "comments": [],
            "evaluated": False,
        }
    hits = [catalog.by_cve[c] for c in all_cves if c in catalog.by_cve]
    due_dates = [_to_date(h.due_date) for h in hits]
    due_dates = [d for d in due_dates if d is not None]
    earliest = min(due_dates) if due_dates else None
    comments = []
    sha12 = catalog.sha256[:12]
    for hit in hits:
        comments.append(
            f"KEV: {hit.cve_id} added {hit.date_added}; "
            f"forensicTriage={hit.forensic_triage or 'No'}; "
            f"ransomware={hit.ransomware or 'Unknown'}; "
            f"catalog {catalog.catalog_version} sha256:{sha12}"
        )
    return {
        "tracking": "Yes" if hits else "",
        "due": earliest.isoformat() if earliest else "",
        "cves": all_cves,
        "kev_cves": [h.cve_id for h in hits],
        "kev_due": earliest,
        "comments": comments,
        "evaluated": True,
    }


def forbidden_blank_tokens(value: str) -> bool:
    """True when a Z/AA/AB cell uses a forbidden No/N/A stand-in."""
    return str(value or "").strip().lower() in {"no", "n/a", "na", "none"}


def fedramp_risk_for_col_r(severity: Any) -> str:
    """Col R allows Low/Moderate/High. Map Critical → High (keep Critical in Comments)."""
    sev = ciso_finding_severity(severity)
    if sev == "critical":
        return "High"
    return {"high": "High", "medium": "Moderate", "low": "Low"}.get(sev, "Low")
