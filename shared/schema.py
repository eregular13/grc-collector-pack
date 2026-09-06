from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

KINDS = frozenset({"asset", "finding", "evidence", "incident"})
SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
ASSET_TYPES = frozenset({"PR", "SP"})


def is_lockfile_path(name: Any) -> bool:
    """True when the asset name/path is package-lock.json (any directory prefix)."""
    text = str(name or "").replace("\\", "/").strip().lower()
    if not text:
        return False
    return text.rsplit("/", 1)[-1] == "package-lock.json"


def asset_type_for_name(name: Any, default: str = "SP") -> str:
    """Lockfile paths are supporting (SP) only — never primary."""
    if is_lockfile_path(name):
        return "SP"
    return default if default in ASSET_TYPES else "SP"
FINDING_CSV_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
FINDING_STATUSES = frozenset({"open", "closed", "in_progress"})
VULN_SEVERITIES = frozenset({"Information", "Low", "Medium", "High", "Critical"})
CONTROL_STATUSES = frozenset({"to_do", "in_progress", "on_hold", "active", "deprecated"})
CONTROL_CATEGORIES = frozenset({"policy", "process", "technical", "physical", "procedure"})
CSF_FUNCTIONS = frozenset({"govern", "identify", "protect", "detect", "respond", "recover"})
RR_LIKELIHOODS = frozenset({"RARE", "UNLIKELY", "POSSIBLE", "LIKELY", "ALMOST_CERTAIN"})
RR_IMPACTS = frozenset({"NEGLIGIBLE", "MINOR", "MODERATE", "MAJOR", "SEVERE"})

_SEV_ALIASES = {
    "informational": "info",
    "information": "info",
    "info": "info",
    "inf": "info",
    "low": "low",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
    "crit": "critical",
    "fail": "high",
    "failed": "high",
    "warning": "medium",
    "error": "high",
}

_VULN_FROM_CANON = {
    "info": "Information",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}

_RR_FROM_CANON = {
    "info": ("RARE", "NEGLIGIBLE"),
    "low": ("UNLIKELY", "MINOR"),
    "medium": ("POSSIBLE", "MODERATE"),
    "high": ("LIKELY", "MAJOR"),
    "critical": ("ALMOST_CERTAIN", "SEVERE"),
}

_OCSF_SEV_ID = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

_FINDING_STATUS_ALIASES = {
    "open": "open",
    "new": "open",
    "active": "open",
    "fail": "open",
    "failed": "open",
    "unresolved": "open",
    "true": "open",
    "noncompliant": "open",
    "non_compliant": "open",
    "issue": "open",
    "detected": "open",
    "present": "open",
    "exploitable": "open",
    "todo": "open",
    "to_do": "open",
    "not_started": "open",
    "unknown": "open",
    "closed": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "pass": "closed",
    "passed": "closed",
    "false": "closed",
    "mitigated": "closed",
    "compliant": "closed",
    "done": "closed",
    "complete": "closed",
    "completed": "closed",
    "inactive": "closed",
    "archived": "closed",
    "false_positive": "closed",
    "ignored": "closed",
    "suppressed": "closed",
    "wont_fix": "closed",
    "wontfix": "closed",
    "won_t_fix": "closed",
    "not_applicable": "closed",
    "na": "closed",
    "n_a": "closed",
    "in_progress": "in_progress",
    "investigating": "in_progress",
    "pending": "in_progress",
    "acknowledged": "in_progress",
    "ack": "in_progress",
    "wip": "in_progress",
    "remediation": "in_progress",
    "remediating": "in_progress",
    "working": "in_progress",
    "assigned": "in_progress",
    "accepted": "in_progress",
    "notified": "in_progress",
    "manual": "in_progress",
    "warning": "in_progress",
}


def normalize_severity(value: Any) -> str:
    if value is None:
        return "info"
    key = str(value).strip().lower()
    if key in SEVERITIES:
        return key
    return _SEV_ALIASES.get(key, "info")


def normalize_finding_status(value: Any) -> str:
    """Map sensor lifecycle labels onto CISO findings.csv status."""
    if value is None:
        return "open"
    raw = str(value).strip().lower()
    if not raw:
        return "open"
    key = re.sub(r"[^a-z0-9]+", "_", raw).strip("_")
    if key in FINDING_STATUSES:
        return key
    return _FINDING_STATUS_ALIASES.get(key, "open")


def severity_to_vuln(value: Any) -> str:
    return _VULN_FROM_CANON[normalize_severity(value)]


def severity_to_riskready(value: Any) -> tuple[str, str]:
    return _RR_FROM_CANON[normalize_severity(value)]


def ocsf_severity_id(value: Any) -> int:
    return _OCSF_SEV_ID[normalize_severity(value)]


def slug(text: str, max_len: int = 48) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", str(text)).strip("-").upper()
    return (cleaned or "X")[:max_len]


def make_ref_id(prefix: str, *parts: str) -> str:
    body = slug("-".join(str(p) for p in parts if p), 56)
    prefix = prefix if prefix.endswith("-") else prefix + "-"
    return f"{prefix}{body}"


@dataclass
class Record:
    kind: str
    ref_id: str
    name: str
    description: str = ""
    source: str = ""
    severity: str | None = None
    status: str | None = None
    asset_type: str | None = None
    domain: str = "default"
    labels: list[str] = field(default_factory=list)
    related_assets: list[str] = field(default_factory=list)
    reference_link: str = ""
    observation: str = ""
    parent_assets: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_canonical(self) -> dict[str, Any]:
        if self.kind not in KINDS:
            raise ValueError(f"invalid kind {self.kind}")
        asset_type = self.asset_type
        if self.kind == "asset":
            asset_type = asset_type if asset_type in ASSET_TYPES else "SP"
        sev = normalize_severity(self.severity) if self.severity is not None else None
        if self.kind == "finding" and sev is None:
            sev = "info"
        status = self.status
        if self.kind == "finding":
            status = normalize_finding_status(status)
        return {
            "kind": self.kind,
            "ref_id": self.ref_id,
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "severity": sev,
            "status": status,
            "asset_type": asset_type,
            "domain": self.domain or "default",
            "labels": list(self.labels),
            "related_assets": list(self.related_assets),
            "reference_link": self.reference_link,
            "observation": self.observation,
            "parent_assets": list(self.parent_assets),
            "extra": dict(self.extra),
        }


def asset(
    prefix: str,
    key: str,
    name: str,
    *,
    description: str = "",
    asset_type: str = "SP",
    source: str,
    domain: str = "default",
    labels: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> Record:
    return Record(
        kind="asset",
        ref_id=make_ref_id(prefix, key),
        name=name,
        description=description or name,
        source=source,
        asset_type=asset_type if asset_type in ASSET_TYPES else "SP",
        domain=domain,
        labels=labels or [],
        extra=extra or {},
    )


def finding(
    prefix: str,
    key: str,
    name: str,
    *,
    description: str,
    severity: str,
    source: str,
    related_assets: list[str] | None = None,
    status: str = "open",
    domain: str = "default",
    labels: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> Record:
    return Record(
        kind="finding",
        ref_id=make_ref_id(prefix, key),
        name=name,
        description=description,
        source=source,
        severity=normalize_severity(severity),
        status=normalize_finding_status(status),
        domain=domain,
        labels=labels or [],
        related_assets=related_assets or [],
        extra=extra or {},
    )


def evidence(
    prefix: str,
    key: str,
    name: str,
    *,
    description: str,
    source: str,
    related_assets: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> Record:
    return Record(
        kind="evidence",
        ref_id=make_ref_id(prefix, "EV", key),
        name=name,
        description=description,
        source=source,
        related_assets=related_assets or [],
        extra=extra or {},
    )


def incident(
    prefix: str,
    key: str,
    name: str,
    *,
    description: str,
    severity: str,
    source: str,
    related_assets: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> Record:
    return Record(
        kind="incident",
        ref_id=make_ref_id(prefix, "INC", key),
        name=name,
        description=description,
        source=source,
        severity=normalize_severity(severity),
        status="open",
        related_assets=related_assets or [],
        extra=extra or {},
    )


def control_extra(
    ref_id: str,
    name: str,
    *,
    category: str = "technical",
    csf_function: str = "protect",
    priority: str = "2",
    status: str = "to_do",
    description: str = "",
) -> dict[str, Any]:
    return {
        "control": {
            "ref_id": ref_id,
            "name": name,
            "description": description or name,
            "domain": "default",
            "status": status if status in CONTROL_STATUSES else "to_do",
            "category": category if category in CONTROL_CATEGORIES else "technical",
            "priority": str(priority),
            "csf_function": csf_function if csf_function in CSF_FUNCTIONS else "protect",
        }
    }
