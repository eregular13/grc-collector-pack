"""Canonical record helpers and GRC severity alphabets."""

from __future__ import annotations

import re
from typing import Any, Iterable

KINDS = frozenset({"asset", "finding", "evidence", "incident"})
FINDING_SEV = frozenset({"info", "low", "medium", "high", "critical"})
ASSET_TYPES = frozenset({"PR", "SP"})
CISO_FINDING_SEV = frozenset({"low", "medium", "high", "critical"})
CISO_VULN_SEV = frozenset({"Information", "Low", "Medium", "High", "Critical"})
SCENARIO_LEVELS = frozenset({"Low", "Moderate", "High", "Very High"})
RR_LIKELIHOOD = frozenset(
    {"RARE", "UNLIKELY", "POSSIBLE", "LIKELY", "ALMOST_CERTAIN"}
)
RR_IMPACT = frozenset(
    {"NEGLIGIBLE", "MINOR", "MODERATE", "MAJOR", "SEVERE"}
)

# Vendor vocabularies seen in file-drop tools (semgrep, testssl, ScoutSuite,
# Falco, RH/Oracle, kube-bench WARN, checkov, etc.). Unknown words must not
# silently become info — see map_severity / extra.severity_unmapped.
_SEV_ALIASES = {
    "informational": "info",
    "information": "info",
    "none": "info",
    "info": "info",
    "negligible": "info",
    "note": "info",
    "debug": "info",
    "trace": "info",
    "low": "low",
    "minor": "low",
    "notice": "low",
    "med": "medium",
    "moderate": "medium",
    "mod": "medium",
    "medium": "medium",
    "warning": "medium",
    "warn": "medium",
    "high": "high",
    "error": "high",
    "err": "high",
    "important": "high",
    "major": "high",
    "danger": "high",
    "crit": "critical",
    "critical": "critical",
    "severe": "critical",
    "fatal": "critical",
    "emergency": "critical",
    "alert": "critical",
    "panic": "critical",
}
_CVSS_RE = re.compile(r"^\d+(?:\.\d+)?$")

_CISO_VULN = {
    "info": "Information",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}

_SCENARIO = {
    "info": "Low",
    "low": "Low",
    "medium": "Moderate",
    "high": "High",
    "critical": "Very High",
}

_RR = {
    "info": ("RARE", "NEGLIGIBLE"),
    "low": ("UNLIKELY", "MINOR"),
    "medium": ("POSSIBLE", "MODERATE"),
    "high": ("LIKELY", "MAJOR"),
    "critical": ("ALMOST_CERTAIN", "SEVERE"),
}

_CSF = {
    "info": "identify",
    "low": "identify",
    "medium": "protect",
    "high": "protect",
    "critical": "respond",
}

PREFIX = {
    "cloud-prowler": "CLD",
    "inventory-nmap": "NMAP",
    "vuln-scan": "VULN",
    "host-wazuh": "WAZ",
    "identity-ad": "ID",
    "easm": "EASM",
    "k8s-kubescape": "K8S",
    "code-secrets": "CODE",
    "saas-idp": "SAAS",
    "honeypot": "HPOT",
    "dns-email": "DNS",
}


def _cvss_band(raw: str) -> str | None:
    """Map a bare CVSS 0–10 number. Reject inf/nan and out-of-range values."""
    s = str(raw or "").strip()
    if not s or not _CVSS_RE.fullmatch(s):
        return None
    try:
        n = float(s)
    except ValueError:
        return None
    if n < 0 or n > 10:
        return None
    if n == 0:
        return "info"
    if n < 4.0:
        return "low"
    if n < 7.0:
        return "medium"
    if n < 9.0:
        return "high"
    return "critical"


def map_severity(raw: Any) -> tuple[str, bool]:
    """Return (canonical severity, unmapped).

    Empty / missing → info (not a vendor word). Known aliases and CVSS
    numbers map in-band. Any other token → medium and unmapped=True so the
    loader can count extra.severity_unmapped instead of silently using info.
    """
    if raw is None:
        return "info", False
    text = str(raw).strip()
    if not text:
        return "info", False
    s = text.lower()
    if s in _SEV_ALIASES:
        return _SEV_ALIASES[s], False
    if s in FINDING_SEV:
        return s, False
    cvss = _cvss_band(s)
    if cvss is not None:
        return cvss, False
    return "medium", True


def canon_severity(raw: Any) -> str:
    sev, _unmapped = map_severity(raw)
    return sev


def ciso_finding_severity(raw: Any) -> str:
    s = canon_severity(raw)
    return "low" if s == "info" else s


def ciso_vuln_severity(raw: Any) -> str:
    return _CISO_VULN[canon_severity(raw)]


def scenario_level(raw: Any) -> str:
    return _SCENARIO[canon_severity(raw)]


def rr_likelihood_impact(raw: Any) -> tuple[str, str]:
    return _RR[canon_severity(raw)]


def csf_function(raw: Any) -> str:
    return _CSF[canon_severity(raw)]


def control_priority(raw: Any) -> int:
    return {"info": 4, "low": 3, "medium": 2, "high": 1, "critical": 1}[canon_severity(raw)]


def residual_level(level: str) -> str:
    order = ["Low", "Moderate", "High", "Very High"]
    if level not in order:
        return "Low"
    idx = max(0, order.index(level) - 1)
    return order[idx]


def slug(text: str, maxlen: int = 48) -> str:
    out = []
    for ch in (text or "").lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in "-_." and (not out or out[-1] != "-"):
            out.append("-")
        elif ch in " /:\\" and (not out or out[-1] != "-"):
            out.append("-")
    s = "".join(out).strip("-") or "item"
    return s[:maxlen]


def make_ref(source: str, key: str) -> str:
    prefix = PREFIX.get(source, "GRC")
    return f"{prefix}-{slug(key)}"


def make_record(
    *,
    kind: str,
    source: str,
    ref_id: str,
    name: str,
    description: str = "",
    severity: str = "info",
    status: str = "identified",
    category: str = "",
    assets: Iterable[str] | None = None,
    labels: Iterable[str] | None = None,
    collected_at: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if kind not in KINDS:
        raise ValueError(f"invalid kind {kind}")
    sev, unmapped = map_severity(severity)
    extra_out = dict(extra or {})
    if unmapped:
        extra_out["severity_unmapped"] = True
        extra_out.setdefault("severity_raw", str(severity))
    rec = {
        "kind": kind,
        "source": source,
        "ref_id": ref_id,
        "name": name,
        "description": description,
        "severity": sev,
        "status": status,
        "category": category,
        "assets": [str(a) for a in (assets or []) if a],
        "labels": [str(x) for x in (labels or []) if x],
        "collected_at": collected_at,
        "extra": extra_out,
    }
    return rec
