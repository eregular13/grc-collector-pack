"""Canonical record helpers and GRC severity alphabets."""

from __future__ import annotations

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

_SEV_ALIASES = {
    "informational": "info",
    "information": "info",
    "none": "info",
    "info": "info",
    "low": "low",
    "med": "medium",
    "moderate": "medium",
    "mod": "medium",
    "medium": "medium",
    "high": "high",
    "crit": "critical",
    "critical": "critical",
    "severe": "critical",
}

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
}


def canon_severity(raw: Any) -> str:
    s = str(raw or "info").strip().lower()
    return _SEV_ALIASES.get(s, s if s in FINDING_SEV else "info")


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
    rec = {
        "kind": kind,
        "source": source,
        "ref_id": ref_id,
        "name": name,
        "description": description,
        "severity": canon_severity(severity),
        "status": status,
        "category": category,
        "assets": [str(a) for a in (assets or []) if a],
        "labels": [str(x) for x in (labels or []) if x],
        "collected_at": collected_at,
        "extra": extra or {},
    }
    return rec
