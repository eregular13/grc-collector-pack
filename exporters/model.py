"""Shared pack estate loaded from the CISO Assistant intermediate.

The prove path (`run_ciso_path` / `python3 -m dropbox ciso`) writes
`out/ciso-assistant/*.csv`. This module reads those headers as-is so
OpenGRC and Probo sinks cannot drift from the CISO contract.
"""

from __future__ import annotations

import csv
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.schema import canon_severity, ciso_finding_severity

ROOT = Path(__file__).resolve().parents[1]
CISO_DIR_NAMES = ("ciso-assistant", "ciso_drop", "ciso")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HONESTY_BANNER = (
    "SAMPLE/DEMO — not a client estate. File-drop parse only. "
    "posted=false. Not a paying-day stamp."
)

# OpenGRC 1–5 likelihood/impact. Residual is one step down (never invented 0).
_SEV_SCORE = {
    "info": 2,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
_SCENARIO_SCORE = {
    "low": 2,
    "moderate": 3,
    "high": 4,
    "very high": 5,
    "veryhigh": 5,
}


def out_dir(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return Path(explicit)
    raw = os.environ.get("OUT_DIR")
    return Path(raw) if raw else ROOT / "out"


def find_ciso_dir(out: Path) -> Path:
    """Prefer ciso-assistant, then ciso_drop, then product-lab/drop/ciso."""
    out = Path(out)
    for name in CISO_DIR_NAMES:
        path = out / name
        if path.is_dir() and (
            (path / "findings.csv").is_file() or (path / "assets.csv").is_file()
        ):
            return path
    if (out / "findings.csv").is_file() or (out / "assets.csv").is_file():
        return out
    return out / "ciso-assistant"


def _split_labels(raw: Any) -> list[str]:
    text = str(raw or "").strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def _looks_sample(labels: list[str], *texts: str) -> bool:
    blob = " ".join(labels + [str(t or "") for t in texts]).lower()
    if "demo" in labels or "sample" in labels:
        return True
    return "demo" in blob or "sample" in blob or "not a client" in blob


def extract_ipv4(*texts: str) -> str:
    for text in texts:
        match = IPV4_RE.search(str(text or ""))
        if match:
            return match.group(0)
    return ""


def extract_hostname(name: str, *texts: str) -> str:
    candidate = str(name or "").strip()
    if candidate and " " not in candidate and "." in candidate and not IPV4_RE.fullmatch(candidate):
        return candidate
    for text in texts:
        for token in re.findall(r"\b[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", str(text or "")):
            if not IPV4_RE.fullmatch(token):
                return token
    return ""


def score_severity(raw: Any) -> int:
    return _SEV_SCORE[canon_severity(raw)]


def score_scenario_level(raw: Any) -> int:
    key = str(raw or "").strip().lower()
    if key in _SCENARIO_SCORE:
        return _SCENARIO_SCORE[key]
    return score_severity(raw)


def residual_score(inherent: int) -> int:
    return max(1, inherent - 1)


@dataclass
class PackAsset:
    ref_id: str
    name: str
    description: str
    domain: str = "Global"
    type: str = "PR"
    reference_link: str = ""
    labels: list[str] = field(default_factory=list)
    hostname: str = ""
    ip_address: str = ""


@dataclass
class PackFinding:
    ref_id: str
    name: str
    description: str
    severity: str
    status: str = "identified"
    labels: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    kind: str = "finding"
    applied_controls: str = ""


@dataclass
class PackControl:
    ref_id: str
    name: str
    description: str
    status: str = "to_do"
    category: str = "technical"
    priority: str = ""
    csf_function: str = ""


@dataclass
class PackScenario:
    ref_id: str
    name: str
    description: str
    assets: str = ""
    threats: str = ""
    current_impact: str = ""
    current_proba: str = ""
    current_risk: str = ""
    residual_impact: str = ""
    residual_proba: str = ""
    residual_risk: str = ""
    treatment: str = "mitigate"
    additional_controls: str = ""


@dataclass
class PackEstate:
    assets: list[PackAsset] = field(default_factory=list)
    findings: list[PackFinding] = field(default_factory=list)
    vulnerabilities: list[PackFinding] = field(default_factory=list)
    controls: list[PackControl] = field(default_factory=list)
    scenarios: list[PackScenario] = field(default_factory=list)
    evidences: list[tuple[str, str]] = field(default_factory=list)
    sample: bool = True
    demo: bool = True
    client: bool = False
    posted: bool = False
    source: str = "ciso-assistant"
    origin: str = "ciso-assistant"

    @property
    def all_findings(self) -> list[PackFinding]:
        return list(self.findings) + list(self.vulnerabilities)

    def honesty(self) -> dict[str, Any]:
        return {
            "sample": True if self.sample else False,
            "demo": True if self.demo or self.sample else False,
            "client": False,
            "client_keep": False,
            "posted": False,
            "http": False,
            "paying_day": "FAIL",
            "estate": HONESTY_BANNER,
            "riskready": "stay-out — review-only; never a build target here",
            "source": self.source,
            "origin": self.origin,
        }


def _read_csv(path: Path, delimiter: str = ",") -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as fh:
        return [{str(k): ("" if v is None else str(v)) for k, v in row.items()} for row in csv.DictReader(fh, delimiter=delimiter)]


def load_pack_estate(out: Path | None = None) -> PackEstate:
    """Load the CISO intermediate. Never invent owner/due. Never mark client."""
    dest = out_dir(out)
    ciso = find_ciso_dir(dest)
    assets: list[PackAsset] = []
    sample = False
    for row in _read_csv(ciso / "assets.csv"):
        name = (row.get("name") or row.get("ref_id") or "").strip()
        ref = (row.get("ref_id") or name).strip()
        if not ref:
            continue
        labels = _split_labels(row.get("filtering_labels"))
        desc = (row.get("description") or "").strip()
        link = (row.get("reference_link") or "").strip()
        sample = sample or _looks_sample(labels, name, desc)
        assets.append(
            PackAsset(
                ref_id=ref,
                name=name or ref,
                description=desc,
                domain=(row.get("domain") or "Global").strip() or "Global",
                type=(row.get("type") or "PR").strip() or "PR",
                reference_link=link,
                labels=labels,
                hostname=extract_hostname(name, desc, link),
                ip_address=extract_ipv4(name, desc, link),
            )
        )

    findings: list[PackFinding] = []
    for row in _read_csv(ciso / "findings.csv"):
        ref = (row.get("ref_id") or "").strip()
        if not ref:
            continue
        labels = _split_labels(row.get("filtering_labels"))
        desc = (row.get("description") or "").strip()
        name = (row.get("name") or ref).strip()
        sample = sample or _looks_sample(labels, name, desc)
        findings.append(
            PackFinding(
                ref_id=ref,
                name=name,
                description=desc,
                severity=ciso_finding_severity(row.get("severity")),
                status=(row.get("status") or "identified").strip() or "identified",
                labels=labels,
            )
        )

    vulns: list[PackFinding] = []
    for row in _read_csv(ciso / "vulnerabilities.csv"):
        ref = (row.get("ref_id") or "").strip()
        if not ref:
            continue
        assets_s = (row.get("assets") or "").strip()
        desc = (row.get("description") or "").strip()
        name = (row.get("name") or ref).strip()
        sample = sample or _looks_sample([], name, desc)
        vulns.append(
            PackFinding(
                ref_id=ref,
                name=name,
                description=desc,
                severity=ciso_finding_severity(row.get("severity")),
                status=(row.get("status") or "Exploitable").strip() or "Exploitable",
                assets=[part.strip() for part in assets_s.split("|") if part.strip()]
                or [part.strip() for part in assets_s.split(",") if part.strip()],
                kind="vulnerability",
                applied_controls=(row.get("applied_controls") or "").strip(),
            )
        )

    controls: list[PackControl] = []
    for row in _read_csv(ciso / "applied_controls.csv"):
        ref = (row.get("ref_id") or "").strip()
        if not ref:
            continue
        controls.append(
            PackControl(
                ref_id=ref,
                name=(row.get("name") or ref).strip(),
                description=(row.get("description") or "").strip(),
                status=(row.get("status") or "to_do").strip() or "to_do",
                category=(row.get("category") or "technical").strip() or "technical",
                priority=(row.get("priority") or "").strip(),
                csf_function=(row.get("csf_function") or "").strip(),
            )
        )

    scenarios: list[PackScenario] = []
    for row in _read_csv(ciso / "risk_scenarios.csv", delimiter=";"):
        ref = (row.get("ref_id") or "").strip()
        if not ref:
            continue
        scenarios.append(
            PackScenario(
                ref_id=ref,
                name=(row.get("name") or ref).strip(),
                description=(row.get("description") or "").strip(),
                assets=(row.get("assets") or "").strip(),
                threats=(row.get("threats") or "").strip(),
                current_impact=(row.get("current_impact") or "").strip(),
                current_proba=(row.get("current_proba") or "").strip(),
                current_risk=(row.get("current_risk") or "").strip(),
                residual_impact=(row.get("residual_impact") or "").strip(),
                residual_proba=(row.get("residual_proba") or "").strip(),
                residual_risk=(row.get("residual_risk") or "").strip(),
                treatment=(row.get("treatment") or "mitigate").strip() or "mitigate",
                additional_controls=(row.get("additional_controls") or "").strip(),
            )
        )

    evidences: list[tuple[str, str]] = []
    for row in _read_csv(ciso / "evidences.csv"):
        name = (row.get("name") or "").strip()
        if name:
            evidences.append((name, (row.get("description") or "").strip()))

    summary: dict[str, Any] = {}
    summary_path = dest / "summary.json"
    if summary_path.is_file():
        try:
            loaded = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                summary = loaded
        except json.JSONDecodeError:
            summary = {}
    demo = bool(summary.get("demo")) or sample
    # File-drop default: never claim a client estate from this pack.
    # SAMPLE/DEMO KEEP is enough — do not wait for denser KEEP.
    return PackEstate(
        assets=assets,
        findings=findings,
        vulnerabilities=vulns,
        controls=controls,
        scenarios=scenarios,
        evidences=evidences,
        sample=True,
        demo=True if demo or sample else True,
        client=False,
        posted=False,
        source="ciso-assistant",
        origin="keep-lab" if "keep" in str(dest).replace("\\", "/") else "ciso-assistant",
    )
