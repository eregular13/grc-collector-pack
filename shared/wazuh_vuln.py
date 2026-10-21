"""Wazuh vulnerability-detector output -> per (agent, CVE, package) rows. Parse-only.

Accepted public shapes:
- alerts (alerts.json lines, an ``alerts`` list, or an indexer ``hits.hits``
  export) whose ``data.vulnerability`` holds {cve, package{name,version},
  severity, status, title} (rule group ``vulnerability-detector``);
- Wazuh 4.8+ vulnerability states (``wazuh-states-vulnerabilities-*`` index
  documents / dashboard export): top-level ``vulnerability`` {id, severity},
  ``package`` {name, version}, ``agent`` {name, id};
- API ``GET /vulnerability/{agent_id}`` (Wazuh <=4.7): ``data.affected_items``
  rows with {cve, name, version, severity, status}, agent from the file or
  ``agent_id``.

Structured CVE fields only (``cve`` / ``vulnerability.id``). Rows whose
latest status is Solved/Fixed are not open findings and are skipped.
"""
from __future__ import annotations

import re
from typing import Any

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_CLOSED = {"solved", "fixed", "resolved", "obsolete"}


def _cve(raw: Any) -> str:
    cid = str(raw or "").strip().upper()
    return cid if CVE_RE.match(cid) else ""


def _pkg(vuln: dict[str, Any], doc: dict[str, Any]) -> tuple[str, str]:
    pkg = vuln.get("package") if isinstance(vuln.get("package"), dict) else {}
    if not pkg and isinstance(doc.get("package"), dict):
        pkg = doc["package"]
    name = str(pkg.get("name") or vuln.get("name") or "").strip()
    version = str(pkg.get("version") or vuln.get("version") or "").strip()
    return name, version


def _agent(doc: dict[str, Any], default: str = "") -> str:
    agent = doc.get("agent") if isinstance(doc.get("agent"), dict) else {}
    return str(agent.get("name") or agent.get("id") or doc.get("agent_name") or doc.get("agent_id") or default or "unknown").strip()


def is_vuln_alert(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
    if isinstance(data.get("vulnerability"), dict) and _cve(data["vulnerability"].get("cve") or data["vulnerability"].get("id")):
        return True
    return False


def _is_state_doc(doc: Any) -> bool:
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("vulnerability"), dict)
        and bool(_cve(doc["vulnerability"].get("id") or doc["vulnerability"].get("cve")))
    )


def _is_api_item(row: Any) -> bool:
    return isinstance(row, dict) and bool(_cve(row.get("cve"))) and bool(row.get("name") or row.get("package"))


def _docs(payload: Any) -> list[dict[str, Any]]:
    """Flatten list / alerts / hits.hits[_source] containers into documents."""
    out: list[dict[str, Any]] = []
    if isinstance(payload, list):
        for row in payload:
            out.extend(_docs(row))
        return out
    if not isinstance(payload, dict):
        return out
    if is_vuln_alert(payload) or _is_state_doc(payload):
        return [payload]
    if isinstance(payload.get("_source"), dict):
        return _docs(payload["_source"])
    for key in ("alerts", "hits"):
        inner = payload.get(key)
        if isinstance(inner, dict):
            out.extend(_docs(inner.get("hits") if isinstance(inner.get("hits"), list) else []))
        elif isinstance(inner, list):
            out.extend(_docs(inner))
    return out


def iter_wazuh_vulns(payload: Any, default_agent: str = "") -> list[dict[str, Any]]:
    """Open vulnerability rows, latest state per (agent, cve, package) wins."""
    raw: list[dict[str, Any]] = []
    for doc in _docs(payload):
        if is_vuln_alert(doc):
            vuln = doc["data"]["vulnerability"]
            rule = doc.get("rule") if isinstance(doc.get("rule"), dict) else {}
            name, version = _pkg(vuln, doc)
            raw.append({
                "agent": _agent(doc, default_agent),
                "cve": _cve(vuln.get("cve") or vuln.get("id")),
                "pkg": name, "version": version,
                "severity": str(vuln.get("severity") or "").strip(),
                "status": str(vuln.get("status") or "").strip(),
                "title": str(vuln.get("title") or rule.get("description") or "").strip(),
                "time": str(doc.get("timestamp") or vuln.get("updated") or vuln.get("published") or ""),
                "rule_id": str(rule.get("id") or ""),
                "shape": "alert",
            })
        elif _is_state_doc(doc):
            vuln = doc["vulnerability"]
            name, version = _pkg(vuln, doc)
            raw.append({
                "agent": _agent(doc, default_agent),
                "cve": _cve(vuln.get("id") or vuln.get("cve")),
                "pkg": name, "version": version,
                "severity": str(vuln.get("severity") or "").strip(),
                "status": str(vuln.get("status") or "").strip(),
                "title": str(vuln.get("description") or "").strip()[:200],
                "time": str(vuln.get("detected_at") or doc.get("@timestamp") or ""),
                "rule_id": "",
                "shape": "state",
            })
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        items = payload["data"].get("affected_items")
        if isinstance(items, list):
            for row in items:
                if not _is_api_item(row):
                    continue
                raw.append({
                    "agent": str(row.get("agent_name") or row.get("agent_id") or payload.get("agent_id") or default_agent or "unknown"),
                    "cve": _cve(row.get("cve")),
                    "pkg": str(row.get("name") or row.get("package") or "").strip(),
                    "version": str(row.get("version") or "").strip(),
                    "severity": str(row.get("severity") or "").strip(),
                    "status": str(row.get("status") or "").strip(),
                    "title": str(row.get("title") or "").strip(),
                    "time": str(row.get("detection_time") or row.get("updated") or ""),
                    "rule_id": "",
                    "shape": "api",
                })
    latest: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in sorted(raw, key=lambda r: r["time"]):
        latest[(row["agent"].lower(), row["cve"], row["pkg"].lower())] = row
    return [r for r in latest.values() if r["status"].lower() not in _CLOSED]


def has_wazuh_vulns(payload: Any) -> bool:
    if _docs(payload):
        return True
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        items = payload["data"].get("affected_items")
        return isinstance(items, list) and any(_is_api_item(r) for r in items)
    return False


def is_vuln_doc(row: Any) -> bool:
    """A vulnerability alert/state doc/API row (never a Wazuh agent record)."""
    return bool(_docs(row)) or _is_api_item(row)
