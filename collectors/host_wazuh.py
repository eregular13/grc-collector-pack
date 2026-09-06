from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.io_util import discover_input_files, emit, load_structured
from shared.schema import asset, control_extra, evidence, finding, incident, normalize_severity

SOURCE = "host_wazuh"
PREFIX = "WAZ-"


def _is_alert_item(item: dict[str, Any]) -> bool:
    rule = item.get("rule")
    if isinstance(rule, dict) and (
        rule.get("level") is not None or rule.get("id") or rule.get("description")
    ):
        return True
    return False


def _agents(doc: dict[str, Any]) -> list[dict[str, Any]]:
    data = doc.get("data") or doc
    if not isinstance(data, dict):
        data = doc
    items = data.get("affected_items") or data.get("agents") or doc.get("agents") or []
    return [i for i in items if isinstance(i, dict) and not _is_alert_item(i)]


def _rule_level_severity(raw: Any) -> str:
    """Wazuh rule.level 0-15 → canonical severity. Empty if not numeric."""
    try:
        level = int(float(str(raw).strip()))
    except (TypeError, ValueError):
        return ""
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "medium"
    if level >= 3:
        return "low"
    return "info"


def _alert_severity(alert: dict[str, Any], rule: dict[str, Any]) -> str:
    mapped = _rule_level_severity(rule.get("level"))
    if mapped:
        return mapped
    mapped = _rule_level_severity(alert.get("level"))
    if mapped:
        return mapped
    named = alert.get("severity") or rule.get("severity")
    if named is not None and str(named).strip() != "":
        return normalize_severity(named)
    return "medium"


def _extract_alerts(doc: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
    wrapper = isinstance(data.get("affected_items"), list) or isinstance(data.get("alerts"), list)
    if _is_alert_item(doc) and not wrapper and not doc.get("alerts"):
        out.append(doc)
    for raw in doc.get("alerts") or []:
        if isinstance(raw, dict):
            out.append(raw)
    for key in ("alerts", "affected_items"):
        for raw in data.get(key) or []:
            if isinstance(raw, dict) and _is_alert_item(raw):
                out.append(raw)
    hits = doc.get("hits") if isinstance(doc.get("hits"), dict) else {}
    for hit in hits.get("hits") or []:
        if not isinstance(hit, dict):
            continue
        src = hit.get("_source") if isinstance(hit.get("_source"), dict) else hit
        if isinstance(src, dict) and _is_alert_item(src):
            out.append(src)
    return out


def _parse_alert(alert: dict[str, Any]) -> list:
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    aname = str(agent.get("name") or agent.get("id") or "unknown")
    rid = str(rule.get("id") or "alert")
    title = str(rule.get("description") or alert.get("full_log") or f"Wazuh rule {rid}")
    sev = _alert_severity(alert, rule)
    if sev == "info":
        return []
    decoder = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    srcip = str(decoder.get("srcip") or decoder.get("src_ip") or "")
    desc = title
    if srcip:
        desc = f"{title} srcip={srcip} agent={aname}."
    elif aname:
        desc = f"{title} agent={aname}."
    key = str(alert.get("id") or f"ALERT-{rid}")
    blob = f"{title} {rid}".lower()
    if "integrity" in blob or "syscheck" in blob or "checksum" in blob:
        extra = control_extra(
            "CTL-FIM",
            "File integrity monitoring response",
            csf_function="respond",
            priority="2",
        )
    else:
        extra = control_extra(
            "CTL-SIEM-TRIAGE",
            "Triage high-severity Wazuh alerts",
            csf_function="detect",
            priority="1" if sev in {"high", "critical"} else "2",
            category="technical",
        )
    extra["rule_id"] = rid
    extra["rule_level"] = rule.get("level")
    labels = ["wazuh", "alert"]
    if rule.get("level") is not None:
        labels.append(f"level-{rule.get('level')}")
    return [
        asset(
            PREFIX,
            aname,
            aname,
            description=f"Wazuh alert host {aname}",
            asset_type="SP",
            source=SOURCE,
            labels=["wazuh", "alert", "host"],
        ),
        finding(
            PREFIX,
            key,
            title,
            description=desc,
            severity=sev,
            source=SOURCE,
            related_assets=[aname],
            labels=labels,
            extra=extra,
        ),
    ]


def _agent_status(agent: dict[str, Any]) -> str:
    """Normalize Wazuh agent status (API uses Disconnected / Never connected)."""
    raw = (
        agent.get("status")
        or agent.get("connection_status")
        or agent.get("Status")
        or agent.get("ConnectionStatus")
        or "unknown"
    )
    key = str(raw).strip().lower().replace(" ", "_").replace("-", "_")
    return key or "unknown"


def parse_doc(doc: Any) -> list:
    if not isinstance(doc, dict):
        return []
    records: list = []
    for agent in _agents(doc):
        name = str(agent.get("name") or agent.get("id") or "agent")
        status = _agent_status(agent)
        ip = str(agent.get("ip") or "")
        os_name = ""
        os_obj = agent.get("os") or {}
        if isinstance(os_obj, dict):
            os_name = str(os_obj.get("name") or "")
        records.append(
            asset(
                PREFIX,
                name,
                name,
                description=f"Wazuh agent {name} ({ip}) os={os_name} status={status}",
                asset_type="SP",
                source=SOURCE,
                labels=["wazuh", "agent", status],
                extra={"agent_id": agent.get("id"), "ip": ip, "status": status},
            )
        )
        if status in {"disconnected", "never_connected"}:
            records.append(
                finding(
                    PREFIX,
                    f"DISC-{name}",
                    f"Wazuh agent disconnected: {name}",
                    description=f"Agent {name} is {status}. Host telemetry gap.",
                    severity="high",
                    source=SOURCE,
                    related_assets=[name],
                    labels=["wazuh", "disconnected"],
                    extra=control_extra(
                        "CTL-EDR-COVERAGE",
                        "Maintain endpoint agent coverage",
                        csf_function="detect",
                        priority="1",
                        category="technical",
                    ),
                )
            )
            records.append(
                incident(
                    PREFIX,
                    f"DISC-{name}",
                    f"Lost Wazuh agent {name}",
                    description=f"Agent {name} disconnected.",
                    severity="high",
                    source=SOURCE,
                    related_assets=[name],
                )
            )
    for alert in _extract_alerts(doc):
        records.extend(_parse_alert(alert))
    return records


def _is_osquery(doc: Any) -> bool:
    if isinstance(doc, list):
        return bool(doc) and all(isinstance(x, dict) for x in doc) and any(_is_osquery(x) for x in doc)
    if not isinstance(doc, dict):
        return False
    blob = doc.get("osquery")
    if isinstance(blob, dict):
        return True
    if isinstance(blob, list) and blob and isinstance(blob[0], dict):
        return True
    if doc.get("rows") is not None or doc.get("host_identifier") or doc.get("hostIdentifier"):
        return True
    if isinstance(doc.get("columns"), dict):
        return True
    if doc.get("name") and (doc.get("pack") or str(doc.get("action") or "").lower() in {"added", "removed", "snapshot"}):
        return True
    cols = _osquery_cols(doc)
    port = cols.get("port") if isinstance(cols, dict) else None
    if port is None:
        port = doc.get("port")
    if port is not None and (
        (isinstance(cols, dict) and (cols.get("address") is not None or cols.get("protocol") is not None))
        or doc.get("address") is not None
        or doc.get("protocol") is not None
    ):
        return True
    return False


def _osquery_cols(row: dict[str, Any]) -> dict[str, Any]:
    cols = row.get("columns")
    return cols if isinstance(cols, dict) else row


def _osquery_host(row: dict[str, Any], cols: dict[str, Any]) -> str:
    deco = row.get("decorations") if isinstance(row.get("decorations"), dict) else {}
    for blob in (row, cols, deco):
        if not isinstance(blob, dict):
            continue
        for key in ("hostIdentifier", "host_identifier", "hostname", "host"):
            val = blob.get(key)
            if val:
                return str(val)
    return "osquery-host"


def parse_osquery(doc: Any) -> list:
    if isinstance(doc, list):
        records: list = []
        for item in doc:
            if isinstance(item, dict) or isinstance(item, list):
                records.extend(parse_osquery(item))
        return records
    if not isinstance(doc, dict):
        return []
    blob = doc.get("osquery")
    if isinstance(blob, dict):
        inner = dict(blob)
        agent = doc.get("agent") if isinstance(doc.get("agent"), dict) else {}
        if agent.get("name") and not inner.get("hostIdentifier") and not inner.get("host_identifier"):
            inner["hostIdentifier"] = agent.get("name")
        doc = inner
    elif isinstance(blob, list):
        host_fb = _osquery_host(doc, {})
        records = []
        for item in blob:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            if host_fb != "osquery-host" and _osquery_host(row, _osquery_cols(row)) == "osquery-host":
                row["hostIdentifier"] = host_fb
            records.extend(parse_osquery(row))
        return records
    rows = doc.get("rows")
    if rows is None:
        rows = [doc]
    query = str(doc.get("name") or doc.get("pack") or "osquery")
    records: list = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cols = _osquery_cols(row)
        host = _osquery_host(row, cols)
        if host == "osquery-host":
            host = _osquery_host(doc, cols)
        port = str(cols.get("port") or row.get("port") or "")
        pname = str(cols.get("name") or cols.get("path") or row.get("name") or query)
        records.append(
            asset(
                PREFIX,
                host,
                host,
                description=f"Osquery host {host}",
                asset_type="SP",
                source=SOURCE,
                labels=["osquery", "host"],
            )
        )
        if port in {"23", "445", "3389"} or "telnet" in pname.lower():
            records.append(
                finding(
                    PREFIX,
                    f"OSQ-{host}-{port or pname}",
                    f"Osquery listening service {pname} on {host}",
                    description=f"Query {query}: {pname} port={port or 'n/a'} on {host}.",
                    severity="high" if port in {"23", "445"} or "telnet" in pname.lower() else "medium",
                    source=SOURCE,
                    related_assets=[host],
                    labels=["osquery", "listening"],
                    extra=control_extra(
                        "CTL-HOST-HARDEN",
                        "Disable insecure listening services",
                        csf_function="protect",
                        priority="2",
                    ),
                )
            )
    return records


def _is_sca(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    if isinstance(doc.get("sca"), dict):
        return True
    if doc.get("policy_id") and (
        doc.get("checks") or doc.get("result") is not None or doc.get("fail") is not None
    ):
        return True
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
    items = data.get("affected_items") or data.get("checks") or doc.get("checks") or []
    if not isinstance(items, list) or not items or not isinstance(items[0], dict):
        return False
    sample = items[0]
    if sample.get("policy_id") and (
        sample.get("result") is not None or sample.get("title") or sample.get("fail") is not None
    ):
        return True
    result = str(sample.get("result") or "").lower()
    return bool(sample.get("title") and result in {"failed", "passed", "fail", "pass", "not applicable"})


def _sca_severity(title: str) -> str:
    blob = title.lower()
    if any(
        tok in blob
        for tok in ("password", "rdp", "administrator", "guest", "firewall", "root", "anonymous")
    ):
        return "high"
    return "medium"


def _sca_host(doc: dict[str, Any], item: dict[str, Any]) -> str:
    agent = item.get("agent") if isinstance(item.get("agent"), dict) else None
    if agent and agent.get("name"):
        return str(agent["name"])
    if isinstance(item.get("agent"), str) and item["agent"]:
        return str(item["agent"])
    wrap = doc.get("agent") if isinstance(doc.get("agent"), dict) else {}
    return str(wrap.get("name") or doc.get("agent_name") or doc.get("hostname") or "wazuh-agent")


def parse_sca(doc: Any) -> list:
    if not isinstance(doc, dict):
        return []
    records: list = []
    checks: list[dict[str, Any]] = []
    sca = doc.get("sca") if isinstance(doc.get("sca"), dict) else {}
    if sca:
        if isinstance(sca.get("check"), dict):
            blob = dict(sca["check"])
            blob.setdefault("policy_id", sca.get("policy_id"))
            checks.append(blob)
        elif sca.get("title") or sca.get("result"):
            checks.append(sca)
        for item in sca.get("checks") or []:
            if isinstance(item, dict):
                checks.append(item)
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
    items = data.get("affected_items") or data.get("checks") or doc.get("checks") or []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("title") or item.get("result"):
            checks.append(item)
            continue
        fail = item.get("fail")
        if fail is None:
            continue
        try:
            fail_n = int(fail)
        except (TypeError, ValueError):
            fail_n = 0
        if fail_n <= 0:
            continue
        policy = str(item.get("policy_id") or item.get("name") or "sca")
        host = _sca_host(doc, item)
        title = str(item.get("name") or policy)
        records.append(
            asset(
                PREFIX,
                host,
                host,
                description=f"Wazuh SCA host {host}",
                asset_type="SP",
                source=SOURCE,
                labels=["wazuh", "sca", "host"],
            )
        )
        records.append(
            finding(
                PREFIX,
                f"SCA-{policy}-SUMMARY",
                f"SCA policy failed checks: {title}",
                description=f"Policy {policy} on {host}: fail={fail_n} pass={item.get('pass')} score={item.get('score')}.",
                severity="high" if fail_n >= 5 else "medium",
                source=SOURCE,
                related_assets=[host],
                labels=["wazuh", "sca", policy],
                extra=control_extra(
                    "CTL-SCA-HARDEN",
                    "Remediate Wazuh SCA failed checks",
                    csf_function="protect",
                    priority="2",
                    category="technical",
                ),
            )
        )
    for check in checks:
        result = str(check.get("result") or check.get("status") or "").lower()
        if result in {"passed", "pass", "not applicable", "n/a", "ok"}:
            continue
        if result not in {"failed", "fail", "invalid"}:
            continue
        title = str(check.get("title") or check.get("name") or "SCA check")
        cid = str(check.get("id") or check.get("check_id") or title)
        policy = str(check.get("policy_id") or sca.get("policy_id") or doc.get("policy_id") or "sca")
        host = _sca_host(doc, check)
        desc = str(check.get("description") or check.get("rationale") or title)
        rem = str(check.get("remediation") or "")
        records.append(
            asset(
                PREFIX,
                host,
                host,
                description=f"Wazuh SCA host {host}",
                asset_type="SP",
                source=SOURCE,
                labels=["wazuh", "sca", "host"],
            )
        )
        records.append(
            finding(
                PREFIX,
                f"SCA-{policy}-{cid}",
                f"SCA failed: {title}",
                description=f"{desc} policy={policy} host={host}. {rem}".strip(),
                severity=_sca_severity(title),
                source=SOURCE,
                related_assets=[host],
                labels=["wazuh", "sca", policy],
                extra=control_extra(
                    "CTL-SCA-HARDEN",
                    "Remediate Wazuh SCA failed checks",
                    csf_function="protect",
                    priority="1" if _sca_severity(title) == "high" else "2",
                    category="technical",
                ),
            )
        )
    return records


def parse_files(files: list[Path]) -> list:
    records: list = []
    for path in files:
        for doc in load_structured(path):
            if _is_osquery(doc):
                records.extend(parse_osquery(doc))
            elif _is_sca(doc):
                records.extend(parse_sca(doc))
            else:
                records.extend(parse_doc(doc))
    return records


def main() -> None:
    files = discover_input_files("wazuh")
    records = parse_files(files)
    records.append(
        evidence(
            PREFIX,
            "WAZUH",
            "Wazuh demo parse",
            description="Parsed Wazuh agent inventory, alerts (data/rule.level, no live API), SCA policy-checks, and Osquery rows (including osquery list wrappers). Healthy and disconnected agents included. No live agent query.",
            source=SOURCE,
        )
    )
    emit("wazuh", records, files)


if __name__ == "__main__":
    main()
