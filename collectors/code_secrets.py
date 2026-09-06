from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from shared.io_util import discover_input_files, emit, load_structured, redact_obj, redact_text
from shared.schema import asset, asset_type_for_name, control_extra, evidence, finding

SOURCE = "code_secrets"
PREFIX = "CODE-"


def _is_gitleaks_sarif(doc: Any, path: Path | None = None) -> bool:
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        return False
    name = (path.name if path is not None else "").lower()
    if "gitleaks" in name:
        return True
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool = str(driver.get("name") or driver.get("informationUri") or "").lower()
        if "gitleaks" in tool:
            return True
    return False


def parse_gitleaks_sarif(doc: dict[str, Any]) -> list:
    """Gitleaks -f sarif: runs[].results ruleId → RuleID; never copy snippet text."""
    items: list[dict[str, Any]] = []
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(
                result.get("ruleId") or result.get("ruleID") or result.get("RuleID") or ""
            )
            msg = result.get("message")
            if isinstance(msg, dict):
                desc = str(msg.get("text") or "")
            else:
                desc = str(msg or "")
            path, _start = _semgrep_path(result)
            items.append(
                {
                    "RuleID": rule_id or "secret",
                    "File": path or "unknown",
                    "Description": redact_text(desc or rule_id or "secret"),
                }
            )
    records = parse_gitleaks(items)
    for rec in records:
        if rec.kind == "finding" and "sarif" not in rec.labels:
            rec.labels.append("sarif")
    return records


def _gitleaks_rule(item: dict[str, Any]) -> str:
    """RuleID / DetectorName, else Fingerprint `file:rule:line` segment. Empty RuleID is not 'secret'."""
    for key in (
        "RuleID",
        "ruleID",
        "ruleId",
        "rule",
        "DetectorName",
        "detectorName",
        "detector",
    ):
        val = str(item.get(key) or "").strip()
        if val:
            return val
    fp = str(item.get("Fingerprint") or item.get("fingerprint") or "").strip()
    if fp:
        parts = fp.replace("\\", "/").split(":")
        if len(parts) >= 3 and re.fullmatch(r"\d+", parts[-1] or ""):
            rule = (parts[-2] or "").strip()
            if rule:
                return rule
        if len(parts) >= 2:
            tail = (parts[-1] or "").strip()
            if tail and not re.fullmatch(r"\d+", tail):
                return tail
    return "secret"


def _gitleaks_text(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    return str(value).strip().strip("\"'")


def _gitleaks_path(item: dict[str, Any]) -> tuple[str, bool]:
    """File/file, else Source/Path when File is empty/whitespace. Second value is True when Source was used."""
    for key in ("File", "file"):
        val = _gitleaks_text(item.get(key))
        if val:
            return val, False
    for key in ("Source", "source", "Path", "path"):
        val = _gitleaks_text(item.get(key))
        if val:
            return val, True
    return "unknown", False


def parse_gitleaks(items: list[Any]) -> list:
    records: list = []
    repo = "app-monorepo"
    records.append(
        asset(
            PREFIX,
            "REPO",
            repo,
            description="Application git repository (demo)",
            asset_type="SP",
            source=SOURCE,
            labels=["code", "repo"],
        )
    )
    for item in items:
        if not isinstance(item, dict):
            continue
        rule = _gitleaks_rule(item)
        path, from_source = _gitleaks_path(item)
        desc = redact_text(str(item.get("Description") or rule))
        extra = control_extra(
            "CTL-SECRET-SCAN",
            "Pre-commit secret scanning and rotation",
            csf_function="protect",
            priority="1",
            category="process",
        )
        for key, value in item.items():
            if key == "Description":
                continue
            extra[key] = value
        extra = redact_obj(extra)
        records.append(
            finding(
                PREFIX,
                rule + "-" + path,
                f"Secret detected: {rule}",
                description=f"{desc} in {path} (secret value redacted).",
                severity="critical" if "aws" in rule.lower() else "high",
                source=SOURCE,
                related_assets=[repo],
                labels=["code", "gitleaks", rule] + (["gitleaks-source"] if from_source else []),
                extra=extra,
            )
        )
    return records


def _trivy_misconfigs(result: dict[str, Any]) -> list[dict[str, Any]]:
    blob = (
        result.get("Misconfigurations")
        or result.get("Misconfs")
        or result.get("misconfigurations")
        or []
    )
    return [item for item in blob if isinstance(item, dict)]


def _trivy_misconfig_failed(item: dict[str, Any]) -> bool:
    """Trivy IaC Status PASS/EXCEPTION is skipped; missing Status is FAIL."""
    status = str(item.get("Status") or item.get("status") or "FAIL").strip().upper()
    status = status.replace(" ", "_").replace("-", "_")
    if status in {"PASS", "PASSED", "SUCCESS", "OK", "EXCEPTION", "EXCEPT", "IGNORE", "IGNORED"}:
        return False
    return True


def parse_trivy(doc: dict[str, Any]) -> list:
    records: list = []
    for result in doc.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "lockfile")
        klass = str(result.get("Class") or "").lower()
        misconfigs = _trivy_misconfigs(result)
        is_secret = klass == "secret" or bool(result.get("Secrets"))
        is_misconfig = klass == "config" or bool(misconfigs)
        if is_secret:
            kind_label, kind_desc = "secret", "Secret scan target"
        elif is_misconfig:
            kind_label, kind_desc = "misconfig", "Misconfig scan target"
        else:
            kind_label, kind_desc = "lockfile", "Lockfile"
        records.append(
            asset(
                PREFIX,
                target,
                target,
                description=f"{kind_desc} {target}",
                asset_type=asset_type_for_name(target, "SP"),
                source=SOURCE,
                labels=["code", kind_label],
            )
        )
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            cve = str(vuln.get("VulnerabilityID") or "CVE")
            pkg = str(vuln.get("PkgName") or "pkg")
            extra = control_extra(
                "CTL-SCA",
                "SCA and lockfile patching",
                csf_function="protect",
                priority="2",
                category="process",
            )
            extra["cve"] = cve
            records.append(
                finding(
                    PREFIX,
                    cve,
                    f"{cve} in {pkg}",
                    description=str(vuln.get("Title") or cve),
                    severity=str(vuln.get("Severity") or "medium"),
                    source=SOURCE,
                    related_assets=[target],
                    labels=["code", "trivy", cve],
                    extra=extra,
                )
            )
        for secret in result.get("Secrets") or []:
            if not isinstance(secret, dict):
                continue
            rule = str(secret.get("RuleID") or secret.get("Category") or "secret")
            title = str(secret.get("Title") or rule)
            start = str(secret.get("StartLine") or "")
            extra = control_extra(
                "CTL-SECRET-SCAN",
                "Pre-commit secret scanning and rotation",
                csf_function="protect",
                priority="1",
                category="process",
            )
            extra["rule_id"] = rule
            extra["target"] = target
            extra["start_line"] = start
            records.append(
                finding(
                    PREFIX,
                    f"TS-{rule}-{target}-{start}",
                    f"Trivy secret: {title}",
                    description=f"{title} in {target} line {start or 'n/a'} match=[REDACTED].",
                    severity=str(secret.get("Severity") or "critical"),
                    source=SOURCE,
                    related_assets=[target],
                    labels=["code", "trivy", "secret", rule],
                    extra=extra,
                )
            )
        for item in misconfigs:
            if not _trivy_misconfig_failed(item):
                continue
            mid = str(
                item.get("ID") or item.get("id") or item.get("AVDID") or item.get("CheckID") or "misconfig"
            )
            title = str(item.get("Title") or item.get("title") or mid)
            desc = str(item.get("Message") or item.get("Description") or title)
            extra = control_extra(
                "CTL-IAC-HARDEN",
                "IaC misconfiguration triage",
                csf_function="protect",
                priority="1" if str(item.get("Severity") or "").lower() in {"high", "critical"} else "2",
                category="process",
            )
            extra["rule_id"] = mid
            extra["target"] = target
            extra["avdid"] = item.get("AVDID") or item.get("avdid")
            records.append(
                finding(
                    PREFIX,
                    mid,
                    f"Trivy misconfig: {title}",
                    description=redact_text(f"{desc} in {target}."),
                    severity=str(item.get("Severity") or item.get("severity") or "medium"),
                    source=SOURCE,
                    related_assets=[target],
                    labels=["code", "trivy", "misconfig", mid],
                    extra=extra,
                )
            )
    return records


def _semgrep_rules(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver") or {})
        for rule in driver.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules[str(rule["id"])] = rule
    return rules


def _semgrep_path(item: dict[str, Any]) -> tuple[str, str]:
    raw_path = item.get("path")
    if isinstance(raw_path, str) and raw_path.strip():
        return raw_path.strip(), ""
    start = ""
    for loc in item.get("locations") or []:
        if not isinstance(loc, dict):
            continue
        phys = loc.get("physicalLocation") or {}
        uri = str((phys.get("artifactLocation") or {}).get("uri") or "")
        region = phys.get("region") if isinstance(phys.get("region"), dict) else {}
        start = str(region.get("startLine") or "")
        if uri:
            return uri, start
    return "", start


def _semgrep_severity(item: dict[str, Any], rule: dict[str, Any] | None = None) -> str:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    rule = rule or {}
    default_cfg = rule.get("defaultConfiguration") if isinstance(rule.get("defaultConfiguration"), dict) else {}
    for raw in (
        extra.get("severity"),
        props.get("severity"),
        item.get("level"),
        default_cfg.get("level"),
    ):
        if raw is None or str(raw).strip() == "":
            continue
        return str(raw)
    return "medium"


def parse_semgrep(doc: dict[str, Any]) -> list:
    records: list = []
    results: list[Any] = []
    rules = _semgrep_rules(doc)
    from_sarif = False
    if "runs" in doc:
        from_sarif = True
        for run in doc.get("runs") or []:
            if isinstance(run, dict):
                results.extend(run.get("results") or [])
    elif "results" in doc:
        results = list(doc.get("results") or [])
    elif doc.get("check_id") or doc.get("ruleId"):
        results = [doc]
    repo = "app-monorepo"
    records.append(
        asset(
            PREFIX,
            "REPO",
            repo,
            description="Application git repository (demo)",
            asset_type="SP",
            source=SOURCE,
            labels=["code", "repo"],
        )
    )
    for item in results:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("check_id") or item.get("ruleId") or item.get("rule") or "semgrep")
        rule = rules.get(rule_id) or {}
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        path, start = _semgrep_path(item)
        msg = extra.get("message") or item.get("message") or rule_id
        if isinstance(item.get("message"), dict):
            msg = item["message"].get("text") or msg
        elif isinstance(rule.get("shortDescription"), dict):
            msg = msg or rule["shortDescription"].get("text")
        msg = str(msg or rule_id)
        sev = _semgrep_severity(item, rule)
        where = path or "unknown"
        if start:
            where = f"{where}:{start}"
        labels = ["code", "semgrep", rule_id]
        if from_sarif:
            labels.append("sarif")
        records.append(
            finding(
                PREFIX,
                f"SG-{rule_id}",
                f"Semgrep {rule_id}",
                description=redact_text(f"{msg} in {where}"),
                severity=sev,
                source=SOURCE,
                related_assets=[repo],
                labels=labels,
                extra=control_extra(
                    "CTL-SAST",
                    "SAST finding triage",
                    csf_function="protect",
                    priority="1" if str(sev).lower() in {"error", "high", "critical"} else "2",
                    category="process",
                ),
            )
        )
    return records


def parse_files(files: list[Path]) -> list:
    records: list = []
    for path in files:
        loaded = load_structured(path)
        if not loaded:
            continue
        first = loaded[0] if loaded and isinstance(loaded[0], dict) else None
        if first and _is_gitleaks_sarif(first, path):
            for doc in loaded:
                if isinstance(doc, dict):
                    records.extend(parse_gitleaks_sarif(doc))
            continue
        if path.name.startswith("gitleaks") or (
            first is not None
            and (
                "RuleID" in first
                or "Fingerprint" in first
                or "fingerprint" in first
                or "DetectorName" in first
            )
        ):
            records.extend(parse_gitleaks(loaded))
            continue
        for doc in loaded:
            if not isinstance(doc, dict):
                continue
            if _is_gitleaks_sarif(doc, path):
                records.extend(parse_gitleaks_sarif(doc))
            elif "RuleID" in doc:
                records.extend(parse_gitleaks([doc]))
            elif "Results" in doc:
                records.extend(parse_trivy(doc))
            elif "results" in doc or "check_id" in doc or "runs" in doc:
                records.extend(parse_semgrep(doc))
    return records


def main() -> None:
    files = discover_input_files("code")
    records = parse_files(files)
    records.append(
        evidence(
            PREFIX,
            "CODE",
            "Gitleaks/Trivy demo parse",
            description="Parsed gitleaks JSON (empty File uses Source) and SARIF (snippet/Secret redacted), Trivy Vulnerabilities, Secrets, and Misconfigurations (FAIL only). Semgrep included. No git remotes contacted.",
            source=SOURCE,
        )
    )
    emit("code", records, files)


if __name__ == "__main__":
    main()
