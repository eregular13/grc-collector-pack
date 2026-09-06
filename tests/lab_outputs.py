from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.schema import (  # noqa: E402
    ASSET_TYPES,
    CONTROL_CATEGORIES,
    CONTROL_STATUSES,
    CSF_FUNCTIONS,
    FINDING_CSV_SEVERITIES,
    FINDING_STATUSES,
    RR_IMPACTS,
    RR_LIKELIHOODS,
    VULN_SEVERITIES,
)

OUT = Path(__file__).resolve().parents[1] / "out"
CISO = OUT / "ciso-assistant"
RR = OUT / "riskready"


def bind_out() -> None:
    """Honor OUT_DIR so Docker facet labs do not clobber the watchdog out/."""
    global OUT, CISO, RR
    from shared.io_util import get_out

    OUT = get_out()
    CISO = OUT / "ciso-assistant"
    RR = OUT / "riskready"
AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
LEAKED_SECRET_FIELD = re.compile(r'(?i)"secret"\s*:\s*"(?!\[REDACTED\])[^"]+"')

ASSET_HEADER = [
    "ref_id",
    "name",
    "description",
    "domain",
    "type",
    "reference_link",
    "observation",
    "filtering_labels",
    "parent_assets",
]
CONTROL_HEADER = [
    "ref_id",
    "name",
    "description",
    "domain",
    "status",
    "category",
    "priority",
    "csf_function",
]
EVIDENCE_HEADER = ["name", "description"]
FINDING_HEADER = [
    "ref_id",
    "name",
    "description",
    "severity",
    "status",
    "filtering_labels",
]
VULN_HEADER = [
    "ref_id",
    "name",
    "description",
    "status",
    "severity",
    "assets",
    "applied_controls",
]
RISK_HEADER = [
    "ref_id",
    "assets",
    "threats",
    "name",
    "description",
    "existing_controls",
    "current_impact",
    "current_proba",
    "current_risk",
    "additional_controls",
    "residual_impact",
    "residual_proba",
    "residual_risk",
    "treatment",
]


class LabFailure(AssertionError):
    pass


def _fail(msg: str) -> None:
    raise LabFailure(msg)


def _read_csv(path: Path, delimiter: str = ",") -> tuple[list[str], list[dict[str, str]]]:
    if not path.exists():
        _fail(f"missing {path}")
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        header = list(reader.fieldnames or [])
        rows = list(reader)
    return header, rows


def _require_files() -> None:
    required = [
        CISO / "assets.csv",
        CISO / "applied_controls.csv",
        CISO / "evidences.csv",
        CISO / "findings.csv",
        CISO / "vulnerabilities.csv",
        CISO / "risk_scenarios.csv",
        RR / "assets.json",
        RR / "incidents.json",
        RR / "evidence.json",
        RR / "risks_proposed.json",
        OUT / "ocsf" / "compliance_findings.json",
        OUT / "summary.json",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        _fail("missing outputs: " + "; ".join(missing))
    _check_sensor_evidence_md()


def _check_sensor_evidence_md() -> None:
    missing: list[str] = []
    for name in SENSOR_EVIDENCE:
        path = OUT / "evidence" / f"{name}.md"
        if not path.exists():
            missing.append(str(path))
            continue
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            _fail(f"empty sensor evidence.md: {path}")
        if not text.lower().startswith("# evidence"):
            _fail(f"{path.name} missing # Evidence heading")
        if name.lower() not in text.lower():
            _fail(f"{path.name} does not mention sensor {name}")
    if missing:
        _fail("missing sensor evidence.md: " + "; ".join(missing))


def _check_headers() -> dict[str, list[dict[str, str]]]:
    checks = {
        "assets": (CISO / "assets.csv", ",", ASSET_HEADER),
        "applied_controls": (CISO / "applied_controls.csv", ",", CONTROL_HEADER),
        "evidences": (CISO / "evidences.csv", ",", EVIDENCE_HEADER),
        "findings": (CISO / "findings.csv", ",", FINDING_HEADER),
        "vulnerabilities": (CISO / "vulnerabilities.csv", ",", VULN_HEADER),
        "risk_scenarios": (CISO / "risk_scenarios.csv", ";", RISK_HEADER),
    }
    tables: dict[str, list[dict[str, str]]] = {}
    for name, (path, delim, expected) in checks.items():
        header, rows = _read_csv(path, delim)
        if header != expected:
            _fail(f"{path.name} headers {header} != {expected}")
        tables[name] = rows
    with (CISO / "risk_scenarios.csv").open(encoding="utf-8") as handle:
        first = handle.readline()
    if "," in first.split(";")[0] and first.count(";") < 3:
        _fail("risk_scenarios.csv is not semicolon-delimited")
    if ";" not in first:
        _fail("risk_scenarios.csv missing semicolon delimiter")
    return tables


def _check_filtering_labels(value: str, context: str) -> None:
    text = value or ""
    if text and not text.strip():
        _fail(f"spaces-only filtering_labels in {context}")
    if text != text.strip():
        _fail(f"padded filtering_labels in {context}: {text!r}")
    if text:
        for token in text.split(","):
            if not token or token != token.strip():
                _fail(f"empty or padded label token {token!r} in {context}")


def _check_enums(tables: dict[str, list[dict[str, str]]]) -> None:
    for row in tables["assets"]:
        if row.get("type") not in ASSET_TYPES:
            _fail(f"asset type not PR|SP: {row}")
        _check_filtering_labels(row.get("filtering_labels") or "", f"asset {row.get('ref_id')}")
    for row in tables["findings"]:
        if row.get("severity") not in FINDING_CSV_SEVERITIES:
            _fail(f"finding severity invalid: {row}")
        if row.get("status") not in FINDING_STATUSES:
            _fail(f"finding status invalid: {row}")
        _check_filtering_labels(row.get("filtering_labels") or "", f"finding {row.get('ref_id')}")
    for row in tables["vulnerabilities"]:
        if row.get("severity") not in VULN_SEVERITIES:
            _fail(f"vuln severity invalid: {row}")
        if (row.get("status") or "Exploitable") != "Exploitable" and not row.get("status"):
            _fail(f"vuln status empty: {row}")
    for row in tables["applied_controls"]:
        if row.get("status") not in CONTROL_STATUSES:
            _fail(f"control status invalid: {row}")
        if row.get("category") not in CONTROL_CATEGORIES:
            _fail(f"control category invalid: {row}")
        if row.get("csf_function") not in CSF_FUNCTIONS:
            _fail(f"csf_function invalid: {row}")
        if row.get("priority") not in {"1", "2", "3", "4"}:
            _fail(f"control priority invalid: {row}")
    csf_seen = {row.get("csf_function") for row in tables["applied_controls"]}
    if "respond" not in csf_seen:
        _fail("applied_controls missing csf_function=respond")
    if "recover" not in csf_seen:
        _fail("applied_controls missing csf_function=recover")
    ocsf = json.loads((OUT / "ocsf" / "compliance_findings.json").read_text(encoding="utf-8"))
    if int(ocsf.get("class_uid") or 0) != 2003:
        _fail("OCSF class_uid is not 2003")
    items = ocsf.get("items") or []
    if not items:
        _fail("OCSF items empty")
    for item in items:
        if not item.get("time"):
            _fail("OCSF item missing time")
        product = ((item.get("metadata") or {}).get("product") or {})
        if not product.get("name"):
            _fail("OCSF item missing metadata.product.name")
        unmapped = item.get("unmapped") or {}
        if not unmapped.get("ref_id"):
            _fail("OCSF item missing unmapped.ref_id")


def _check_counts(tables: dict[str, list[dict[str, str]]]) -> dict:
    summary = json.loads((OUT / "summary.json").read_text(encoding="utf-8"))
    assets = len(tables["assets"])
    findings = len(tables["findings"])
    evidence = len(tables["evidences"])
    if assets < 20:
        _fail(f"assets {assets} < 20")
    if findings < 20:
        _fail(f"findings {findings} < 20")
    if evidence < 8:
        _fail(f"evidence {evidence} < 8")
    if summary.get("assets") != assets:
        _fail(f"summary assets {summary.get('assets')} != csv {assets}")
    if summary.get("findings") != findings:
        _fail(f"summary findings mismatch")
    canon_n = len(list((OUT / "canonical").glob("*.jsonl")))
    if "sensors_canonical" not in summary:
        _fail("summary.json missing sensors_canonical")
    if summary.get("sensors_canonical") != canon_n:
        _fail(f"summary sensors_canonical {summary.get('sensors_canonical')} != {canon_n}")
    if canon_n < 9:
        _fail(f"sensors_canonical {canon_n} < 9")
    return summary


SENSOR_EVIDENCE = (
    "cloud",
    "nmap",
    "vuln",
    "wazuh",
    "identity",
    "easm",
    "k8s",
    "code",
    "saas",
)
SENSOR_PREFIXES = (
    "CLD-",
    "NMAP-",
    "VULN-",
    "WAZ-",
    "ID-",
    "EASM-",
    "K8S-",
    "CODE-",
    "SAAS-",
)


def _dupes(values: list[str]) -> list[str]:
    seen: set[str] = set()
    dups: list[str] = []
    for value in values:
        if value in seen and value not in dups:
            dups.append(value)
        seen.add(value)
    return dups


def _check_uniques(tables: dict[str, list[dict[str, str]]]) -> None:
    finding_refs = [str(row.get("ref_id") or "") for row in tables["findings"]]
    if any(not ref for ref in finding_refs):
        _fail("finding missing ref_id")
    finding_dups = _dupes(finding_refs)
    if finding_dups:
        _fail("duplicate finding ref_ids: " + ",".join(finding_dups[:8]))
    ev_names = [str(row.get("name") or "") for row in tables["evidences"]]
    if any(not name for name in ev_names):
        _fail("evidence missing name")
    ev_dups = _dupes(ev_names)
    if ev_dups:
        _fail("duplicate evidence names: " + ",".join(ev_dups[:8]))
    rr_ev = json.loads((RR / "evidence.json").read_text(encoding="utf-8"))
    if not isinstance(rr_ev, list):
        _fail("riskready/evidence.json must be a list")
    rr_names = [str(row.get("name") or "") for row in rr_ev]
    rr_dups = _dupes(rr_names)
    if rr_dups:
        _fail("duplicate evidence names in riskready/evidence.json: " + ",".join(rr_dups[:8]))


def _check_canonical_and_prefixes(tables: dict[str, list[dict[str, str]]]) -> None:
    canon = OUT / "canonical"
    required = ["cloud", "nmap", "vuln", "wazuh", "identity", "easm", "k8s", "code", "saas"]
    missing = [name for name in required if not (canon / f"{name}.jsonl").exists()]
    if missing:
        _fail("missing canonical jsonl: " + ",".join(missing))
    for row in tables["assets"]:
        ref = row.get("ref_id") or ""
        if not ref.startswith(SENSOR_PREFIXES):
            _fail(f"asset ref_id missing sensor prefix: {ref}")
    for row in tables["findings"]:
        ref = row.get("ref_id") or ""
        if not ref.startswith(SENSOR_PREFIXES):
            _fail(f"finding ref_id missing sensor prefix: {ref}")
    finding_refs = {row.get("ref_id") for row in tables["findings"]}
    if "CLD-S3-BUCKET-OBJECT-LOCK-ENABLED" not in finding_refs:
        _fail("Prowler CSV CHECK_ID finding missing: CLD-S3-BUCKET-OBJECT-LOCK-ENABLED")
    lock_csv = [row for row in tables["findings"] if row.get("ref_id") == "CLD-S3-BUCKET-OBJECT-LOCK-ENABLED"]
    if not lock_csv or lock_csv[0].get("severity") != "high":
        _fail("Prowler CSV SEVERITY high / STATUS FAIL must map to high")
    if "CLD-IAM-PASSWORD-POLICY-MINIMUM-LENGTH-14" not in finding_refs:
        _fail("Prowler CSV CHECK_ID finding missing: CLD-IAM-PASSWORD-POLICY-MINIMUM-LENGTH-14")
    pw_csv = [row for row in tables["findings"] if row.get("ref_id") == "CLD-IAM-PASSWORD-POLICY-MINIMUM-LENGTH-14"]
    if not pw_csv or pw_csv[0].get("severity") != "medium":
        _fail("Prowler CSV SEVERITY medium must map to medium")
    if "CLD-EC2-INSTANCE-MANAGED-BY-SSM" in finding_refs:
        _fail("Prowler CSV STATUS PASS must be skipped")
    if "CLD-GUARDDUTY-IS-ENABLED" not in finding_refs:
        _fail("BOM cloud fixture finding missing: CLD-GUARDDUTY-IS-ENABLED")
    if "CLD-EC2-INSTANCE-IMDSV1-ENABLED" not in finding_refs:
        _fail("Prowler v4 nested Metadata/Status finding missing: CLD-EC2-INSTANCE-IMDSV1-ENABLED")
    if "CLD-GUARDDUTY-NO-HIGH-SEVERITY-FINDINGS" not in finding_refs:
        _fail("Prowler MANUAL finding missing: CLD-GUARDDUTY-NO-HIGH-SEVERITY-FINDINGS")
    gd_manual = [row for row in tables["findings"] if row.get("ref_id") == "CLD-GUARDDUTY-NO-HIGH-SEVERITY-FINDINGS"]
    if not gd_manual or gd_manual[0].get("status") != "in_progress":
        _fail("Prowler MANUAL must map to finding status in_progress")
    if "CLD-EC2-INSTANCE-PUBLIC-IP" not in finding_refs:
        _fail("Prowler WorkflowStatus RESOLVED finding missing: CLD-EC2-INSTANCE-PUBLIC-IP")
    closed_rows = [row for row in tables["findings"] if row.get("ref_id") == "CLD-EC2-INSTANCE-PUBLIC-IP"]
    if not closed_rows or closed_rows[0].get("status") != "closed":
        _fail("Prowler WorkflowStatus RESOLVED must map to finding status closed")
    if "CLD-S3-BUCKET-ACL-PROHIBITED" not in finding_refs:
        _fail("Prowler FindingStatus IN PROGRESS finding missing: CLD-S3-BUCKET-ACL-PROHIBITED")
    acl_rows = [row for row in tables["findings"] if row.get("ref_id") == "CLD-S3-BUCKET-ACL-PROHIBITED"]
    if not acl_rows or acl_rows[0].get("status") != "in_progress":
        _fail("Prowler FindingStatus IN PROGRESS must map to finding status in_progress")
    asset_names = {row.get("name") for row in tables["assets"]}
    if "corp-lock-bucket" not in asset_names:
        _fail("Prowler CSV resource asset missing: corp-lock-bucket")
    if "i-0ssm" in asset_names:
        _fail("Prowler CSV PASS resource must not be an asset")
    if "corp-audit-plain" not in asset_names:
        _fail("Prowler CheckStatus asset missing: corp-audit-plain")
    if "CLD-S3-BUCKET-DEFAULT-ENCRYPTION-KMS" not in finding_refs:
        _fail("Prowler CheckStatus finding missing: CLD-S3-BUCKET-DEFAULT-ENCRYPTION-KMS")
    kms_s3 = [
        row
        for row in tables["findings"]
        if row.get("ref_id") == "CLD-S3-BUCKET-DEFAULT-ENCRYPTION-KMS"
    ]
    if not kms_s3 or kms_s3[0].get("severity") != "high":
        _fail("Prowler CheckStatus FAIL with empty Status must map to high")
    if "kms-unrotated-key" not in asset_names:
        _fail("Prowler check_status asset missing: kms-unrotated-key")
    if "CLD-KMS-CMK-ROTATION-ENABLED" not in finding_refs:
        _fail("Prowler check_status finding missing: CLD-KMS-CMK-ROTATION-ENABLED")
    kms_rot = [
        row
        for row in tables["findings"]
        if row.get("ref_id") == "CLD-KMS-CMK-ROTATION-ENABLED"
    ]
    if not kms_rot or kms_rot[0].get("severity") != "critical":
        _fail("Prowler check_status FAIL must map to critical")
    if "CLD-EC2-EBS-VOLUME-ENCRYPTION" in finding_refs:
        _fail("Prowler CheckStatus PASS must be skipped")
    if "2001:db8::9" not in asset_names:
        _fail("nmap IPv6 no-hostname asset missing: 2001:db8::9")
    if "bastion-prod.corp.local" not in asset_names:
        _fail("nmap type=user hostname missing: bastion-prod.corp.local")
    lock_rows = [
        row
        for row in tables["assets"]
        if str(row.get("name") or "").replace("\\", "/").lower().endswith("package-lock.json")
    ]
    if not lock_rows:
        _fail("package-lock.json asset missing")
    for row in lock_rows:
        if row.get("type") != "SP":
            _fail(f"package-lock.json path must be SP not {row.get('type')}: {row}")
    if "apps/web/package-lock.json" not in asset_names:
        _fail("nested package-lock.json path asset missing: apps/web/package-lock.json")
    if "CODE-CVE-2024-21538" not in finding_refs:
        _fail("nested package-lock.json CVE missing: CODE-CVE-2024-21538")
    if "deploy/api.Dockerfile" not in asset_names:
        _fail("Trivy misconfig Dockerfile asset missing: deploy/api.Dockerfile")
    if "k8s/privileged-pod.yaml" not in asset_names:
        _fail("Trivy misconfig k8s asset missing: k8s/privileged-pod.yaml")
    if "CODE-DS002" not in finding_refs:
        _fail("Trivy misconfig FAIL finding missing: CODE-DS002")
    ds002 = [row for row in tables["findings"] if row.get("ref_id") == "CODE-DS002"]
    if not ds002 or ds002[0].get("severity") != "high":
        _fail("Trivy misconfig DS002 FAIL must map to high")
    if "CODE-KSV017" not in finding_refs:
        _fail("Trivy misconfig FAIL finding missing: CODE-KSV017")
    ksv = [row for row in tables["findings"] if row.get("ref_id") == "CODE-KSV017"]
    if not ksv or ksv[0].get("severity") != "critical":
        _fail("Trivy misconfig KSV017 FAIL must map to critical")
    if "CODE-DS005" in finding_refs:
        _fail("Trivy misconfig Status PASS must be skipped: CODE-DS005")
    if "CODE-SLACK-BOT-TOKEN-OPS-PAGER-ENV" not in finding_refs:
        _fail("Gitleaks Fingerprint rule finding missing: CODE-SLACK-BOT-TOKEN-OPS-PAGER-ENV")
    pager = [row for row in tables["findings"] if row.get("ref_id") == "CODE-SLACK-BOT-TOKEN-OPS-PAGER-ENV"]
    if not pager or pager[0].get("severity") != "high":
        _fail("Gitleaks Fingerprint slack-bot-token must map to high")
    if "CODE-PRIVATE-KEY-CERTS-LEGACY-PEM" not in finding_refs:
        _fail("Gitleaks DetectorName finding missing: CODE-PRIVATE-KEY-CERTS-LEGACY-PEM")
    pem = [row for row in tables["findings"] if row.get("ref_id") == "CODE-PRIVATE-KEY-CERTS-LEGACY-PEM"]
    if not pem or pem[0].get("severity") != "high":
        _fail("Gitleaks DetectorName private-key must map to high")
    if "CODE-HASHICORP-TF-PASSWORD-TERRAFORM-PROD-TFVARS" not in finding_refs:
        _fail("Gitleaks Source-path finding missing: CODE-HASHICORP-TF-PASSWORD-TERRAFORM-PROD-TFVARS")
    tf_src = [
        row
        for row in tables["findings"]
        if row.get("ref_id") == "CODE-HASHICORP-TF-PASSWORD-TERRAFORM-PROD-TFVARS"
    ]
    if not tf_src or tf_src[0].get("severity") != "high":
        _fail("Gitleaks empty File + Source must map to high")
    if "CODE-JWT-MOBILE-CONFIG-JSON" not in finding_refs:
        _fail("Gitleaks Source-only finding missing: CODE-JWT-MOBILE-CONFIG-JSON")
    jwt_src = [row for row in tables["findings"] if row.get("ref_id") == "CODE-JWT-MOBILE-CONFIG-JSON"]
    if not jwt_src or jwt_src[0].get("severity") != "high":
        _fail("Gitleaks Source-only jwt must map to high")
    if "CODE-HASHICORP-TF-PASSWORD-UNKNOWN" in finding_refs:
        _fail("Gitleaks empty File must not use unknown when Source is set")
    if "CODE-JWT-UNKNOWN" in finding_refs:
        _fail("Gitleaks Source-only must not use unknown File")
    if "CODE-SECRET-OPS-PAGER-ENV" in finding_refs:
        _fail("Gitleaks empty RuleID must not fall back to generic secret")
    if "CODE-SLACK-BOT-TOKEN-CI-SECRETS-ENV" not in finding_refs:
        _fail("Gitleaks SARIF ruleId finding missing: CODE-SLACK-BOT-TOKEN-CI-SECRETS-ENV")
    slack_rows = [row for row in tables["findings"] if row.get("ref_id") == "CODE-SLACK-BOT-TOKEN-CI-SECRETS-ENV"]
    if not slack_rows or slack_rows[0].get("severity") != "high":
        _fail("Gitleaks SARIF slack-bot-token must map to high")
    if any(str(ref).startswith("CODE-SG-SLACK-BOT-TOKEN") for ref in finding_refs):
        _fail("Gitleaks SARIF must not be parsed as Semgrep")
    if "ip-10-0-0-77.ec2.internal" in asset_names:
        _fail("nmap must prefer hostname type=user over PTR")
    if "up-xml.corp.local" not in asset_names:
        _fail("nmap XML up host missing: up-xml.corp.local")
    if "down-xml.corp.local" in asset_names:
        _fail("nmap XML must skip host with status state=down")
    if "xml-down-mixed.corp.local" in asset_names:
        _fail("nmap XML must skip host with status state=Down")
    if "10.0.0.43" in asset_names or "10.0.0.45" in asset_names:
        _fail("nmap XML down host IP must not be an asset")
    if "admin-confluence.example-corp.com" not in asset_names:
        _fail("httpx JSON input host missing: admin-confluence.example-corp.com")
    if "owa-legacy.example-corp.com" not in asset_names:
        _fail("httpx JSON whitespace host input fallback missing: owa-legacy.example-corp.com")
    if "fileshare.example-corp.com" not in asset_names:
        _fail("httpx JSON missing-host input asset missing: fileshare.example-corp.com")
    if "EASM-ADMIN-CONFLUENCE-EXAMPLE-CORP-COM" not in finding_refs:
        _fail("httpx JSON input finding missing: EASM-ADMIN-CONFLUENCE-EXAMPLE-CORP-COM")
    confluence = [row for row in tables["findings"] if row.get("ref_id") == "EASM-ADMIN-CONFLUENCE-EXAMPLE-CORP-COM"]
    if not confluence or confluence[0].get("severity") != "high":
        _fail("httpx JSON input admin-confluence must map to high")
    if "unknown-host" in asset_names:
        _fail("httpx empty host+input must not emit unknown-host")
    if "test.example-corp.com" not in asset_names:
        _fail("httpx URL-only host missing: test.example-corp.com")
    if "portal-legacy.example-corp.com" not in asset_names:
        _fail("httpx URL-only path host missing: portal-legacy.example-corp.com")
    if "git.example-corp.com" not in asset_names:
        _fail("subfinder JSONL host object missing: git.example-corp.com")
    if "citrix.example-corp.com" not in asset_names:
        _fail("subfinder JSONL hostname object missing: citrix.example-corp.com")
    if "admin-sso.example-corp.com" not in asset_names:
        _fail("subfinder JSONL host object missing: admin-sso.example-corp.com")
    if "vpn.backup.example-corp.com" not in asset_names:
        _fail("Amass names-array host missing: vpn.backup.example-corp.com")
    if "admin-portal.example-corp.com" not in asset_names:
        _fail("Amass names-array host missing: admin-portal.example-corp.com")
    if "intranet.example-corp.com" not in asset_names:
        _fail("Amass names-array host missing: intranet.example-corp.com")
    if "EASM-AMASS-VPN-BACKUP-EXAMPLE-CORP-COM" not in finding_refs:
        _fail("Amass names-array finding missing: EASM-AMASS-VPN-BACKUP-EXAMPLE-CORP-COM")
    vpn_bak = [row for row in tables["findings"] if row.get("ref_id") == "EASM-AMASS-VPN-BACKUP-EXAMPLE-CORP-COM"]
    if not vpn_bak or vpn_bak[0].get("severity") != "medium":
        _fail("Amass names-array vpn-backup must map to medium")
    if "EASM-AMASS-ADMIN-PORTAL-EXAMPLE-CORP-COM" not in finding_refs:
        _fail("Amass names-array finding missing: EASM-AMASS-ADMIN-PORTAL-EXAMPLE-CORP-COM")
    if "sharepoint-old.example-corp.com" not in asset_names:
        _fail("Amass JSON name object missing: sharepoint-old.example-corp.com")
    if "remote.example-corp.com" not in asset_names:
        _fail("Amass JSON fqdn object missing: remote.example-corp.com")
    if "admin-vpn.example-corp.com" not in asset_names:
        _fail("Amass JSON name object missing: admin-vpn.example-corp.com")
    if any(str(n).lower().startswith(("http://", "https://")) for n in asset_names):
        _fail("easm asset name is a raw URL (expected hostname only)")
    if "ad.tailspintoys.local" not in asset_names:
        _fail("PingCastle XML DomainFQDN attr asset missing: ad.tailspintoys.local")
    if "ID-PCXML-P-ADMINPWDTOOOLD" not in finding_refs:
        _fail("PingCastle XML DomainFQDN finding missing: ID-PCXML-P-ADMINPWDTOOOLD")
    pwd_old = [row for row in tables["findings"] if row.get("ref_id") == "ID-PCXML-P-ADMINPWDTOOOLD"]
    if not pwd_old or pwd_old[0].get("severity") != "high":
        _fail("PingCastle P-AdminPwdTooOld points=20 must map to high")
    if "unknown-domain" in asset_names:
        _fail("PingCastle empty Host must use DomainFQDN, not unknown-domain")
    if "AW.LOCAL" not in asset_names:
        _fail("BloodHound CE data-list domain asset missing: AW.LOCAL")
    if "SVC-SQL@AW.LOCAL" not in asset_names:
        _fail("BloodHound CE data-list SPN user missing: SVC-SQL@AW.LOCAL")
    if "ID-BHCE-SPN-SVC-SQL-AW-LOCAL" not in finding_refs:
        _fail("BloodHound CE data-list SPN finding missing: ID-BHCE-SPN-SVC-SQL-AW-LOCAL")
    sqlspn = [row for row in tables["findings"] if row.get("ref_id") == "ID-BHCE-SPN-SVC-SQL-AW-LOCAL"]
    if not sqlspn or sqlspn[0].get("severity") != "high":
        _fail("BloodHound CE data-list hasspn must map to high")
    if "ID-BHCE-ASREP-JDOE-AW-LOCAL" not in finding_refs:
        _fail("BloodHound CE data-list AS-REP finding missing: ID-BHCE-ASREP-JDOE-AW-LOCAL")
    asrep = [row for row in tables["findings"] if row.get("ref_id") == "ID-BHCE-ASREP-JDOE-AW-LOCAL"]
    if not asrep or asrep[0].get("severity") != "high":
        _fail("BloodHound CE data-list dontreqpreauth must map to high")
    if "ID-BHCE-GENERICALL-CONTRACTOR-AW-LOCAL-DC02-AW-LOCAL" not in finding_refs:
        _fail("BloodHound CE data-list GenericAll finding missing: ID-BHCE-GENERICALL-CONTRACTOR-AW-LOCAL-DC02-AW-LOCAL")
    gall = [row for row in tables["findings"] if row.get("ref_id") == "ID-BHCE-GENERICALL-CONTRACTOR-AW-LOCAL-DC02-AW-LOCAL"]
    if not gall or gall[0].get("severity") != "critical":
        _fail("BloodHound CE data-list GenericAll must map to critical")
    if any("ANALYST" in str(ref) for ref in finding_refs):
        _fail("BloodHound CE data-list ANALYST must not emit a finding")
    if "ID-PCHCR-P-TRUSTEDCREDS" not in finding_refs:
        _fail("PingCastle HealthcheckRisk JSON finding missing: ID-PCHCR-P-TRUSTEDCREDS")
    trusted_rows = [row for row in tables["findings"] if row.get("ref_id") == "ID-PCHCR-P-TRUSTEDCREDS"]
    if not trusted_rows or trusted_rows[0].get("severity") != "high":
        _fail("PingCastle HealthcheckRisk P-TrustedCreds points=20 must map to high")
    if "ID-PCHCR-A-NULLSESSION" not in finding_refs:
        _fail("PingCastle HealthcheckRisk JSON finding missing: ID-PCHCR-A-NULLSESSION")
    null_rows = [row for row in tables["findings"] if row.get("ref_id") == "ID-PCHCR-A-NULLSESSION"]
    if not null_rows or null_rows[0].get("severity") != "medium":
        _fail("PingCastle HealthcheckRisk A-NullSession points=10 must map to medium")
    if "fabrikam.local" not in asset_names:
        _fail("PingCastle HealthcheckRisk JSON domain asset missing: fabrikam.local")
    if "ID-SCUBA-MS-TEAMS-2-1V1" not in finding_refs:
        _fail("ScubaGear RelativePath finding missing: ID-SCUBA-MS-TEAMS-2-1V1")
    teams_scuba = [row for row in tables["findings"] if row.get("ref_id") == "ID-SCUBA-MS-TEAMS-2-1V1"]
    if not teams_scuba or teams_scuba[0].get("severity") != "high":
        _fail("ScubaGear RelativePath MS.TEAMS.2.1v1 must map to high")
    if "ID-SCUBA-MS-DEFENDER-1-4V1" not in finding_refs:
        _fail("ScubaGear RelativePath finding missing: ID-SCUBA-MS-DEFENDER-1-4V1")
    defender = [row for row in tables["findings"] if row.get("ref_id") == "ID-SCUBA-MS-DEFENDER-1-4V1"]
    if not defender or defender[0].get("severity") != "high":
        _fail("ScubaGear RelativePath MS.DEFENDER.1.4v1 must map to high")
    if "ID-SCUBA-MS-SHAREPOINT-1-1V1" in finding_refs:
        _fail("ScubaGear RelativePath Pass must be skipped: ID-SCUBA-MS-SHAREPOINT-1-1V1")
    if not any("fabrikam.onmicrosoft.com" in str(n) for n in asset_names):
        _fail("ScubaGear RelativePath tenant asset missing: fabrikam.onmicrosoft.com")
    if "ID-SCUBA-MS-EXO-4-1V1" not in finding_refs:
        _fail("ScubaGear Failed-array finding missing: ID-SCUBA-MS-EXO-4-1V1")
    scuba_rows = [row for row in tables["findings"] if row.get("ref_id") == "ID-SCUBA-MS-EXO-4-1V1"]
    if not scuba_rows or scuba_rows[0].get("severity") != "high":
        _fail("ScubaGear Failed array MS.EXO.4.1v1 must map to high")
    if "okta-appadmin@contoso.com" not in asset_names:
        _fail("Okta /api/v1/users admin asset missing: okta-appadmin@contoso.com")
    if "okta-contractor@contoso.com" not in asset_names:
        _fail("Okta /api/v1/users contractor asset missing: okta-contractor@contoso.com")
    if "SAAS-OKTA-MFA-OKTA-APPADMIN-CONTOSO-COM" not in finding_refs:
        _fail("Okta credentials.provider MFA gap missing: SAAS-OKTA-MFA-OKTA-APPADMIN-CONTOSO-COM")
    appadmin = [row for row in tables["findings"] if row.get("ref_id") == "SAAS-OKTA-MFA-OKTA-APPADMIN-CONTOSO-COM"]
    if not appadmin or appadmin[0].get("severity") != "critical":
        _fail("Okta admin without factors must map to critical")
    if "SAAS-OKTA-MFA-OKTA-CONTRACTOR-CONTOSO-COM" not in finding_refs:
        _fail("Okta credentials.provider MFA gap missing: SAAS-OKTA-MFA-OKTA-CONTRACTOR-CONTOSO-COM")
    contractor = [row for row in tables["findings"] if row.get("ref_id") == "SAAS-OKTA-MFA-OKTA-CONTRACTOR-CONTOSO-COM"]
    if not contractor or contractor[0].get("severity") != "high":
        _fail("Okta user OKTA provider without factors must map to high")
    if "SAAS-OKTA-MFA-OKTA-ANALYST-CONTOSO-COM" in finding_refs:
        _fail("Okta user with TOTP factor must not be an MFA gap")
    if "SAAS-OKTA-MFA-OKTA-FEDERATED-CONTOSO-COM" in finding_refs:
        _fail("Okta FEDERATION credentials.provider must not be a local MFA gap")
    if "litware.onmicrosoft.com" not in asset_names:
        _fail("Graph userRegistrationDetails tenant asset missing: litware.onmicrosoft.com")
    if "ga-breakglass@litware.onmicrosoft.com" not in asset_names:
        _fail("Graph userRegistrationDetails admin asset missing: ga-breakglass@litware.onmicrosoft.com")
    if "vendor@litware.onmicrosoft.com" not in asset_names:
        _fail("Graph userRegistrationDetails user asset missing: vendor@litware.onmicrosoft.com")
    if "SAAS-GRAPH-MFA-GA-BREAKGLASS-LITWARE-ONMICROSOFT-COM" not in finding_refs:
        _fail("Graph isMfaRegistered MFA gap missing: SAAS-GRAPH-MFA-GA-BREAKGLASS-LITWARE-ONMICROSOFT-COM")
    ga_graph = [
        row
        for row in tables["findings"]
        if row.get("ref_id") == "SAAS-GRAPH-MFA-GA-BREAKGLASS-LITWARE-ONMICROSOFT-COM"
    ]
    if not ga_graph or ga_graph[0].get("severity") != "critical":
        _fail("Graph admin isMfaRegistered=false must map to critical")
    if "SAAS-GRAPH-MFA-VENDOR-LITWARE-ONMICROSOFT-COM" not in finding_refs:
        _fail("Graph isMfaRegistered MFA gap missing: SAAS-GRAPH-MFA-VENDOR-LITWARE-ONMICROSOFT-COM")
    vendor_graph = [
        row
        for row in tables["findings"]
        if row.get("ref_id") == "SAAS-GRAPH-MFA-VENDOR-LITWARE-ONMICROSOFT-COM"
    ]
    if not vendor_graph or vendor_graph[0].get("severity") != "high":
        _fail("Graph user isMfaRegistered=false must map to high")
    if "SAAS-GRAPH-MFA-ANALYST-LITWARE-ONMICROSOFT-COM" in finding_refs:
        _fail("Graph isMfaRegistered=true analyst must not be an MFA gap")
    if "SAAS-GRAPH-MFA-HELPDESK-LITWARE-ONMICROSOFT-COM" in finding_refs:
        _fail("Graph admin with MFA registered must not be an MFA gap")
    if any("GUEST" in str(r) and "GRAPH-MFA" in str(r) for r in finding_refs):
        _fail("Graph guest userType must not emit an MFA gap")
    if "WAZ-ALERT-5712" not in finding_refs:
        _fail("Wazuh alerts JSON rule.level finding missing: WAZ-ALERT-5712")
    brute = [row for row in tables["findings"] if row.get("ref_id") == "WAZ-ALERT-5712"]
    if not brute or brute[0].get("severity") != "high":
        _fail("Wazuh rule.level 10 must map to high")
    if "WAZ-ALERT-550" not in finding_refs:
        _fail("Wazuh alerts JSON rule.level finding missing: WAZ-ALERT-550")
    fim = [row for row in tables["findings"] if row.get("ref_id") == "WAZ-ALERT-550"]
    if not fim or fim[0].get("severity") != "critical":
        _fail("Wazuh rule.level 12 must map to critical")
    if "WAZ-ALERT-1002" in finding_refs:
        _fail("Wazuh rule.level 2 info alert must be skipped")
    if "vpn-gw" not in asset_names:
        _fail("Wazuh alert host missing: vpn-gw")
    if "cfg-bastion" not in asset_names:
        _fail("Wazuh alert host missing: cfg-bastion")
    if "WAZ-DISC-JUMP-LEGACY" not in finding_refs:
        _fail("Wazuh status Disconnected finding missing: WAZ-DISC-JUMP-LEGACY")
    disc_rows = [row for row in tables["findings"] if row.get("ref_id") == "WAZ-DISC-JUMP-LEGACY"]
    if not disc_rows or disc_rows[0].get("severity") != "high":
        _fail("Wazuh status Disconnected (capital D) must map to high")
    if "jump-legacy" not in asset_names:
        _fail("Wazuh Disconnected agent asset missing: jump-legacy")
    if "nas-legacy.corp.local" not in asset_names:
        _fail("osquery list-wrapper host missing: nas-legacy.corp.local")
    if "WAZ-OSQ-NAS-LEGACY-CORP-LOCAL-445" not in finding_refs:
        _fail("osquery list-wrapper finding missing: WAZ-OSQ-NAS-LEGACY-CORP-LOCAL-445")
    nas = [row for row in tables["findings"] if row.get("ref_id") == "WAZ-OSQ-NAS-LEGACY-CORP-LOCAL-445"]
    if not nas or nas[0].get("severity") != "high":
        _fail("osquery list-wrapper port 445 must map to high")
    if "modem-legacy.corp.local" not in asset_names:
        _fail("osquery list-wrapper host missing: modem-legacy.corp.local")
    if "WAZ-OSQ-MODEM-LEGACY-CORP-LOCAL-23" not in finding_refs:
        _fail("osquery list-wrapper finding missing: WAZ-OSQ-MODEM-LEGACY-CORP-LOCAL-23")
    modem = [row for row in tables["findings"] if row.get("ref_id") == "WAZ-OSQ-MODEM-LEGACY-CORP-LOCAL-23"]
    if not modem or modem[0].get("severity") != "high":
        _fail("osquery list-wrapper port 23 must map to high")
    if "WAZ-OSQ-HELPER-SSH-CORP-LOCAL-22" in finding_refs:
        _fail("osquery list-wrapper ssh port 22 must not be a finding")
    if "WAZ-OSQ-SMB-LEGACY-CORP-LOCAL-445" not in finding_refs:
        _fail("osquery nested columns listening_ports finding missing: WAZ-OSQ-SMB-LEGACY-CORP-LOCAL-445")
    osq_rows = [row for row in tables["findings"] if row.get("ref_id") == "WAZ-OSQ-SMB-LEGACY-CORP-LOCAL-445"]
    if not osq_rows or osq_rows[0].get("severity") != "high":
        _fail("osquery listening_ports port 445 must map to high")
    if "log4j-legacy.corp.local" not in asset_names:
        _fail("Nuclei classification cve-id asset missing: log4j-legacy.corp.local")
    if "VULN-CVE-2021-45046" not in finding_refs:
        _fail("Nuclei classification cve-id finding missing: VULN-CVE-2021-45046")
    log4j = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2021-45046"]
    if not log4j or log4j[0].get("severity") != "critical":
        _fail("Nuclei classification CVE-2021-45046 must map to critical")
    if "func-legacy.corp.local" not in asset_names:
        _fail("Nuclei classification cve_id list asset missing: func-legacy.corp.local")
    if "VULN-CVE-2022-22963" not in finding_refs:
        _fail("Nuclei classification cve_id list finding missing: VULN-CVE-2022-22963")
    spel = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2022-22963"]
    if not spel or spel[0].get("severity") != "high":
        _fail("Nuclei classification CVE-2022-22963 must map to high")
    if "VULN-LOG4J-RCE" in finding_refs:
        _fail("Nuclei classification cve-id must not keep non-CVE template-id as ref")
    if "weblogic-legacy.corp.local" not in asset_names:
        _fail("Nuclei template-path host missing: weblogic-legacy.corp.local")
    if "VULN-CVE-2020-14882" not in finding_refs:
        _fail("Nuclei empty template-id path finding missing: VULN-CVE-2020-14882")
    weblogic = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2020-14882"]
    if not weblogic or weblogic[0].get("severity") != "critical":
        _fail("Nuclei template-path CVE-2020-14882 must map to critical")
    if "vsphere-legacy.corp.local" not in asset_names:
        _fail("Nuclei template-path host missing: vsphere-legacy.corp.local")
    if "VULN-CVE-2021-21972" not in finding_refs:
        _fail("Nuclei empty template-id path finding missing: VULN-CVE-2021-21972")
    vsphere = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2021-21972"]
    if not vsphere or vsphere[0].get("severity") != "critical":
        _fail("Nuclei template-path CVE-2021-21972 must map to critical")
    if "VULN-EXPOSED-KIBANA" not in finding_refs:
        _fail("Nuclei non-CVE template basename missing: VULN-EXPOSED-KIBANA")
    if "VULN-ORACLE-WEBLOGIC-CONSOLE-RCE" in finding_refs:
        _fail("Nuclei empty template-id must not use info.name as ref")
    if "VULN-VMWARE-VSPHERE-CLIENT-RCE" in finding_refs:
        _fail("Nuclei empty template-id must not use info.name as ref")
    if "10.0.0.55" not in asset_names:
        _fail("Nuclei JSONL ip-only asset missing: 10.0.0.55")
    if "VULN-CVE-2018-13379" not in finding_refs:
        _fail("Nuclei JSONL ip-only finding missing: VULN-CVE-2018-13379")
    forti = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2018-13379"]
    if not forti or forti[0].get("severity") != "critical":
        _fail("Nuclei ip-only CVE-2018-13379 must map to critical")
    if "pulse-legacy.corp.local" not in asset_names:
        _fail("Nuclei matched-at URL host missing: pulse-legacy.corp.local")
    if "VULN-CVE-2019-11510" not in finding_refs:
        _fail("Nuclei matched-at URL finding missing: VULN-CVE-2019-11510")
    pulse_rows = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2019-11510"]
    if not pulse_rows or pulse_rows[0].get("severity") != "critical":
        _fail("Nuclei matched-at Pulse CVE-2019-11510 must map to critical")
    if "VULN-CVE-2014-0160" not in finding_refs:
        _fail("OpenVAS numeric CVSS finding missing: VULN-CVE-2014-0160")
    ov_rows = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2014-0160"]
    if not ov_rows or ov_rows[0].get("severity") != "critical":
        _fail("OpenVAS numeric CVSS 9.8 must map to critical not info")
    if "struts-legacy.corp.local" not in asset_names:
        _fail("OpenVAS NOCVE ref host missing: struts-legacy.corp.local")
    if "VULN-CVE-2017-5638" not in finding_refs:
        _fail("OpenVAS NOCVE must use ref type=cve: VULN-CVE-2017-5638")
    struts = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2017-5638"]
    if not struts or struts[0].get("severity") != "critical":
        _fail("OpenVAS NOCVE CVE-2017-5638 must map to critical")
    if "tomcat-legacy.corp.local" not in asset_names:
        _fail("OpenVAS nested cves host missing: tomcat-legacy.corp.local")
    if "VULN-CVE-2020-1938" not in finding_refs:
        _fail("OpenVAS nested cves finding missing: VULN-CVE-2020-1938")
    ghostcat = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2020-1938"]
    if not ghostcat or ghostcat[0].get("severity") != "high":
        _fail("OpenVAS nested cves CVE-2020-1938 must map to high")
    if "VULN-NOCVE" in finding_refs:
        _fail("OpenVAS placeholder NOCVE must not be a finding ref")
    if "10.0.0.66" not in asset_names:
        _fail("OpenVAS empty <host> text ip= asset missing: 10.0.0.66")
    if "VULN-CVE-2018-7600" not in finding_refs:
        _fail("OpenVAS empty host ip= finding missing: VULN-CVE-2018-7600")
    ov_ip_rows = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2018-7600"]
    if not ov_ip_rows or ov_ip_rows[0].get("severity") != "critical":
        _fail("OpenVAS empty host ip= CVE-2018-7600 must map to critical")
    if "gvm-named.corp.local" not in asset_names:
        _fail("OpenVAS <host> text preferred over ip= missing: gvm-named.corp.local")
    if "10.0.0.199" in asset_names:
        _fail("OpenVAS must prefer <host> text over conflicting ip= attribute")
    if "VULN-CVE-2012-1823" not in finding_refs:
        _fail("OpenVAS host text vs ip= finding missing: VULN-CVE-2012-1823")
    php_rows = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2012-1823"]
    if not php_rows or php_rows[0].get("severity") != "high":
        _fail("OpenVAS host text CVE-2012-1823 must map to high")
    if "dc-legacy.corp.local" not in asset_names:
        _fail("Nessus host-fqdn asset missing: dc-legacy.corp.local")
    if "10.0.88.12" in asset_names:
        _fail("Nessus must prefer host-fqdn over ReportHost IP name")
    if "print-legacy.corp.local" not in asset_names:
        _fail("Nessus empty host-fqdn ReportHost name missing: print-legacy.corp.local")
    if "VULN-CVE-2020-1472" not in finding_refs:
        _fail("Nessus ReportItem finding missing: VULN-CVE-2020-1472")
    zero = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2020-1472"]
    if not zero or zero[0].get("severity") != "critical":
        _fail("Nessus CVE-2020-1472 cvss3 10.0 must map to critical")
    if "VULN-CVE-2021-34527" not in finding_refs:
        _fail("Nessus empty host-fqdn finding missing: VULN-CVE-2021-34527")
    spool = [row for row in tables["findings"] if row.get("ref_id") == "VULN-CVE-2021-34527"]
    if not spool or spool[0].get("severity") != "high":
        _fail("Nessus CVE-2021-34527 cvss3 8.8 must map to high")
    if "VULN-19506" in finding_refs:
        _fail("Nessus severity 0 info plugin must be skipped: VULN-19506")
    if "CODE-SG-PYTHON-DJANGO-SQL-EXTRA-USED" not in finding_refs:
        _fail("Semgrep SARIF ruleId finding missing: CODE-SG-PYTHON-DJANGO-SQL-EXTRA-USED")
    sql_rows = [row for row in tables["findings"] if row.get("ref_id") == "CODE-SG-PYTHON-DJANGO-SQL-EXTRA-USED"]
    if not sql_rows or sql_rows[0].get("severity") != "high":
        _fail("Semgrep SARIF level=error must map to high")
    hash_rows = [row for row in tables["findings"] if row.get("ref_id") == "CODE-SG-PYTHON-LANG-SECURITY-INSECURE-HASH"]
    if not hash_rows or hash_rows[0].get("severity") != "medium":
        _fail("Semgrep SARIF defaultConfiguration.level=warning must map to medium")
    if "staging-gke" not in asset_names:
        _fail("Kubescape failedControls cluster asset missing: staging-gke")
    if "K8S-C-0016" not in finding_refs:
        _fail("Kubescape failedControls finding missing: K8S-C-0016")
    c0016 = [row for row in tables["findings"] if row.get("ref_id") == "K8S-C-0016"]
    if not c0016 or c0016[0].get("severity") != "high":
        _fail("Kubescape failedControls C-0016 must map to high")
    if "K8S-C-0048" not in finding_refs:
        _fail("Kubescape failedControls finding missing: K8S-C-0048")
    c0048 = [row for row in tables["findings"] if row.get("ref_id") == "K8S-C-0048"]
    if not c0048 or c0048[0].get("severity") != "high":
        _fail("Kubescape failedControls C-0048 scoreFactor 8 must map to high")
    if "K8S-C-0005" in finding_refs:
        _fail("Kubescape failedControls passed control must be skipped: K8S-C-0005")
    if "K8S-KB-4-2-1" not in finding_refs:
        _fail("kube-bench hyphenated test-number finding missing: K8S-KB-4-2-1")
    kb421 = [row for row in tables["findings"] if row.get("ref_id") == "K8S-KB-4-2-1"]
    if not kb421 or kb421[0].get("severity") != "high":
        _fail("kube-bench hyphenated 4.2.1 anonymous FAIL must map to high")
    if "K8S-KB-4-2-4" not in finding_refs:
        _fail("kube-bench hyphenated test-result finding missing: K8S-KB-4-2-4")
    kb424 = [row for row in tables["findings"] if row.get("ref_id") == "K8S-KB-4-2-4"]
    if not kb424 or kb424[0].get("severity") != "medium":
        _fail("kube-bench hyphenated 4.2.4 fail must map to medium")
    if "K8S-KB-4-2-6" not in finding_refs:
        _fail("kube-bench hyphenated WARN finding missing: K8S-KB-4-2-6")
    kb426 = [row for row in tables["findings"] if row.get("ref_id") == "K8S-KB-4-2-6"]
    if not kb426 or kb426[0].get("severity") != "medium":
        _fail("kube-bench hyphenated 4.2.6 WARN must map to medium")
    if "K8S-KB-4-2-13" in finding_refs:
        _fail("kube-bench hyphenated PASS must be skipped: K8S-KB-4-2-13")
    if "K8S-KB-4-1-1" not in finding_refs:
        _fail("kube-bench top-level tests finding missing: K8S-KB-4-1-1")
    kb411 = [row for row in tables["findings"] if row.get("ref_id") == "K8S-KB-4-1-1"]
    if not kb411 or kb411[0].get("severity") != "medium":
        _fail("kube-bench top-level tests 4.1.1 FAIL must map to medium")
    if "K8S-KB-4-1-2" not in finding_refs:
        _fail("kube-bench top-level tests finding missing: K8S-KB-4-1-2")
    kb412 = [row for row in tables["findings"] if row.get("ref_id") == "K8S-KB-4-1-2"]
    if not kb412 or kb412[0].get("severity") != "medium":
        _fail("kube-bench top-level tests 4.1.2 FAIL must map to medium")
    if "K8S-KB-4-1-9" not in finding_refs:
        _fail("kube-bench top-level tests WARN finding missing: K8S-KB-4-1-9")
    kb419 = [row for row in tables["findings"] if row.get("ref_id") == "K8S-KB-4-1-9"]
    if not kb419 or kb419[0].get("severity") != "medium":
        _fail("kube-bench top-level tests 4.1.9 WARN must map to medium")
    if "K8S-KB-4-1-10" in finding_refs:
        _fail("kube-bench top-level tests PASS must be skipped: K8S-KB-4-1-10")
    if "K8S-KB-1-2-6" not in finding_refs:
        _fail("kube-bench WARN finding missing: K8S-KB-1-2-6")
    if "K8S-KB-1-2-7" not in finding_refs:
        _fail("kube-bench Fail mixed-case finding missing: K8S-KB-1-2-7")
    fail_mixed = [row for row in tables["findings"] if row.get("ref_id") == "K8S-KB-1-2-7"]
    if not fail_mixed or fail_mixed[0].get("severity") != "medium":
        _fail("kube-bench status Fail must map to medium")
    if "K8S-KB-1-2-8" not in finding_refs:
        _fail("kube-bench Failed finding missing: K8S-KB-1-2-8")
    failed_rows = [row for row in tables["findings"] if row.get("ref_id") == "K8S-KB-1-2-8"]
    if not failed_rows or failed_rows[0].get("severity") != "medium":
        _fail("kube-bench status Failed must map to medium")
    warn_rows = [row for row in tables["findings"] if row.get("ref_id") == "K8S-KB-1-2-6"]
    if not warn_rows or warn_rows[0].get("severity") != "medium":
        _fail("kube-bench WARN must map to medium")
    easm_keys: list[tuple[str, str]] = []
    easm_path = canon / "easm.jsonl"
    for line in easm_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("kind") != "finding":
            continue
        related = row.get("related_assets") or []
        host = str(related[0] if related else "").lower().rstrip(".")
        labels = {str(x).lower() for x in (row.get("labels") or [])}
        fkind = "exposed" if "exposed" in labels else "enum"
        key = (host, fkind)
        if key in easm_keys:
            _fail(f"duplicate easm finding hostname+kind: {key}")
        easm_keys.append(key)
    if ("admin-confluence.example-corp.com", "exposed") not in easm_keys:
        _fail("httpx JSON input exposed finding missing: admin-confluence.example-corp.com")
    if ("admin-confluence.example-corp.com", "enum") in easm_keys:
        _fail("httpx JSON input must not be treated as subfinder/amass enum")
    if ("test.example-corp.com", "exposed") not in easm_keys:
        _fail("httpx URL-only exposed finding missing: test.example-corp.com")
    if ("admin-sso.example-corp.com", "enum") not in easm_keys:
        _fail("subfinder JSONL enum finding missing: admin-sso.example-corp.com")
    if ("admin-sso.example-corp.com", "exposed") in easm_keys:
        _fail("subfinder JSONL {host} must not be treated as httpx exposed")
    if ("vpn.backup.example-corp.com", "enum") not in easm_keys:
        _fail("Amass names-array enum finding missing: vpn.backup.example-corp.com")
    if ("vpn.backup.example-corp.com", "exposed") in easm_keys:
        _fail("Amass names-array must not be treated as httpx exposed")
    if ("admin-portal.example-corp.com", "enum") not in easm_keys:
        _fail("Amass names-array enum finding missing: admin-portal.example-corp.com")
    if ("admin-vpn.example-corp.com", "enum") not in easm_keys:
        _fail("Amass JSON enum finding missing: admin-vpn.example-corp.com")
    if ("admin-vpn.example-corp.com", "exposed") in easm_keys:
        _fail("Amass JSON {name} must not be treated as httpx exposed")


def _check_risks() -> None:
    risks = json.loads((RR / "risks_proposed.json").read_text(encoding="utf-8"))
    if not isinstance(risks, list):
        _fail("risks_proposed.json must be a list")
    for row in risks:
        sev = str(row.get("severity") or "").lower()
        if sev not in {"high", "critical"}:
            _fail(f"risks_proposed contains non high/critical: {row}")
        if row.get("likelihood") not in RR_LIKELIHOODS:
            _fail(f"likelihood invalid: {row}")
        if row.get("impact") not in RR_IMPACTS:
            _fail(f"impact invalid: {row}")
    proposed_refs = {str(r.get("ref_id") or "") for r in risks}
    findings_path = CISO / "findings.csv"
    high_crit: list[dict[str, str]] = []
    with findings_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("severity") not in {"high", "critical"}:
                continue
            high_crit.append(row)
            expected = f"RSK-{row.get('ref_id')}"
            if expected not in proposed_refs:
                _fail(f"high/crit finding missing from risks_proposed: {row.get('ref_id')}")
    _, scenarios = _read_csv(CISO / "risk_scenarios.csv", ";")
    if len(scenarios) != len(high_crit):
        _fail(
            f"risk_scenarios {len(scenarios)} != high+critical findings {len(high_crit)}"
        )
    scenario_refs = [str(r.get("ref_id") or "") for r in scenarios]
    if any(not ref for ref in scenario_refs):
        _fail("risk_scenarios row missing ref_id")
    scenario_dups = _dupes(scenario_refs)
    if scenario_dups:
        _fail("duplicate risk_scenarios ref_ids: " + ",".join(scenario_dups[:8]))
    scenario_set = set(scenario_refs)
    for row in high_crit:
        expected = f"RSK-{row.get('ref_id')}"
        if expected not in scenario_set:
            _fail(f"high/crit finding missing from risk_scenarios: {row.get('ref_id')}")
    if len(risks) != len(high_crit):
        _fail(f"risks_proposed {len(risks)} != high+critical findings {len(high_crit)}")


def _scan_secrets() -> None:
    example_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    yaml_raw = OUT / "raw" / "code" / "aws-creds.yaml"
    jsonl_raw = OUT / "raw" / "code" / "aws-creds.jsonl"
    if not yaml_raw.exists():
        _fail("missing redacted raw copy: out/raw/code/aws-creds.yaml")
    if not jsonl_raw.exists():
        _fail("missing redacted raw copy: out/raw/code/aws-creds.jsonl")
    for path in (yaml_raw, jsonl_raw):
        text = path.read_text(encoding="utf-8", errors="replace")
        if example_secret in text:
            _fail(f"aws_secret_access_key value leaked in {path}")
        if "[REDACTED]" not in text:
            _fail(f"expected [REDACTED] in {path}")
    for path in OUT.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".csv", ".json", ".jsonl", ".md", ".txt", ".yml", ".yaml", ".sarif"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if AWS_KEY.search(text):
            _fail(f"raw AWS access key in {path}")
        if example_secret in text:
            _fail(f"aws_secret_access_key value leaked in {path}")
        if path.suffix.lower() in {".json", ".jsonl"} and LEAKED_SECRET_FIELD.search(text):
            _fail(f"unredacted Secret field in {path}")
        if path.suffix.lower() in {".json", ".jsonl"} and "ghp_exampleExampleExampleExampleExamp" in text:
            _fail(f"gitleaks Secret value leaked in {path}")
        if "ghp_sarifSnippetMustNotLeakAAAA" in text:
            _fail(f"gitleaks SARIF snippet leaked in {path}")


def _check_idempotent(summary: dict) -> None:
    snap = OUT / "evidence" / "summary-pass1.json"
    if not snap.exists():
        _fail("missing out/evidence/summary-pass1.json (run_lab.ps1 must double-run collectors+loader)")
    try:
        pass1 = json.loads(snap.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        _fail(f"summary-pass1.json invalid JSON: {exc}")
    if not isinstance(pass1, dict):
        _fail("summary-pass1.json must be an object")
    diffs: list[str] = []
    for key in SUMMARY_KEYS:
        if pass1.get(key) != summary.get(key):
            diffs.append(f"{key}: pass1={pass1.get(key)} pass2={summary.get(key)}")
    report = OUT / "evidence" / "idempotent.md"
    lines = [
        "# Idempotent double-run",
        "",
        "collectors+loader pass 1 vs pass 2",
        "result: " + ("match" if not diffs else "MISMATCH"),
        "",
        "pass 1: " + format_summary_line(pass1),
        "pass 2: " + format_summary_line(summary),
        "",
    ]
    if diffs:
        lines.append("diffs:")
        lines.extend(f"- {item}" for item in diffs)
        lines.append("")
    report.write_text("\n".join(lines), encoding="utf-8")
    if diffs:
        _fail("idempotent counts differ: " + "; ".join(diffs))


def _scan_push_scripts() -> None:
    pack = Path(__file__).resolve().parents[1]
    forbidden = "POST /api/risks"
    wrap_needles = ("/api/itsm", "/api/auth/login", "curl.exe -fsS -X POST")
    hits = []
    for path in pack.glob("push_*"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if forbidden in text:
            hits.append(f"{path} {forbidden}")
        if path.name.startswith("push_riskready"):
            lower = text.lower()
            for needle in wrap_needles:
                if needle.lower() in lower:
                    hits.append(f"{path} wrap {needle}")
            if "WRAP_DEAD" not in text:
                hits.append(f"{path} missing WRAP_DEAD")
    if hits:
        _fail("push scripts wrap/risk POST: " + "; ".join(hits))


def assert_lab() -> dict:
    bind_out()
    _require_files()
    tables = _check_headers()
    _check_enums(tables)
    _check_canonical_and_prefixes(tables)
    _check_uniques(tables)
    summary = _check_counts(tables)
    _check_idempotent(summary)
    _check_risks()
    _check_changelog(summary)
    _scan_secrets()
    _scan_push_scripts()
    return summary


SUMMARY_KEYS = (
    "assets",
    "findings",
    "evidence",
    "incidents",
    "vulnerabilities",
    "risks_proposed",
    "applied_controls",
    "canonical_rows",
    "sensors_canonical",
)


def format_summary_line(summary: dict) -> str:
    return "summary: " + ", ".join(f"{k} {summary.get(k)}" for k in SUMMARY_KEYS) + "."


def refresh_latest_lab(summary: dict) -> None:
    """Stamp CHANGELOG.md ## latest lab from summary.json (run_lab.ps1 --stamp)."""
    path = ROOT / "CHANGELOG.md"
    text = path.read_text(encoding="utf-8") if path.exists() else "# Changelog\n"
    block = (
        "## latest lab\n\n"
        "Auto-stamped from out/summary.json after run_lab.ps1.\n"
        f"{format_summary_line(summary)}\n"
    )
    if re.search(r"^## latest lab\s*$", text, re.M):
        text = re.sub(
            r"^## latest lab\n(?:.*?)(?=^## |\Z)",
            block + "\n",
            text,
            count=1,
            flags=re.M | re.S,
        )
    elif text.lstrip().startswith("# Changelog"):
        first, _, rest = text.partition("\n")
        text = first + "\n\n" + block + "\n" + rest.lstrip("\n")
    else:
        text = "# Changelog\n\n" + block + "\n" + text
    path.write_text(text, encoding="utf-8")


def _check_changelog(summary: dict) -> None:
    path = ROOT / "CHANGELOG.md"
    if not path.exists():
        _fail("missing CHANGELOG.md")
    text = path.read_text(encoding="utf-8")
    cycles = re.findall(r"^## cycle\s+(\d+)\s*$", text, re.M | re.I)
    if not cycles:
        _fail("CHANGELOG.md missing ## cycle N headings")
    bodies = re.split(r"(?im)^## cycle\s+\d+\s*$", text)[1:]
    if not bodies:
        _fail("CHANGELOG.md cycle sections empty")
    latest_n, latest_body = cycles[0], bodies[0]
    if "summary:" not in latest_body.lower():
        _fail(f"CHANGELOG cycle {latest_n} missing summary: line")
    for key in SUMMARY_KEYS:
        if not re.search(rf"\b{re.escape(key)}\b", latest_body, re.I):
            _fail(f"CHANGELOG cycle {latest_n} missing summary key {key}")
    match = re.search(r"^## latest lab\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not match:
        _fail("CHANGELOG.md missing ## latest lab stamp (run lab_outputs --stamp)")
    blob = match.group(1)
    for key in SUMMARY_KEYS:
        want = str(summary.get(key))
        if not re.search(rf"\b{re.escape(key)}\s+{re.escape(want)}\b", blob, re.I):
            _fail(f"CHANGELOG latest lab missing {key} {want}")


def main() -> int:
    try:
        bind_out()
        if "--stamp" in sys.argv:
            summary_path = OUT / "summary.json"
            if not summary_path.exists():
                _fail("summary.json missing; cannot stamp CHANGELOG")
            refresh_latest_lab(json.loads(summary_path.read_text(encoding="utf-8")))
        summary = assert_lab()
    except LabFailure as exc:
        print(f"LAB_FAIL: {exc}")
        return 1
    print("LAB_GREEN")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
