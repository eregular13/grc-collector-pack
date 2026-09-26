"""One weakness-class → NIST CSF 2.0 subcategory + CISA CPG 2.0 table.

IDs are copied from the published catalogs. This module does not invent
subcategory or CPG identifiers. Wizard-safe stamps (no colons) are derived
from those official IDs for the CISO wire.

Sources
-------
* NIST CSF 2.0 Core (NIST CSWP 29, 2024-02-26), Appendix A.
  https://doi.org/10.6028/NIST.CSWP.29
* CISA Cross-Sector Cybersecurity Performance Goals 2.0 (current published
  CPGs as of 2026-09-26).
  https://www.cisa.gov/cybersecurity-performance-goals-2-0-cpg-2-0

CPG version used: **CPG 2.0** (CISA's current published set; CPG 1.0.1
1.E / 2.W are not current).

CSF function on the CISO wire stays the PR #128 stamp (800-53 / CIS / topic).
The subcategory is chosen under that function. When a class has two honest
subcategories (vuln → ID.RA-01 or PR.PS-02), the stamped function picks.
Anything that cannot be mapped is the explicit value ``unmapped`` — never
``csf_PR``.

Internet-facing rule (CPG 3.S vs 3.I)
-------------------------------------
CPG 2.0 **3.S Secure Internet Facing Devices** is stamped only when
``is_internet_facing`` finds evidence: a public unicast IP, collector
source ``easm``, a cloud public flag (RDS/S3/SG 0.0.0.0/0), or an
explicit extra flag. CPG 2.0 **3.I Implement Logical/Physical Network
Segmentation** is the honest goal for internal exposure (Telnet, SMB
445 on a DC, msrpc 135, admin shares, unauthenticated Redis on RFC1918).
No evidence → do not claim internet-facing.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# NIST CSF 2.0 subcategory IDs that this pack may stamp. Every id was checked
# against NIST CSWP 29 Appendix A. Withdrawn 1.1 ids (PR.DS-03..09, DE.CM-04
# etc.) are intentionally absent.
CSF20_SUBCATEGORIES: dict[str, str] = {
    "ID.AM-01": "Inventories of hardware managed by the organization are maintained",
    "ID.RA-01": "Vulnerabilities in assets are identified, validated, and recorded",
    "PR.AA-01": (
        "Identities and credentials for authorized users, services, and hardware "
        "are managed by the organization"
    ),
    "PR.AA-03": "Users, services, and hardware are authenticated",
    "PR.AA-05": (
        "Access permissions, entitlements, and authorizations are defined in a "
        "policy, managed, enforced, and reviewed, and incorporate the principles "
        "of least privilege and separation of duties"
    ),
    "PR.DS-01": (
        "The confidentiality, integrity, and availability of data-at-rest are protected"
    ),
    "PR.DS-02": (
        "The confidentiality, integrity, and availability of data-in-transit are protected"
    ),
    "PR.PS-01": "Configuration management practices are established and applied",
    "PR.PS-02": "Software is maintained, replaced, and removed commensurate with risk",
    "PR.PS-04": "Log records are generated and made available for continuous monitoring",
    "PR.PS-06": (
        "Secure software development practices are integrated, and their "
        "performance is monitored throughout the software development life cycle"
    ),
    "PR.IR-01": (
        "Networks and environments are protected from unauthorized logical access "
        "and usage"
    ),
    "DE.CM-01": (
        "Networks and network services are monitored to find potentially adverse events"
    ),
    "DE.CM-03": (
        "Personnel activity and technology usage are monitored to find potentially adverse events"
    ),
    "DE.CM-09": (
        "Computing hardware and software, runtime environments, and their data "
        "are monitored to find potentially adverse events"
    ),
}

CSF20_FUNCTION_OF = {
    sid: {"ID": "identify", "PR": "protect", "DE": "detect", "GV": "govern", "RS": "respond", "RC": "recover"}[sid.split(".", 1)[0]]
    for sid in CSF20_SUBCATEGORIES
}

# CISA CPG 2.0 goal id → published name. Checked against the CPG 2.0 page.
CPG20_GOALS: dict[str, str] = {
    "2.A": "Manage Organizational Assets",
    "2.B": "Mitigate Known Vulnerabilities",
    "3.A": "Changing Default Passwords",
    "3.B": "Establish Minimum Password Strength",
    "3.C": "Create Unique Credentials",
    "3.D": "Revoking Credentials for Departing Staff",
    "3.E": "Monitor Unsuccessful (Automated) Login Attempts",
    "3.F": "Implement Multi-factor Authentication",
    "3.H": "Implement the Principles of Least Privilege",
    "3.K": "Utilize Strong Encryption",
    "3.L": "Enable Email Security",
    "3.N": "Establish Change Management Processes",
    "3.Q": "Maintain Log Collection & Storage",
    "3.I": "Implement Logical/Physical Network Segmentation",
    "3.S": "Secure Internet Facing Devices",
    "4.A": "Establish Malicious Code Detection",
    "4.B": "Identify Adverse Events",
}

# Function-level CSF stamps and retired CPG 1.0.1 ids. The register may carry
# class-based subcategory/goal stamps (same as poam.csv) or none — never these.
BLANKET_REGISTER_STAMPS = frozenset(
    {
        "csf_PR",
        "csf_protect",
        "csf_GV",
        "csf_govern",
        "csf_ID",
        "csf_identify",
        "csf_DE",
        "csf_detect",
        "csf_RS",
        "csf_respond",
        "csf_RC",
        "csf_recover",
        "cpg_2_W",
        "cpg_1_E",
    }
)

# Cloud / playbook rows that are internet-facing by evidence, not by guess.
_INTERNET_FACING_TYPES = frozenset(
    {
        "rds_public",
        "s3_public_access",
        "sg_ingress_open",
    }
)
_INTERNET_FACING_CONTROLS = frozenset(
    {
        "Disable public accessibility on RDS",
        "Block public object-storage access",
        "Block public object-storage ACL and policy",
        "Restrict security-group ingress from the internet",
    }
)
_EXTERNAL_SCAN_SOURCES = frozenset({"easm"})
_EXPOSURE_CPG_CLASSES = frozenset({"exposure_network", "exposure_access"})

UNMAPPED = "unmapped"
CSF_UNMAPPED_STAMP = "csf_unmapped"
CPG_UNMAPPED_STAMP = "cpg_unmapped"

# One row per weakness class. `by_function` reconciles with the PR #128 stamp.
# source_note cites the official catalog line that justifies the pair.
WEAKNESS_CLASS_MAP: dict[str, dict[str, Any]] = {
    "vuln_patch": {
        "by_function": {"identify": "ID.RA-01", "protect": "PR.PS-02"},
        "cpg": "2.B",
        "source_note": (
            "NIST CSF 2.0 ID.RA-01 / PR.PS-02 (CSWP 29); CISA CPG 2.0 2.B "
            "Mitigate Known Vulnerabilities. Vuln/patch findings."
        ),
    },
    "exposure_network": {
        "by_function": {"protect": "PR.IR-01", "identify": "ID.AM-01"},
        "cpg": "3.S",
        "source_note": (
            "NIST CSF 2.0 PR.IR-01 (unauthorized logical access to networks). "
            "CISA CPG 2.0 3.S Secure Internet Facing Devices only when "
            "is_internet_facing() has evidence (public IP, easm source, cloud "
            "public flag). Otherwise CPG 2.0 3.I Implement Logical/Physical "
            "Network Segmentation. No evidence → not internet-facing."
        ),
    },
    "exposure_access": {
        "by_function": {"protect": "PR.AA-05"},
        "cpg": "3.S",
        "source_note": (
            "NIST CSF 2.0 PR.AA-05 (least privilege / entitlements). CPG 3.S "
            "only with internet-facing evidence (public ACL / RDS / 0.0.0.0/0); "
            "else CPG 3.I. Guest, anonymous, admin-share, Redis without auth, "
            "or public-ACL exposure."
        ),
    },
    "host_firewall": {
        "by_function": {"protect": "PR.PS-01"},
        "cpg": "3.I",
        "source_note": (
            "NIST CSF 2.0 PR.PS-01 (configuration management); CISA CPG 2.0 "
            "3.I Implement Logical/Physical Network Segmentation. A disabled "
            "host firewall is a missing segmentation control, not 3.S."
        ),
    },
    "tls_crypto": {
        "by_function": {"protect": "PR.DS-02"},
        "cpg": "3.K",
        "source_note": (
            "NIST CSF 2.0 PR.DS-02 (data-in-transit); CISA CPG 2.0 3.K "
            "Utilize Strong Encryption. TLS/SSL protocol, cipher, cert, signing."
        ),
    },
    "encryption_rest": {
        "by_function": {"protect": "PR.DS-01"},
        "cpg": "3.K",
        "source_note": (
            "NIST CSF 2.0 PR.DS-01 (data-at-rest); CISA CPG 2.0 3.K "
            "Utilize Strong Encryption. Disk / object / volume encryption."
        ),
    },
    "identity_mfa": {
        "by_function": {"protect": "PR.AA-03"},
        "cpg": "3.F",
        "source_note": (
            "NIST CSF 2.0 PR.AA-03 (authentication); CISA CPG 2.0 3.F "
            "Implement Multi-factor Authentication. Legacy auth (IMAP/SMTP "
            "basic) is here because those protocols cannot carry MFA."
        ),
    },
    "identity_privilege": {
        "by_function": {"protect": "PR.AA-05"},
        "cpg": "3.H",
        "source_note": (
            "NIST CSF 2.0 PR.AA-05 (least privilege); CISA CPG 2.0 3.H "
            "Implement the Principles of Least Privilege. Standing admin / AD ACEs."
        ),
    },
    "identity_credential": {
        "by_function": {"protect": "PR.AA-01"},
        "cpg": "3.C",
        "source_note": (
            "NIST CSF 2.0 PR.AA-01 (identities and credentials managed); "
            "CISA CPG 2.0 3.C Create Unique Credentials. Secrets / roastable SPNs."
        ),
    },
    "identity_password": {
        "by_function": {"protect": "PR.AA-01"},
        "cpg": "3.B",
        "source_note": (
            "NIST CSF 2.0 PR.AA-01; CISA CPG 2.0 3.B Establish Minimum "
            "Password Strength. Password policy / empty / LM hash. AS-REP "
            "roastable and Kerberoast/roastable SPN are offline cracks of "
            "Kerberos material encrypted with the account password — 3.B, "
            "not 3.E (failed-login monitoring) or only 3.C (unique creds)."
        ),
    },
    "identity_default": {
        "by_function": {"protect": "PR.AA-01"},
        "cpg": "3.A",
        "source_note": (
            "NIST CSF 2.0 PR.AA-01; CISA CPG 2.0 3.A Changing Default Passwords."
        ),
    },
    "identity_lifecycle": {
        "by_function": {"protect": "PR.AA-01"},
        "cpg": "3.D",
        "source_note": (
            "NIST CSF 2.0 PR.AA-01; CISA CPG 2.0 3.D Revoking Credentials for "
            "Departing Staff. Stale guest / unused accounts."
        ),
    },
    "identity_auth": {
        "by_function": {"protect": "PR.AA-03", "detect": "DE.CM-03"},
        "cpg": "3.E",
        "source_note": (
            "NIST CSF 2.0 PR.AA-03 (authentication) or DE.CM-01 when the "
            "stamped function is detect; CISA CPG 2.0 3.E Monitor Unsuccessful "
            "(Automated) Login Attempts. Lockout, session lock, brute-force. "
            "Legacy auth is identity_mfa (3.F); AS-REP/Kerberoast is "
            "identity_password (3.B)."
        ),
    },
    "config_benchmark": {
        "by_function": {"protect": "PR.PS-01"},
        "cpg": "3.N",
        "source_note": (
            "NIST CSF 2.0 PR.PS-01 (configuration management); CISA CPG 2.0 "
            "3.N Establish Change Management Processes. Benchmark / MDM "
            "enrollment / directory listing. Falco binary-dir writes are "
            "detect_endpoint (runtime), not this class."
        ),
    },
    "email_dns": {
        "by_function": {"protect": "PR.DS-02"},
        "cpg": "3.L",
        "source_note": (
            "NIST CSF 2.0 PR.DS-02 (in-transit authenticity); CISA CPG 2.0 3.L "
            "Enable Email Security (SPF / DKIM / DMARC)."
        ),
    },
    "detect_endpoint": {
        "by_function": {"detect": "DE.CM-09", "protect": "PR.PS-02"},
        "cpg": "4.A",
        "source_note": (
            "NIST CSF 2.0 DE.CM-09 (endpoint monitoring) or PR.PS-02 when the "
            "stamped function is protect (SI-3 malware protection); CISA CPG 2.0 "
            "4.A Establish Malicious Code Detection. EDR / AV / Falco "
            "write-below-binary-dir (runtime integrity signal)."
        ),
    },
    "detect_telemetry": {
        "by_function": {"detect": "DE.CM-01", "protect": "PR.IR-01"},
        "cpg": "4.B",
        "source_note": (
            "NIST CSF 2.0 DE.CM-01 (network/service monitoring); CISA CPG 2.0 "
            "4.B Identify Adverse Events. Honeypot / coverage-gap / agent down."
        ),
    },
    "detect_time": {
        "by_function": {"detect": "DE.CM-09"},
        "cpg": "3.Q",
        "source_note": (
            "NIST CSF 2.0 DE.CM-09 (runtime/data monitoring needs trustworthy "
            "time); CISA CPG 2.0 3.Q Maintain Log Collection & Storage. NTP/chrony."
        ),
    },
    "logging": {
        "by_function": {"detect": "DE.CM-09", "protect": "PR.PS-04"},
        "cpg": "3.Q",
        "source_note": (
            "NIST CSF 2.0 DE.CM-09 / PR.PS-04 (log generation); CISA CPG 2.0 "
            "3.Q Maintain Log Collection & Storage. CloudTrail / audit policy."
        ),
    },
    "asset_inventory": {
        "by_function": {"identify": "ID.AM-01", "protect": "PR.IR-01"},
        "cpg": "2.A",
        "source_note": (
            "NIST CSF 2.0 ID.AM-01 (hardware inventory) when Identify; PR.IR-01 "
            "when the stamp is Protect. CISA CPG 2.0 2.A Manage Organizational "
            "Assets. Inventory-only rows. Sensitive perimeter hostnames from "
            "EASM are exposure_network (lock down the listener), not this class."
        ),
    },
    "app_secure_dev": {
        "by_function": {"protect": "PR.PS-06"},
        "cpg": "2.B",
        "source_note": (
            "NIST CSF 2.0 PR.PS-06 (secure software development); CISA CPG 2.0 "
            "2.B Mitigate Known Vulnerabilities. SQLi / XSS / command injection."
        ),
    },
    UNMAPPED: {
        "by_function": {},
        "cpg": UNMAPPED,
        "source_note": (
            "No honest CSF 2.0 subcategory or CPG 2.0 goal. Explicit unmapped; "
            "never default to csf_PR."
        ),
    },
}

# Named playbook → class. Keys are control_name values from control_map.
CONTROL_CLASS: dict[str, str] = {
    "Restrict Windows admin shares": "exposure_access",
    "Harden or restrict SMB file sharing": "exposure_network",
    "Disable Telnet; require encrypted remote admin": "exposure_network",
    "Disable or lock down cleartext FTP": "exposure_network",
    "Restrict RDP to approved paths": "exposure_network",
    "Disable TLS 1.0": "tls_crypto",
    "Harden TLS on the exposed service": "tls_crypto",
    "Remediate Heartbleed-vulnerable TLS": "vuln_patch",
    "Review deception-sensor telemetry": "detect_telemetry",
    "Publish a DMARC policy": "email_dns",
    "Tighten DMARC beyond p=none": "email_dns",
    "Restrict SPF +all": "email_dns",
    "Publish an SPF record": "email_dns",
    "Tighten SPF softfail (~all)": "email_dns",
    "Publish DKIM for the listed selector": "email_dns",
    "Block public object-storage access": "exposure_access",
    "Block public object-storage ACL and policy": "exposure_access",
    "Remove standing IAM AdministratorAccess": "identity_privilege",
    "Require MFA on the cloud root account": "identity_mfa",
    "Restrict security-group ingress from the internet": "exposure_network",
    "Disable public accessibility on RDS": "exposure_network",
    "Enable encryption at rest on cloud storage": "encryption_rest",
    "Enable S3 default encryption (SSE-S3 or SSE-KMS)": "encryption_rest",
    "Enable EBS volume encryption": "encryption_rest",
    "Require MFA on IAM users": "identity_mfa",
    "Enable multi-region CloudTrail logging": "logging",
    "Stop SQL injection in the application": "app_secure_dev",
    "Stop OS command injection": "app_secure_dev",
    "Patch Log4Shell-vulnerable services": "vuln_patch",
    "Stop remote code execution": "vuln_patch",
    "Stop cross-site scripting": "app_secure_dev",
    "Remove non-DC DCSync rights": "identity_privilege",
    "Remove non-DC DCSync / replication rights": "identity_privilege",
    "Remove standing local-admin (AdminTo) rights": "identity_privilege",
    "Disable SMB null / anonymous sessions": "exposure_access",
    "Remove GenericAll on privileged objects": "identity_privilege",
    "Require Kerberos preauthentication": "identity_password",
    "Harden kerberoastable service accounts": "identity_password",
    "Remove unconstrained Kerberos delegation": "identity_privilege",
    "Restrict Backup Operators membership": "identity_privilege",
    "Restrict Domain Admins membership": "identity_privilege",
    "Enable full-disk encryption": "encryption_rest",
    "Deploy endpoint detection and response": "detect_endpoint",
    "Enroll the endpoint in MDM": "config_benchmark",
    "Review and expire stale guest accounts": "identity_lifecycle",
    "Restore endpoint coverage": "detect_telemetry",
    "Rotate and revoke exposed credentials": "identity_credential",
    "Require phishing-resistant MFA for privileged users": "identity_mfa",
    "Require MFA for privileged SaaS admins": "identity_mfa",
    "Remove standing Global Administrator assignment": "identity_privilege",
    "Enforce Windows password history": "identity_password",
    "Disable LM hash storage": "identity_password",
    "Enable a host firewall": "host_firewall",
    "Disable SSH root login": "identity_privilege",
    "Disable SSH empty passwords": "identity_password",
    "Apply security updates": "vuln_patch",
    "Apply vulnerability remediation": "vuln_patch",
    "Enable time synchronization": "detect_time",
    "Enforce password policy": "identity_password",
    "Enforce account lockout": "identity_auth",
    "Enforce session lock": "identity_auth",
    "Enable audit logging": "logging",
    "Enable malware protection": "detect_endpoint",
    "Require encryption in transit": "tls_crypto",
    "Deny privileged Kubernetes containers": "identity_privilege",
    "Disable anonymous Kubernetes API access": "exposure_access",
    "Block Kubernetes privilege escalation": "identity_privilege",
    "Avoid hostNetwork on Kubernetes workloads": "exposure_network",
    "Stop writes under container binary directories": "detect_endpoint",
    "Restrict exposed admin interfaces": "exposure_network",
    "Lock down sensitive perimeter hostnames": "exposure_network",
    "Remove standing privileged role assignment": "identity_privilege",
    "Disable legacy authentication protocols": "identity_mfa",
    "Restrict external sharing": "exposure_access",
    "Review SSH brute-force activity": "identity_auth",
    "Disable anonymous FTP access": "exposure_access",
    "Require authentication on Redis": "exposure_access",
    "Disable web server directory listing": "config_benchmark",
    "Disable deprecated TLS protocols": "tls_crypto",
    "Remove weak TLS cipher suites": "tls_crypto",
    "Replace self-signed TLS certificate with a trusted CA certificate": "tls_crypto",
    "Reissue TLS certificate with a strong key": "tls_crypto",
    "Require SMB message signing": "tls_crypto",
    "Disable SMB guest access": "exposure_access",
    "Set strong credentials on database accounts": "identity_password",
    "Remove vendor default credentials": "identity_default",
}

FINDING_TYPE_CLASS: dict[str, str] = {
    "s3_public_access": "exposure_access",
    "s3_encryption": "encryption_rest",
    "ebs_encryption": "encryption_rest",
    "iam_admin_access": "identity_privilege",
    "iam_root_mfa": "identity_mfa",
    "iam_user_mfa": "identity_mfa",
    "sg_ingress_open": "exposure_network",
    "cloudtrail_logging": "logging",
    "rds_public": "exposure_network",
    "ad_dcsync": "identity_privilege",
    "ad_genericall": "identity_privilege",
    "ad_adminto": "identity_privilege",
    "ad_backup_operators": "identity_privilege",
    "ad_kerberoast": "identity_password",
    "ad_asrep": "identity_password",
    "ad_domain_admins": "identity_privilege",
    "ad_unconstrained_delegation": "identity_privilege",
    "entra_ga_pim": "identity_privilege",
    "ad_smb_null_session": "exposure_access",
    "hk_password_history": "identity_password",
    "hk_lm_hash": "identity_password",
    "k8s_privileged": "identity_privilege",
    "k8s_anonymous_auth": "exposure_access",
    "k8s_privilege_escalation": "identity_privilege",
    "k8s_hostnetwork": "exposure_network",
    "k8s_write_binary_dir": "detect_endpoint",
    "honeypot": "detect_telemetry",
    "nse-ftp-anon": "exposure_access",
    "nse-redis-noauth": "exposure_access",
    "exposed-redis": "exposure_access",
    "nse-http-dirlist": "config_benchmark",
    "nse-tls-deprecated-protocol": "tls_crypto",
    "nse-tls-weak-cipher": "tls_crypto",
    "nse-tls-self-signed": "tls_crypto",
    "nse-tls-weak-key": "tls_crypto",
    "nse-smb-signing-not-required": "tls_crypto",
    "nse-smb-guest": "exposure_access",
    "nse-db-empty-password": "identity_password",
    "nse-default-credentials": "identity_default",
}


def csf_stamp(subcategory_id: str) -> str:
    """Wizard-safe CSF 2.0 subcategory stamp. PR.IR-01 → csf_PR_IR_01."""
    if subcategory_id == UNMAPPED:
        return CSF_UNMAPPED_STAMP
    return "csf_" + subcategory_id.replace(".", "_").replace("-", "_")


def cpg_stamp(cpg_id: str) -> str:
    """Wizard-safe CPG 2.0 stamp. 3.S → cpg_3_S."""
    if cpg_id == UNMAPPED:
        return CPG_UNMAPPED_STAMP
    return "cpg_" + cpg_id.replace(".", "_")


def _looks_unauth_redis(mapped: dict[str, Any], rec: dict[str, Any]) -> bool:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    tid = str(
        mapped.get("finding_type")
        or extra.get("template_id")
        or extra.get("rule")
        or extra.get("check_id")
        or ""
    ).lower()
    if tid in {"exposed-redis", "nse-redis-noauth"}:
        return True
    blob = " ".join(
        str(x or "")
        for x in (
            mapped.get("control_name"),
            mapped.get("weakness_name"),
            rec.get("name"),
            rec.get("description"),
        )
    ).lower()
    if "redis" not in blob:
        return False
    return any(
        tok in blob
        for tok in (
            "without auth",
            "unauthenticated",
            "noauth",
            "no auth",
            "requirepass",
            "accessible without authentication",
        )
    )


def classify_weakness_class(mapped: dict[str, Any], rec: dict[str, Any] | None = None) -> str:
    """Pick one class from control name, finding type, then light heuristics."""
    rec = rec or {}
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    ftype = str(
        mapped.get("finding_type")
        or extra.get("check_id")
        or extra.get("template_id")
        or extra.get("rule")
        or ""
    )
    if ftype in FINDING_TYPE_CLASS:
        return FINDING_TYPE_CLASS[ftype]
    if _looks_unauth_redis(mapped, rec):
        return "exposure_access"
    name = str(mapped.get("control_name") or "")
    if name in CONTROL_CLASS:
        return CONTROL_CLASS[name]
    if name.startswith("Reduce unnecessary network exposure"):
        return "exposure_network"
    if name.startswith("Patch ") or name.startswith("Apply security") or name.startswith("Apply vulnerability"):
        return "vuln_patch"
    if name.startswith("Remediate:") or name.startswith("Review and remediate"):
        return UNMAPPED
    cat = str(rec.get("category") or "").lower()
    if cat == "vulnerability" or mapped.get("nist_800_53") == ["SI-2", "RA-5"]:
        if "SI-2" in (mapped.get("nist_800_53") or []) and "RA-5" in (mapped.get("nist_800_53") or []):
            return "vuln_patch"
    if cat in {"honeypot", "deception-sensor"}:
        return "detect_telemetry"
    return UNMAPPED


def _iter_candidate_hosts(rec: dict[str, Any] | None, mapped: dict[str, Any] | None) -> list[str]:
    rec = rec or {}
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    out: list[str] = []
    for raw in (
        extra.get("ip"),
        extra.get("address"),
        extra.get("host"),
        extra.get("matched_at"),
        extra.get("public_ip"),
        *(rec.get("assets") or []),
    ):
        text = str(raw or "").strip()
        if text:
            out.append(text)
    return out


def _host_token_is_public_ip(raw: str) -> bool:
    """True only for a public unicast IP. RFC1918 / loopback / ULA never qualify."""
    token = str(raw or "").strip()
    if not token:
        return False
    token = token.split("%", 1)[0]
    token = token.split("/", 1)[0]
    if token.startswith("[") and "]" in token:
        token = token[1 : token.index("]")]
    if "://" in token:
        token = token.split("://", 1)[1]
    token = token.split("/", 1)[0]
    token = token.split("?", 1)[0]
    if token.count(":") == 1 and token.rsplit(":", 1)[-1].isdigit():
        token = token.rsplit(":", 1)[0]
    try:
        addr = ipaddress.ip_address(token)
    except ValueError:
        return False
    return bool(addr.is_global and not addr.is_multicast)


_CLOUD_PUBLIC_RE = re.compile(
    r"0\.0\.0\.0/0|::/0|publiclyaccessible|publicly.accessible|public_acl|public-acl",
    re.I,
)


def is_internet_facing(
    rec: dict[str, Any] | None = None, mapped: dict[str, Any] | None = None
) -> bool:
    """True only from evidence. No evidence → not internet-facing. Never guess.

    Evidence accepted
    -----------------
    * Cloud public flag: finding type rds_public / s3_public_access /
      sg_ingress_open, matching control names, extra.public /
      extra.publicly_accessible / extra.internet_facing, or 0.0.0.0/0.
    * Public unicast IP on the finding extra or assets (not RFC1918,
      loopback, link-local, CGNAT, ULA, or documentation ranges).
    * External scan source ``easm``.
    * Explicit extra.exposure in {internet, public, external}.

    Internal Telnet, SMB on dc, msrpc 135, admin shares, and Redis on
    10/8 or *.lab.internal / *.corp.local therefore stay 3.I.
    """
    rec = rec or {}
    mapped = mapped or {}
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    ftype = str(
        mapped.get("finding_type")
        or extra.get("check_id")
        or extra.get("template_id")
        or ""
    )
    if ftype in _INTERNET_FACING_TYPES:
        return True
    if str(mapped.get("control_name") or "") in _INTERNET_FACING_CONTROLS:
        return True
    source = str(rec.get("source") or "").lower()
    if source in _EXTERNAL_SCAN_SOURCES:
        return True
    for key in ("internet_facing", "publicly_accessible", "public"):
        val = extra.get(key)
        if val is True or str(val).lower() in {"1", "true", "yes", "public"}:
            return True
    exposure = str(extra.get("exposure") or extra.get("exposure_plane") or "").lower()
    if exposure in {"internet", "public", "external", "internet-facing"}:
        return True
    blob = " ".join(
        str(x or "")
        for x in (rec.get("name"), rec.get("description"), extra.get("cidr"), extra.get("ingress"))
    )
    if _CLOUD_PUBLIC_RE.search(blob):
        return True
    for host in _iter_candidate_hosts(rec, mapped):
        if _host_token_is_public_ip(host):
            return True
    return False


def resolve_class_tags(
    cls: str,
    csf_function: str,
    rec: dict[str, Any] | None = None,
    mapped: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Subcategory under the stamped function, or explicit unmapped.

    Never invent a subcategory. Never fall back to csf_PR.
    Exposure classes stamp CPG 3.S only with internet-facing evidence;
    otherwise 3.I (CISA CPG 2.0 Implement Logical/Physical Network
    Segmentation).
    """
    row = WEAKNESS_CLASS_MAP.get(cls) or WEAKNESS_CLASS_MAP[UNMAPPED]
    by_fn = dict(row.get("by_function") or {})
    official = by_fn.get(csf_function) or ""
    if official and official not in CSF20_SUBCATEGORIES:
        official = ""
    if official and CSF20_FUNCTION_OF.get(official) != csf_function:
        official = ""
    cpg_id = str(row.get("cpg") or UNMAPPED)
    if cls in _EXPOSURE_CPG_CLASSES and cpg_id == "3.S":
        if not is_internet_facing(rec, mapped):
            cpg_id = "3.I"
    if official:
        if cpg_id != UNMAPPED and cpg_id not in CPG20_GOALS:
            cpg_id = UNMAPPED
        return {
            "weakness_class": cls,
            "csf_subcategory": official,
            "csf_stamp": csf_stamp(official),
            "cpg_id": cpg_id,
            "cpg_stamp": cpg_stamp(cpg_id),
            "cpg_name": CPG20_GOALS.get(cpg_id, UNMAPPED),
            "source_note": str(row.get("source_note") or ""),
        }
    return {
        "weakness_class": cls if cls == UNMAPPED else cls,
        "csf_subcategory": UNMAPPED,
        "csf_stamp": CSF_UNMAPPED_STAMP,
        "cpg_id": UNMAPPED,
        "cpg_stamp": CPG_UNMAPPED_STAMP,
        "cpg_name": UNMAPPED,
        "source_note": str(row.get("source_note") or ""),
    }


def apply_class_mapping(mapped: dict[str, Any], rec: dict[str, Any] | None = None) -> dict[str, Any]:
    """Attach class + subcategory + CPG 2.0. Rewrites framework_refs CSF/CPG tags."""
    fn = str(mapped.get("csf_function") or "")
    cls = classify_weakness_class(mapped, rec)
    tags = resolve_class_tags(cls, fn, rec=rec, mapped=mapped)
    mapped["weakness_class"] = tags["weakness_class"]
    mapped["csf_subcategory"] = tags["csf_subcategory"]
    mapped["csf_subcategory_stamp"] = tags["csf_stamp"]
    mapped["cpg_id"] = tags["cpg_id"]
    mapped["cpg_name"] = tags["cpg_name"]
    mapped["class_source_note"] = tags["source_note"]
    mapped["cpg"] = [tags["cpg_stamp"]]
    n53 = list(mapped.get("nist_800_53") or [])
    cis = list(mapped.get("cis") or [])
    n53_tokens = [f"nist80053_{cid}" for cid in n53]
    refs = [tags["cpg_stamp"], tags["csf_stamp"]] + n53_tokens + list(cis)
    mapped["framework_refs"] = ",".join(dict.fromkeys(x for x in refs if x))
    csf_stamps = list(mapped.get("csf") or [])
    if tags["csf_stamp"] not in csf_stamps:
        csf_stamps.append(tags["csf_stamp"])
    mapped["csf"] = csf_stamps
    return mapped


def csf_cpg_tag_set(framework_refs: str) -> tuple[frozenset[str], frozenset[str]]:
    """CSF stamps and CPG stamps from a framework_refs cell."""
    csf: set[str] = set()
    cpg: set[str] = set()
    for tok in str(framework_refs or "").split(","):
        t = tok.strip()
        if t.startswith("csf_"):
            csf.add(t)
        elif t.startswith("cpg_"):
            cpg.add(t)
    return frozenset(csf), frozenset(cpg)
