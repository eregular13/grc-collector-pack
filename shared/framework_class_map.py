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

Env-eval / web-TLS NIST 800-53 IDs live in this same map. Call
``nist_800_53_ids`` from a content pipeline — do not keep a second
control map. CIS v8 tokens stay under ``extra.cis_v8_internal`` via
``cis_v8_internal_ids`` and never on client-facing ``framework_refs``.
``normalize_csf20_id`` remaps mixed CSF 1.1 (PR.AC / PR.PT / PR.IP) to
CSF 2.0.

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
from collections.abc import Mapping
from typing import Any

# Same token as shared.hardening_map.CIS_V8_PREFIX. Do not import that
# module here — it imports this file.
CIS_V8_INTERNAL_FIELD = "cis_v8_internal"
CIS_V8_PREFIX = "CIS-v8-"

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
        "Block public EBS snapshot sharing",
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
    "Block public EBS snapshot sharing": "exposure_access",
    "End privileged HasSession logons": "identity_privilege",
    "Run container images as a non-root USER": "identity_privilege",
    "Disable weak SSH cryptographic algorithms": "tls_crypto",
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
    "Require a Kubernetes container securityContext": "config_benchmark",
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
    "Disable HTTP compression on HTTPS (BREACH)": "tls_crypto",
    "Disable TLS CBC ciphers (LUCKY13)": "tls_crypto",
    "Renew the expired or expiring TLS certificate": "tls_crypto",
    "Disable TLS 1.1": "tls_crypto",
    "Disable SSLv3": "tls_crypto",
    "Disable SSLv2": "tls_crypto",
    "Remove or lock down the exposed web admin path": "exposure_access",
    "Disable web-app directory listing": "config_benchmark",
    "Remove exposed web-app sensitive files": "config_benchmark",
    "Disable dangerous HTTP methods": "config_benchmark",
    "Replace web-app default credentials": "identity_default",
    "Raise domain minimum password length": "identity_password",
    "Rotate the krbtgt password twice": "identity_credential",
    "Stop reflected web-app cross-site scripting": "config_benchmark",
    "Stop web-app local file inclusion": "config_benchmark",
    "Mark privileged accounts sensitive and cannot be delegated": "identity_privilege",
    "Set dSHeuristics LDAP security (CVE-2021-42291)": "identity_auth",
    "Deploy baseline HTTP security headers": "config_benchmark",
    "Set Secure HttpOnly SameSite cookie flags": "tls_crypto",
    "Allowlist CORS origins": "exposure_access",
    "Terminate TLS and redirect HTTP to HTTPS": "tls_crypto",
    "Replace default web welcome or error pages": "config_benchmark",
    "Redirect HTTP to HTTPS": "tls_crypto",
    "Remove public exposure of data and admin services": "exposure_network",
    "Strip Server and X-Powered-By version tokens": "config_benchmark",
    "Inventory listeners and close unused ports": "exposure_network",
    "Restrict SSH to management networks": "exposure_network",
    "Ensure TLS is present where HTTPS is expected": "tls_crypto",
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
    "k8s_security_context": "config_benchmark",
    "k8s_anonymous_auth": "exposure_access",
    "k8s_privilege_escalation": "identity_privilege",
    "k8s_hostnetwork": "exposure_network",
    "k8s_write_binary_dir": "detect_endpoint",
    "honeypot": "detect_telemetry",
    "nse-ftp-anon": "exposure_access",
    "nse-redis-noauth": "exposure_access",
    "nse_redis_noauth": "exposure_access",
    "exposed-redis": "exposure_access",
    "exposed_redis": "exposure_access",
    "redis_noauth": "exposure_access",
    "redis-noauth": "exposure_access",
    "redis-unauth": "exposure_access",
    "redis_unauth": "exposure_access",
    "nse-http-dirlist": "config_benchmark",
    "nse-tls-deprecated-protocol": "tls_crypto",
    "nse-tls-weak-cipher": "tls_crypto",
    "nse-tls-self-signed": "tls_crypto",
    "nse-tls-weak-key": "tls_crypto",
    "nse-smb-signing-not-required": "tls_crypto",
    "nse-smb-guest": "exposure_access",
    "nse-db-empty-password": "identity_password",
    "nse-default-credentials": "identity_default",
    "tls_breach": "tls_crypto",
    "tls_lucky13": "tls_crypto",
    "tls_cert_expiration": "tls_crypto",
    "tls_heartbleed": "vuln_patch",
    "tls_1_0": "tls_crypto",
    "tls_1_1": "tls_crypto",
    "tls_sslv3": "tls_crypto",
    "tls_sslv2": "tls_crypto",
    "web_admin_path": "exposure_access",
    "web_dir_listing": "config_benchmark",
    "web_sensitive_file": "config_benchmark",
    "web_http_methods": "config_benchmark",
    "web_default_creds": "identity_default",
    "web_xss": "config_benchmark",
    "web_lfi": "config_benchmark",
    "pc_min_pwd_len": "identity_password",
    "pc_krbtgt": "identity_credential",
    "pc_delegated": "identity_privilege",
    "pc_dsheuristics": "identity_auth",
    "web_security_headers": "config_benchmark",
    "web_cookie_flags": "tls_crypto",
    "web_cors": "exposure_access",
    "web_cleartext_http": "tls_crypto",
    "web_cleartext_ftp": "exposure_network",
    "web_default_page": "config_benchmark",
    "web_http_redirect": "tls_crypto",
    "web_service_exposure": "exposure_network",
    "web_tech_disclosure": "config_benchmark",
    "web_surface": "exposure_network",
    "web_ssh_banner": "exposure_network",
    "web_tls_service": "tls_crypto",
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


# Nuclei / nmap ids that are Redis-without-auth (exposure), not a patch CVE.
# Hyphen and underscore forms: finding_types.norm_type_key rewrites '-'.
REDIS_AUTH_TEMPLATE_IDS = frozenset(
    {
        "exposed-redis",
        "exposed_redis",
        "nse-redis-noauth",
        "nse_redis_noauth",
        "redis_noauth",
        "redis-noauth",
        "redis-unauth",
        "redis_unauth",
    }
)

_REDIS_AUTH_BLOB_TOKS = (
    "without auth",
    "unauthenticated",
    "noauth",
    "no auth",
    "requirepass",
    "accessible without authentication",
    "unprotected by password",
)


def redis_auth_template_ids(
    rec: dict[str, Any], mapped: dict[str, Any] | None = None
) -> list[str]:
    """Every extra/template id. Do not first-win on check_id or finding_type."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    mapped = mapped or {}
    raw: list[str] = []
    for key in ("check_id", "template_id", "rule", "template-id", "id"):
        val = str(extra.get(key) or "").strip().lower()
        if val:
            raw.append(val)
    ftype = str(mapped.get("finding_type") or "").strip().lower()
    # vuln_playbook sets finding_type=vulnerability and must not hide extra.rule.
    if ftype and ftype not in {"vulnerability", "unknown", "generic"}:
        raw.append(ftype)
    out: list[str] = []
    seen: set[str] = set()
    for val in raw:
        for form in (val, val.replace("-", "_").replace(" ", "_")):
            if form and form not in seen:
                seen.add(form)
                out.append(form)
    return out


def _looks_unauth_redis(mapped: dict[str, Any], rec: dict[str, Any]) -> bool:
    if any(tid in REDIS_AUTH_TEMPLATE_IDS for tid in redis_auth_template_ids(rec, mapped)):
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
    return any(tok in blob for tok in _REDIS_AUTH_BLOB_TOKS)


# NIST CSF 1.1 subcategory ids (and unpadded 2.0-style twins) → CSF 2.0.
# PR.AC → PR.AA, PR.PT/PR.IP → PR.PS. Official 2.0 ids pass through.
CSF11_TO_20: dict[str, str] = {
    "PR.AC-1": "PR.AA-01",
    "PR.AC-01": "PR.AA-01",
    "PR.AC-3": "PR.AA-05",
    "PR.AC-03": "PR.AA-05",
    "PR.AC-4": "PR.AA-05",
    "PR.AC-04": "PR.AA-05",
    "PR.AC-5": "PR.IR-01",
    "PR.AC-05": "PR.IR-01",
    "PR.PT-3": "PR.PS-01",
    "PR.PT-03": "PR.PS-01",
    "PR.IP-1": "PR.PS-01",
    "PR.IP-01": "PR.PS-01",
    "PR.DS-1": "PR.DS-01",
    "PR.DS-2": "PR.DS-02",
    "ID.AM-1": "ID.AM-01",
    "DE.CM-1": "DE.CM-01",
}


def normalize_csf20_id(raw: str) -> str:
    """Normalize mixed NIST CSF 1.1 / 2.0 tokens to a CSF 2.0 subcategory id.

    Returns ``unmapped`` when the token is not a known 2.0 subcategory after
    the 1.1 remap. CPG 2.0 stays the client-facing spine; this helper only
    touches CSF ids.
    """
    text = str(raw or "").strip()
    if not text:
        return UNMAPPED
    for prefix in ("NIST.CSF.", "NIST_CSF:", "NIST_CSF.", "csf_"):
        if text.upper().startswith(prefix.upper()) or text.startswith(prefix):
            text = text[len(prefix) :]
            break
    text = text.replace("_", ".").strip()
    # csf_PR_DS_02 → PR.DS.02 then restore hyphen form
    parts = text.split(".")
    if len(parts) >= 3 and parts[1].isalpha() and parts[2].isdigit():
        text = f"{parts[0]}.{parts[1]}-{parts[2].zfill(2)}"
    elif "-" in text:
        fam, num = text.split("-", 1)
        if num.isdigit():
            text = f"{fam}-{num.zfill(2)}"
    text = CSF11_TO_20.get(text, text)
    if text in CSF20_SUBCATEGORIES:
        return text
    return UNMAPPED


def _norm_sensor(raw: str) -> str:
    return str(raw or "").strip().lower().replace("_", "-")


def _cis_v8_token(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    for prefix in ("CIS.", "CIS-", "CIS_"):
        if text.upper().startswith(prefix):
            text = text[len(prefix) :]
            break
    if text.upper().startswith("V8-") or text.upper().startswith("V8."):
        text = text[3:]
    if text.startswith(CIS_V8_PREFIX):
        return text
    return f"{CIS_V8_PREFIX}{text}"


# Folded from frozen freedom45 control_map.py (sensor + title heuristics).
# CIS v8 tokens are internal-only. CPG 2.0 is stamped via WEAKNESS_CLASS_MAP.
ENV_EVAL_SENSOR_RULES: dict[str, dict[str, Any]] = {
    "sense-cleartext-http": {
        "weakness_class": "tls_crypto",
        "nist_800_53": ("SC-8", "SC-7"),
        "cis_v8_internal": ("3.3",),
        "csf20": "PR.DS-02",
    },
    "sense-cleartext-ftp": {
        "weakness_class": "exposure_network",
        "nist_800_53": ("SC-8",),
        "cis_v8_internal": ("3.3",),
        "csf20": "PR.DS-02",
    },
    "sense-http-https-redirect": {
        "weakness_class": "tls_crypto",
        "nist_800_53": ("SC-8", "SC-7"),
        "cis_v8_internal": ("3.3",),
        "csf20": "PR.DS-02",
    },
    "sense-http-headers": {
        "weakness_class": "config_benchmark",
        "nist_800_53": ("SC-7", "SC-18"),
        "cis_v8_internal": ("5.2",),
        "csf20": "PR.PS-01",
    },
    "sense-cookie-flags": {
        "weakness_class": "tls_crypto",
        "nist_800_53": ("SC-23", "AC-12"),
        "cis_v8_internal": ("5.2",),
        "csf20": "PR.DS-02",
    },
    "sense-cors": {
        "weakness_class": "exposure_access",
        "nist_800_53": ("AC-3", "SC-7"),
        "cis_v8_internal": ("5.2",),
        "csf20": "PR.AA-05",
    },
    "sense-ssh-banner": {
        "weakness_class": "exposure_network",
        "nist_800_53": ("CM-7", "AC-17"),
        "cis_v8_internal": ("5.2", "12.2"),
        "csf20": "PR.IR-01",
    },
    "sense-surface": {
        "weakness_class": "exposure_network",
        "nist_800_53": ("CM-7", "CM-8"),
        "cis_v8_internal": ("16.2",),
        "csf20": "ID.AM-01",
    },
    "sense-tls": {
        "weakness_class": "tls_crypto",
        "nist_800_53": ("SC-8", "SC-13"),
        "cis_v8_internal": ("3.3",),
        "csf20": "PR.DS-02",
    },
    "sense-tls-expiry": {
        "weakness_class": "tls_crypto",
        "nist_800_53": ("SC-8", "SC-17"),
        "cis_v8_internal": ("3.3",),
        "csf20": "PR.DS-02",
    },
    "sense-service-exposure": {
        "weakness_class": "exposure_network",
        "nist_800_53": ("SC-7", "CM-7"),
        "cis_v8_internal": ("16.2", "12.2"),
        "csf20": "PR.IR-01",
    },
    "sense-dir-listing": {
        "weakness_class": "config_benchmark",
        "nist_800_53": ("CM-6", "AC-3"),
        "cis_v8_internal": ("5.2",),
        "csf20": "PR.DS-01",
    },
    "sense-git-exposed": {
        "weakness_class": "config_benchmark",
        "nist_800_53": ("CM-7", "AC-3", "SI-12"),
        "cis_v8_internal": ("5.2",),
        "csf20": "PR.DS-01",
    },
    "sense-tech-disclosure": {
        "weakness_class": "config_benchmark",
        "nist_800_53": ("CM-7",),
        "cis_v8_internal": ("5.2",),
        "csf20": "PR.PS-01",
    },
    "sense-http-info": {
        "weakness_class": "config_benchmark",
        "nist_800_53": ("CM-7",),
        "cis_v8_internal": ("5.2",),
        "csf20": "PR.PS-01",
    },
    "sense-default-page": {
        "weakness_class": "config_benchmark",
        "nist_800_53": ("CM-2", "CM-6"),
        "cis_v8_internal": ("5.2",),
        "csf20": "PR.PS-01",
    },
    "sense-http-methods": {
        "weakness_class": "config_benchmark",
        "nist_800_53": ("CM-7", "AC-3"),
        "cis_v8_internal": ("5.2",),
        "csf20": "PR.PS-01",
    },
}

ENV_EVAL_HEURISTICS: list[tuple[re.Pattern[str], dict[str, Any]]] = [
    (
        re.compile(r"smbv?1|smb\s*v1", re.I),
        {
            "rule_id": "smb-v1",
            "weakness_class": "exposure_network",
            "nist_800_53": ("CM-7",),
            "cis_v8_internal": ("5.1",),
            "csf20": "PR.AA-01",
        },
    ),
    (
        re.compile(r"s3.*public|public.*bucket|block public access", re.I),
        {
            "rule_id": "s3-public",
            "weakness_class": "exposure_access",
            "nist_800_53": ("AC-3",),
            "cis_v8_internal": ("3.3",),
            "csf20": "PR.DS-01",
        },
    ),
    (
        re.compile(r"\brdp\b|(?<!\d)3389(?!\d)|remote desktop", re.I),
        {
            "rule_id": "rdp",
            "weakness_class": "exposure_network",
            "nist_800_53": ("AC-17",),
            "cis_v8_internal": ("12.2",),
            "csf20": "PR.IR-01",
        },
    ),
    (
        re.compile(r"\bredis\b|(?<!\d)6379(?!\d)", re.I),
        {
            "rule_id": "redis",
            "weakness_class": "exposure_access",
            "nist_800_53": ("SC-7",),
            "cis_v8_internal": ("16.2",),
            "csf20": "PR.IR-01",
        },
    ),
    (
        re.compile(r"\bmongodb\b|(?<!\d)27017(?!\d)", re.I),
        {
            "rule_id": "mongodb",
            "weakness_class": "exposure_network",
            "nist_800_53": ("SC-7",),
            "cis_v8_internal": ("16.2",),
            "csf20": "PR.IR-01",
        },
    ),
    (
        re.compile(r"\bmysql\b|(?<!\d)3306(?!\d)|\bpostgres(?:ql)?\b|(?<!\d)5432(?!\d)", re.I),
        {
            "rule_id": "sql-db",
            "weakness_class": "exposure_network",
            "nist_800_53": ("SC-7",),
            "cis_v8_internal": ("16.2",),
            "csf20": "PR.IR-01",
        },
    ),
    (
        re.compile(r"\belasticsearch\b|(?<!\d)9200(?!\d)|\bkibana\b", re.I),
        {
            "rule_id": "elastic",
            "weakness_class": "exposure_network",
            "nist_800_53": ("SC-7",),
            "cis_v8_internal": ("16.2",),
            "csf20": "PR.IR-01",
        },
    ),
    (
        re.compile(r"\bmemcached\b|(?<!\d)11211(?!\d)", re.I),
        {
            "rule_id": "memcached",
            "weakness_class": "exposure_network",
            "nist_800_53": ("SC-7",),
            "cis_v8_internal": ("16.2",),
            "csf20": "PR.IR-01",
        },
    ),
    (
        re.compile(r"\btelnet\b", re.I),
        {
            "rule_id": "telnet",
            "weakness_class": "exposure_network",
            "nist_800_53": ("SC-8",),
            "cis_v8_internal": ("3.3",),
            "csf20": "PR.DS-02",
        },
    ),
    (
        re.compile(r"\bvnc\b|(?<!\d)5900(?!\d)", re.I),
        {
            "rule_id": "vnc",
            "weakness_class": "exposure_network",
            "nist_800_53": ("AC-17",),
            "cis_v8_internal": ("12.2",),
            "csf20": "PR.IR-01",
        },
    ),
    (
        re.compile(r"weak cipher|sslv3|tlsv1\.0|tls 1\.0|heartbleed", re.I),
        {
            "rule_id": "weak-tls",
            "weakness_class": "tls_crypto",
            "nist_800_53": ("SC-8", "SC-13"),
            "cis_v8_internal": ("3.3",),
            "csf20": "PR.DS-02",
        },
    ),
    (
        re.compile(r"open.?relay|smtp captur|anonymous bind", re.I),
        {
            "rule_id": "insecure-service",
            "weakness_class": "exposure_access",
            "nist_800_53": ("AC-3",),
            "cis_v8_internal": ("5.2",),
            "csf20": "PR.AA-05",
        },
    ),
    (
        re.compile(r"world.?writ|0?777|permissions too open", re.I),
        {
            "rule_id": "perms",
            "weakness_class": "config_benchmark",
            "nist_800_53": ("AC-3",),
            "cis_v8_internal": ("5.2",),
            "csf20": "PR.AA-05",
        },
    ),
]


def _lookup_env_eval_rule(
    *,
    sensor: str = "",
    title: str = "",
    description: str = "",
    finding_type: str = "",
) -> dict[str, Any] | None:
    sid = _norm_sensor(sensor)
    if sid in ENV_EVAL_SENSOR_RULES:
        return {"sensor": sid, **ENV_EVAL_SENSOR_RULES[sid]}
    ftype = _norm_sensor(finding_type)
    if ftype.startswith("sense-") and ftype in ENV_EVAL_SENSOR_RULES:
        return {"sensor": ftype, **ENV_EVAL_SENSOR_RULES[ftype]}
    blob = " ".join(x for x in (title, description, finding_type, sensor) if x)
    for pat, hit in ENV_EVAL_HEURISTICS:
        if pat.search(blob):
            return dict(hit)
    return None


def _dedupe_ids(ids: Any) -> list[str]:
    out: list[str] = []
    for raw in ids or ():
        token = str(raw or "").strip()
        if token and token not in out:
            out.append(token)
    return out


def nist_800_53_ids(
    rec: Mapping[str, Any] | None = None,
    *,
    finding_type: str = "",
    sensor: str = "",
    title: str = "",
    description: str = "",
) -> list[str]:
    """NIST SP 800-53 Rev.5 IDs via the same path as POA&M Controls.

    Prefer ``TYPE_REMEDIATIONS`` (finding type / alias). sense-* rules are
    a fallback only when no type map hits. Title heuristics use word
    boundaries and do not match version numbers (WordPress, Apache 2.4.23).
    Returns an ordered de-duplicated list. CIS v8 is not returned
    (see ``cis_v8_internal_ids``).
    """
    from shared.finding_types import (
        TYPE_ALIASES,
        TYPE_REMEDIATIONS,
        finding_type as resolve_type,
        norm_type_key,
        type_remediation,
    )

    extra: dict[str, Any] = {}
    if rec and isinstance(rec.get("extra"), dict):
        extra = rec["extra"]  # type: ignore[assignment]
    sensor = sensor or str(extra.get("sensor") or extra.get("check_id") or extra.get("finding_id") or "")
    title = title or str((rec or {}).get("name") or "")
    description = description or str((rec or {}).get("description") or "")
    ftype = str(finding_type or "").strip()
    if rec and not ftype:
        mapped = type_remediation(dict(rec))
        if mapped and mapped.get("nist_800_53"):
            return _dedupe_ids(mapped.get("nist_800_53"))
        ftype = resolve_type(dict(rec)) or ""
    if not ftype:
        key = norm_type_key(sensor)
        ftype = TYPE_ALIASES.get(key) or TYPE_ALIASES.get(sensor) or ""
    if ftype and ftype in TYPE_REMEDIATIONS:
        return _dedupe_ids(TYPE_REMEDIATIONS[ftype].get("nist_800_53"))
    rule = ENV_EVAL_SENSOR_RULES.get(_norm_sensor(sensor))
    if rule:
        return _dedupe_ids(rule.get("nist_800_53"))
    blob = " ".join(x for x in (title, description) if x)
    if blob:
        for pat, hit in ENV_EVAL_HEURISTICS:
            if pat.search(blob):
                return _dedupe_ids(hit.get("nist_800_53"))
    return []


def cis_v8_internal_ids(
    *,
    sensor: str = "",
    title: str = "",
    description: str = "",
    finding_type: str = "",
) -> list[str]:
    """CIS Controls v8 tokens for extra.cis_v8_internal only — never client-facing."""
    rule = _lookup_env_eval_rule(
        sensor=sensor, title=title, description=description, finding_type=finding_type
    )
    if not rule:
        return []
    return [_cis_v8_token(str(x)) for x in (rule.get("cis_v8_internal") or ()) if x]


def classify_weakness_class(mapped: dict[str, Any], rec: dict[str, Any] | None = None) -> str:
    """Pick one class from control name, finding type, then light heuristics."""
    rec = rec or {}
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    sensor = _norm_sensor(str(extra.get("sensor") or extra.get("finding_id") or ""))
    if sensor in ENV_EVAL_SENSOR_RULES:
        return str(ENV_EVAL_SENSOR_RULES[sensor]["weakness_class"])
    ftype = str(
        mapped.get("finding_type")
        or extra.get("check_id")
        or extra.get("template_id")
        or extra.get("rule")
        or ""
    )
    if ftype in FINDING_TYPE_CLASS:
        return FINDING_TYPE_CLASS[ftype]
    for tid in redis_auth_template_ids(rec, mapped):
        if tid in FINDING_TYPE_CLASS:
            return FINDING_TYPE_CLASS[tid]
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
    # Freedom45 title heuristics only for env-eval / web-tls rows so DEMO
    # nmap/easm classifications stay byte-identical.
    env_eval = str(rec.get("source") or "") == "web-tls" or sensor.startswith("sense-")
    if env_eval:
        rule = _lookup_env_eval_rule(
            sensor=sensor,
            title=str(mapped.get("control_name") or rec.get("name") or ""),
            description=str(rec.get("description") or ""),
            finding_type=ftype,
        )
        if rule and rule.get("weakness_class"):
            return str(rule["weakness_class"])
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
