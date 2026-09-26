"""Finding → CISA CPG + NIST CSF stamps and a POA&M fix line.

Wizard-safe labels only (no colons). Honest: port-open is not a CVE.
"""

from __future__ import annotations

import os
import re
from typing import Any

from shared.finding_types import TYPE_WEAKNESS_NAME, finding_type, has_xss_signal, type_remediation
from shared.framework_class_map import (
    BLANKET_REGISTER_STAMPS,
    REDIS_AUTH_TEMPLATE_IDS,
    apply_class_mapping,
    csf_cpg_tag_set,
    redis_auth_template_ids,
)
from shared.schema import canon_severity
from shared.poam_fields import _CVE_RE

# CISA CPG 2.x-style stamps already used on the CISO wire (underscore, not colon).
# 2_W = known-weak / unnecessary service posture. 1_E = asset/exposure inventory.
CPG_WEAK_SERVICE = "cpg_2_W"
CPG_EXPOSURE = "cpg_1_E"

# NIST CSF 2.0 function stamps. Derived from control family/topic, never severity.
CSF_FUNCTIONS = ("govern", "identify", "protect", "detect", "respond", "recover")
CSF_STAMP = {
    "govern": "csf_GV",
    "identify": "csf_ID",
    "protect": "csf_PR",
    "detect": "csf_DE",
    "respond": "csf_RS",
    "recover": "csf_RC",
}
# Schema-valid fallback when no 800-53 / CIS / topic maps. Identify = found, not classified.
CSF_UNMAPPED_FUNCTION = "identify"
CSF_UNMAPPED_STAMP = "csf_unmapped"

# Honest CPG only from 800-53 ids that sit in that CPG's scope.
# 2_W = known-weak / unnecessary service posture. 1_E = asset/exposure inventory.
# Do not stamp either from severity. Drop CPG when no control maps.
N53_CPG = {
    "CM-7": CPG_WEAK_SERVICE,
    "SC-7": CPG_WEAK_SERVICE,
    "CM-8": CPG_EXPOSURE,
}
CVE_N53 = ["SI-2", "RA-5"]
CVE_CIS = ["cis_7_3", "cis_7_4", "cis_7_7"]
# Specific remediations where the CVE + package/title make a playbook derivable.
KNOWN_CVE_REMEDIATION: dict[str, dict[str, str]] = {
    "CVE-2024-3094": {
        "weakness_name": "xz-utils supply chain backdoor (CVE-2024-3094)",
        "control_name": "Remove the xz-utils/liblzma backdoor",
        "fix": (
            "Replace xz-utils/liblzma 5.6.0/5.6.1 (the backdoored builds) with a clean "
            "package (5.4.x or a later rebuilt release). Rotate credentials or keys that "
            "may have been exposed on hosts that ran the backdoored library. This is a "
            "supply-chain CVE, not a config-drift finding."
        ),
    },
    "CVE-2023-38545": {
        "weakness_name": "curl SOCKS heap overflow (CVE-2023-38545)",
        "control_name": "Patch curl SOCKS heap overflow",
        "fix": (
            "Upgrade curl/libcurl to 8.4.0 or later so CVE-2023-38545 (SOCKS5 heap "
            "buffer overflow) is not present."
        ),
    },
    "CVE-2023-44487": {
        "weakness_name": "HTTP/2 Rapid Reset (CVE-2023-44487)",
        "control_name": "Mitigate HTTP/2 Rapid Reset",
        "fix": (
            "Upgrade the HTTP/2 stack (nginx, Envoy, load balancer, or language runtime) "
            "to a release that limits or rejects Rapid Reset; disable HTTP/2 only if a "
            "patch is not available."
        ),
    },
    "CVE-2021-44228": {
        "weakness_name": "Log4Shell (CVE-2021-44228) is present",
        "control_name": "Patch Log4Shell-vulnerable services",
        "fix": (
            "Upgrade Log4j to a fixed release and block JNDI lookups. "
            "This is a dropped Nuclei finding, not a live scan."
        ),
    },
    "CVE-2014-0160": {
        "weakness_name": "Heartbleed (CVE-2014-0160) is present",
        "control_name": "Remediate Heartbleed-vulnerable TLS",
        "fix": (
            "Upgrade the TLS stack so Heartbleed is not offered. "
            "This is a dropped TLS export, not a live probe."
        ),
    },
}

# Scanner check titles that read as a pass when used as the weakness name.
CHECK_TITLE_FAILURE: dict[str, str] = {
    "root account mfa enabled": "Root account has no MFA",
    "s3 bucket prohibits public access": "S3 bucket allows public access",
    "rds instance not publicly accessible": "RDS instance is publicly accessible",
    "default security group restricts all traffic": "Default security group allows inbound traffic",
    "cloudtrail multi-region trail exists": "CloudTrail multi-region trail is missing",
    "iam user does not have administratoraccess": "IAM user has standing AdministratorAccess",
    "s3 bucket server-side encryption": "S3 bucket default encryption is not enabled",
    "legacy authentication protocols disabled": "Legacy authentication protocols are enabled",
    "external sharing restricted": "External sharing is not restricted",
}

# Action-oriented control names → failure statement for the weakness column.
CONTROL_WEAKNESS: dict[str, str] = {
    "Require MFA on the cloud root account": "Root account has no MFA",
    "Block public object-storage access": "S3 bucket allows public access",
    "Block public object-storage ACL and policy": "S3 bucket allows public access",
    "Remove standing IAM AdministratorAccess": "IAM user has standing AdministratorAccess",
    "Restrict security-group ingress from the internet": (
        "Security group allows inbound traffic from the internet"
    ),
    "Disable public accessibility on RDS": "RDS instance is publicly accessible",
    "Enable multi-region CloudTrail logging": "CloudTrail multi-region trail is missing",
    "Enable S3 default encryption (SSE-S3 or SSE-KMS)": (
        "S3 bucket default encryption is not enabled"
    ),
    "Enable encryption at rest on cloud storage": "Cloud storage is not encrypted at rest",
    "Enable EBS volume encryption": "EBS volume is not encrypted",
    "Require MFA on IAM users": "IAM user has no MFA",
    "Harden or restrict SMB file sharing": "SMB file sharing is exposed",
    "Restrict Windows admin shares": "Windows admin shares are reachable",
    "Disable Telnet; require encrypted remote admin": "Telnet is exposed",
    "Disable or lock down cleartext FTP": "Cleartext FTP is exposed",
    "Restrict RDP to approved paths": "RDP is exposed beyond approved paths",
    "Disable TLS 1.0": "TLS 1.0 is offered",
    "Harden TLS on the exposed service": "TLS on the exposed service is weak",
    "Remediate Heartbleed-vulnerable TLS": "Heartbleed-vulnerable TLS is offered",
    "Publish a DMARC policy": "DMARC policy is missing",
    "Tighten DMARC beyond p=none": "DMARC is monitor-only (p=none)",
    "Restrict SPF +all": "SPF allows +all",
    "Publish an SPF record": "SPF record is missing",
    "Tighten SPF softfail (~all)": "SPF is softfail-only (~all)",
    "Publish DKIM for the listed selector": "DKIM is missing for the listed selector",
    "Rotate and revoke exposed credentials": "Hardcoded or leaked credential is present",
    "Review privileged directory role": "Privileged directory role is assigned (unspecified)",
    "Remove standing Global Administrator assignment": "Standing Global Administrator is assigned",
    "Remove standing privileged role assignment": "Standing privileged role is assigned",
    "Disable legacy authentication protocols": "Legacy authentication protocols are enabled",
    "Restrict external sharing": "External sharing is not restricted",
    "Review SSH brute-force activity": "SSH brute-force activity was observed",
    "Enforce password policy": "Password policy is not enforced",
    "Raise domain minimum password length": "Domain minimum password length is below 8",
    "Restrict Account Operators membership": "Account Operators has standing members",
    "Restrict Print Operators membership": "Print Operators has standing members",
    "Restrict Server Operators membership": "Server Operators has standing members",
    "Restrict Schema Admins membership": "Schema Admins has standing members",
    "Restrict Enterprise Admins membership": "Enterprise Admins has standing members",
    "Restrict Administrators membership": "Builtin Administrators has standing members",
    "Review informational PingCastle finding": "PingCastle reported a zero-point finding",
    "Enforce Windows password history": "Password history is shorter than required",
    "Disable LM hash storage": "LM hashes are stored",
    "Enforce account lockout": "Account lockout is not enforced",
    "Enforce session lock": "Session lock after inactivity is not enforced",
    "Enable audit logging": "Audit logging is not enabled",
    "Enable malware protection": "Malware real-time protection is disabled",
    "Require encryption in transit": "Remote session encryption is not required",
    "Enable a host firewall": "Host firewall is disabled",
    "Enable full-disk encryption on the endpoint": "Disk encryption is disabled",
    "Require authentication and bind Redis": "Redis accepts unauthenticated access",
    "Require authentication on Redis": "Redis accepts unauthenticated access",
    "Bind Redis and enable protected-mode": "Redis is bound beyond localhost without protected-mode",
    "Rename or disable dangerous Redis commands": "Dangerous Redis commands are enabled",
    "End privileged HasSession logons": "Privileged principal has a HasSession on a workstation",
    "Run container images as a non-root USER": "Container image runs as root",
    "Block public EBS snapshot sharing": "EBS snapshot is shared publicly",
    "Disable weak SSH cryptographic algorithms": "SSH offers weak encryption or MAC algorithms",
    "Disable SSH root login": "SSH root login is enabled",
    "Disable SSH empty passwords": "SSH empty passwords are allowed",
    "Apply security updates": "Security updates are not applied",
    "Enable time synchronization": "Time synchronization is not enabled",
}

# Host-hardening control_keys (Lynis / OpenSCAP / HardeningKitty). Check
# titles are policy names; the weakness column must state the failure.
HARDENING_CONTROL_KEYS = frozenset(
    {
        "password_policy",
        "account_lockout",
        "session_lock",
        "audit_logging",
        "malware_protection",
        "encryption_in_transit",
        "host_firewall",
        "ssh_root_login",
        "ssh_empty_passwords",
        "patching",
        "time_sync",
    }
)

# SP 800-53 Rev. 5 family → CSF 2.0 function (NIST CSF 2.0 Informative References).
N53_FAMILY_CSF = {
    "AC": "protect",
    "AT": "protect",
    "AU": "detect",
    "CA": "identify",
    "CM": "protect",
    "CP": "recover",
    "IA": "protect",
    "IR": "respond",
    "MA": "protect",
    "MP": "protect",
    "PE": "protect",
    "PL": "govern",
    "PM": "govern",
    "PS": "protect",
    "PT": "govern",
    "RA": "identify",
    "SA": "protect",
    "SC": "protect",
    "SI": "detect",
    "SR": "govern",
}

# Control-id overrides where the family default is the wrong CSF function.
N53_CONTROL_CSF = {
    "CM-8": "identify",  # system component inventory
    "SI-2": "protect",  # flaw remediation
    "SI-3": "protect",  # malicious code protection
    "SI-7": "protect",  # software / firmware integrity
    "SI-8": "protect",  # spam protection
    "SI-10": "protect",  # information input validation
    "CA-7": "detect",  # continuous monitoring
}

# CIS Controls v8 (cis_<control>_<safeguard>) → CSF 2.0 function.
CIS_CONTROL_CSF = {
    1: "identify",
    2: "identify",
    3: "protect",
    4: "protect",
    5: "protect",
    6: "protect",
    7: "protect",
    8: "detect",
    9: "protect",
    10: "protect",
    11: "recover",
    12: "protect",
    13: "detect",
    14: "protect",
    15: "govern",
    16: "protect",
    17: "respond",
    18: "identify",
}

# Topic primary when the control name is more specific than family defaults.
TOPIC_CSF = {
    "Review deception-sensor telemetry": "detect",
    "Deploy endpoint detection and response": "detect",
    "Restore endpoint coverage": "detect",
    "Enable time synchronization": "detect",
    "Lock down sensitive perimeter hostnames": "protect",
    "Stop writes under container binary directories": "detect",
}


def _blob(rec: dict[str, Any]) -> str:
    """Narrative match blob. Never include ARN/asset names (demo-public-assets
    used to steal the S3 public-ACL playbook for encryption findings)."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    return " ".join(
        str(x or "")
        for x in (
            rec.get("name"),
            rec.get("description"),
            rec.get("category"),
            extra.get("port"),
            extra.get("service"),
            extra.get("rule"),
            extra.get("template_id"),
            extra.get("template-id"),
            extra.get("cve"),
            extra.get("check_id"),
            extra.get("id"),
            extra.get("control"),
            extra.get("edge"),
            extra.get("access"),
        )
    ).lower()


# Evidence-backed misconfig rules keyed by extra.check_id (shared/nmap_nse.py).
# nist_800_53 = SP 800-53 Rev. 5 control ids; cis = CIS Controls v8 safeguards.
# CSF function is the control's topic (protect), not a severity heuristic.
MISCONFIG_RULES: dict[str, dict[str, Any]] = {
    "nse-ftp-anon": {
        "name": "Disable anonymous FTP access",
        "fix": (
            "Set anonymous_enable=NO (vsftpd) or the equivalent, remove world-readable content from the "
            "anonymous root, and move file transfer to authenticated SFTP or FTPS. Restrict TCP/21 to the "
            "hosts that need it. Rescan with nmap ftp-anon to verify FTP code 530 for anonymous."
        ),
        "nist_800_53": ["AC-3", "AC-14", "CM-7", "IA-2"],
        "cis": ["cis_4_8", "cis_3_3"],
    },
    "nse-redis-noauth": {
        "name": "Require authentication on Redis",
        "fix": (
            "Enable Redis ACL users or requirepass with a strong secret, set protected-mode yes, bind Redis "
            "to localhost or a private interface only, and firewall TCP/6379. Deny dangerous commands with "
            "ACL rules (for example -@dangerous) instead of rename-command. Rescan with nmap redis-info to "
            "verify INFO is refused."
        ),
        "nist_800_53": ["IA-2", "AC-3", "CM-6", "CM-7", "SC-7"],
        "cis": ["cis_4_1", "cis_4_8", "cis_5_2"],
    },
    "nse-http-dirlist": {
        "name": "Disable web server directory listing",
        "fix": (
            "Turn off auto-indexing (nginx autoindex off; Apache Options -Indexes; IIS directoryBrowse "
            "enabled=false), remove backups and other sensitive files from the web root, and serve an "
            "explicit index or 403. Rescan with nmap http-enum to verify no 'directory listing' paths."
        ),
        "nist_800_53": ["CM-7", "CM-6", "AC-3"],
        "cis": ["cis_4_1", "cis_3_3"],
    },
    "nse-tls-deprecated-protocol": {
        "name": "Disable deprecated TLS protocols",
        "fix": (
            "Disable SSLv3, TLS 1.0, and TLS 1.1 and require TLS 1.2 or TLS 1.3 (e.g. nginx ssl_protocols "
            "TLSv1.2 TLSv1.3; Windows SCHANNEL registry or IIS Crypto). Confirm client compatibility first. "
            "Rescan with nmap ssl-enum-ciphers to verify only TLSv1.2/1.3 are listed."
        ),
        "nist_800_53": ["SC-8", "SC-8(1)", "SC-13", "CM-6"],
        "cis": ["cis_3_10", "cis_4_1"],
    },
    "nse-tls-weak-cipher": {
        "name": "Remove weak TLS cipher suites",
        "fix": (
            "Remove anonymous (aNULL), NULL, EXPORT, RC4, DES/3DES, and MD5 suites and prefer ECDHE with "
            "AES-GCM or CHACHA20-POLY1305 (e.g. Mozilla 'intermediate' profile). Rescan with nmap "
            "ssl-enum-ciphers and target least strength A."
        ),
        "nist_800_53": ["SC-8", "SC-8(1)", "SC-13", "CM-6"],
        "cis": ["cis_3_10", "cis_4_1"],
    },
    "nse-tls-self-signed": {
        "name": "Replace self-signed TLS certificate with a trusted CA certificate",
        "fix": (
            "Issue a certificate from the organization's internal CA or a public CA with the full chain, "
            "matching hostnames (SAN), and a tracked expiry. Self-signed certificates train users to click "
            "through warnings and allow undetected interception. Rescan with nmap ssl-cert to verify "
            "issuer != subject."
        ),
        "nist_800_53": ["SC-17", "SC-23", "SC-8"],
        "cis": ["cis_3_10"],
    },
    "nse-tls-weak-key": {
        "name": "Reissue TLS certificate with a strong key",
        "fix": (
            "Reissue the certificate with RSA 2048-bit or larger (3072 preferred) or ECDSA P-256, and revoke "
            "the old key. Rescan with nmap ssl-cert to verify Public Key bits >= 2048."
        ),
        "nist_800_53": ["SC-12", "SC-13", "SC-17"],
        "cis": ["cis_3_10"],
    },
    "nse-smb-signing-not-required": {
        "name": "Require SMB message signing",
        "fix": (
            "Require SMB signing: Windows GPO 'Microsoft network server: Digitally sign communications "
            "(always)' = Enabled (and client), or Samba 'server signing = mandatory'. Disable SMBv1 and "
            "restrict TCP/445 to required hosts. Unsigned SMB enables NTLM relay. Rescan with nmap "
            "smb2-security-mode to verify 'enabled and required'."
        ),
        "nist_800_53": ["SC-8", "SC-8(1)", "SC-23", "CM-6"],
        "cis": ["cis_4_1", "cis_3_10"],
    },
    "nse-smb-guest": {
        "name": "Disable SMB guest access",
        "fix": (
            "Set 'map to guest = Never' and remove 'guest ok' shares (Samba) or disable the Guest account and "
            "insecure guest logons (Windows GPO). Require authenticated, least-privilege share access. "
            "Rescan with nmap smb-security-mode to verify account_used is not guest."
        ),
        "nist_800_53": ["AC-3", "AC-14", "IA-2", "AC-6"],
        "cis": ["cis_3_3", "cis_4_7"],
    },
    "nse-db-empty-password": {
        "name": "Set strong credentials on database accounts",
        "fix": (
            "Set a strong unique password or socket/auth-plugin-only login for root and every account with an "
            "empty password, remove anonymous users and the test database (mysql_secure_installation), set "
            "bind-address to localhost or a private interface, and firewall TCP/3306. Rotate any secrets the "
            "database held. Rescan with nmap mysql-empty-password to verify."
        ),
        "nist_800_53": ["IA-5", "IA-5(1)", "IA-2", "AC-2", "CM-6"],
        "cis": ["cis_4_7", "cis_5_2"],
    },
    "nse-default-credentials": {
        "name": "Remove vendor default credentials",
        "fix": (
            "Change or disable the vendor default account immediately, set a strong unique password, restrict "
            "the admin interface to the management network or VPN, and enable MFA where supported. Review "
            "logs for prior use of the default login. Rescan with nmap http-default-accounts to verify."
        ),
        "nist_800_53": ["IA-5", "IA-5(1)", "AC-2", "CM-6", "AC-17"],
        "cis": ["cis_4_7", "cis_5_2"],
    },
}

# Named controls → SP 800-53 Rev. 5 ids (family/topic drives CSF, not severity).
CONTROL_800_53: dict[str, list[str]] = {
    "Restrict Windows admin shares": ["AC-3", "AC-6", "CM-7"],
    "Harden or restrict SMB file sharing": ["CM-7", "SC-7"],
    "Disable Telnet; require encrypted remote admin": ["CM-7", "SC-8", "AC-17"],
    "Disable or lock down cleartext FTP": ["CM-7", "SC-8"],
    "Restrict RDP to approved paths": ["AC-17", "SC-7"],
    "Disable TLS 1.0": ["SC-8", "SC-8(1)", "SC-13"],
    "Harden TLS on the exposed service": ["SC-8", "SC-8(1)", "SC-13"],
    "Remediate Heartbleed-vulnerable TLS": ["SI-2", "SC-8", "RA-5"],
    "Review deception-sensor telemetry": ["SI-4", "AU-2"],
    "Publish a DMARC policy": ["SI-8", "SC-8"],
    "Tighten DMARC beyond p=none": ["SI-8", "SC-8"],
    "Restrict SPF +all": ["SI-8", "SC-8"],
    "Publish an SPF record": ["SI-8", "SC-8"],
    "Tighten SPF softfail (~all)": ["SI-8", "SC-8"],
    "Publish DKIM for the listed selector": ["SI-8", "SC-8"],
    "Block public object-storage access": ["AC-3", "AC-6", "SC-7"],
    "Block public object-storage ACL and policy": ["AC-3", "AC-6", "SC-7"],
    "Remove standing IAM AdministratorAccess": ["AC-2", "AC-6"],
    "Require MFA on the cloud root account": ["IA-2", "IA-2(1)"],
    "Restrict security-group ingress from the internet": ["SC-7", "AC-17"],
    "Disable public accessibility on RDS": ["SC-7", "AC-3"],
    "Enable encryption at rest on cloud storage": ["SC-28", "SC-13"],
    "Enable S3 default encryption (SSE-S3 or SSE-KMS)": ["SC-28", "SC-13"],
    "Enable EBS volume encryption": ["SC-28", "SC-13"],
    "Require MFA on IAM users": ["IA-2", "IA-2(1)"],
    "Enable multi-region CloudTrail logging": ["AU-2", "AU-3", "AU-12"],
    "Stop SQL injection in the application": ["SI-10", "SA-11"],
    "Stop OS command injection": ["SI-10", "SA-11"],
    "Patch Log4Shell-vulnerable services": ["SI-2", "RA-5"],
    "Stop remote code execution": ["SI-2", "SI-10"],
    "Stop cross-site scripting": ["SI-10", "SA-11"],
    "Remove non-DC DCSync rights": ["AC-6", "AC-2"],
    "Remove non-DC DCSync / replication rights": ["AC-6", "AC-2", "AC-3"],
    "Remove standing local-admin (AdminTo) rights": ["AC-6", "AC-2"],
    "Disable SMB null / anonymous sessions": ["AC-14", "AC-3", "IA-2"],
    "Remove GenericAll on privileged objects": ["AC-6", "AC-2"],
    "Require Kerberos preauthentication": ["IA-2", "AC-2"],
    "Harden kerberoastable service accounts": ["IA-5", "AC-6"],
    "Remove unconstrained Kerberos delegation": ["AC-6", "IA-2"],
    "Restrict Backup Operators membership": ["AC-6", "AC-2"],
    "Restrict Account Operators membership": ["AC-6", "AC-2"],
    "Restrict Print Operators membership": ["AC-6", "AC-2"],
    "Restrict Server Operators membership": ["AC-6", "AC-2"],
    "Restrict Schema Admins membership": ["AC-6", "AC-2"],
    "Restrict Enterprise Admins membership": ["AC-6", "AC-2"],
    "Restrict Administrators membership": ["AC-6", "AC-2"],
    "Raise domain minimum password length": ["IA-5"],
    "Restrict Domain Admins membership": ["AC-6", "AC-2"],
    "Enable full-disk encryption": ["SC-28", "MP-5"],
    "Deploy endpoint detection and response": ["SI-4"],
    "Enroll the endpoint in MDM": ["CM-2", "CM-6"],
    "Review and expire stale guest accounts": ["AC-2"],
    "Restore endpoint coverage": ["SI-4"],
    "Rotate and revoke exposed credentials": ["IA-5", "SI-4"],
    "Require phishing-resistant MFA for privileged users": ["IA-2", "IA-2(1)"],
    "Require MFA for privileged SaaS admins": ["IA-2", "IA-2(1)"],
    "Remove standing Global Administrator assignment": ["AC-2", "AC-6", "AC-5"],
    "Review privileged directory role": ["AC-2", "AC-6"],
    "Enforce Windows password history": ["IA-5"],
    "Disable LM hash storage": ["IA-5", "CM-6"],
    "Enable a host firewall": ["SC-7", "CM-7"],
    "Disable SSH root login": ["IA-2", "AC-6"],
    "End privileged HasSession logons": ["AC-6", "AC-2"],
    "Run container images as a non-root USER": ["AC-6", "CM-7"],
    "Block public EBS snapshot sharing": ["AC-3", "SC-7"],
    "Disable weak SSH cryptographic algorithms": ["CM-6", "SC-8(1)", "SC-13"],
    "Disable SSH empty passwords": ["IA-5", "IA-2"],
    "Apply security updates": ["SI-2", "CM-6", "RA-5"],
    "Enable time synchronization": ["AU-8"],
    "Enforce password policy": ["IA-5"],
    "Enforce account lockout": ["AC-7"],
    "Enforce session lock": ["AC-11"],
    "Enable audit logging": ["AU-2", "AU-12"],
    "Enable malware protection": ["SI-3"],
    "Require encryption in transit": ["SC-8"],
    "Deny privileged Kubernetes containers": ["AC-6", "CM-7"],
    "Disable anonymous Kubernetes API access": ["AC-3", "IA-2"],
    "Block Kubernetes privilege escalation": ["AC-6"],
    "Avoid hostNetwork on Kubernetes workloads": ["SC-7", "CM-7"],
    "Stop writes under container binary directories": ["SI-7", "CM-6", "AC-3"],
    "Restrict exposed admin interfaces": ["AC-17", "SC-7"],
    "Lock down sensitive perimeter hostnames": ["SC-7"],
    "Remove standing privileged role assignment": ["AC-2", "AC-6"],
    "Disable legacy authentication protocols": ["IA-2", "IA-5"],
    "Restrict external sharing": ["AC-3", "AC-6"],
    "Review SSH brute-force activity": ["SI-4", "AC-17", "SC-7"],
}

# Backward-compatible alias used by older tests/docs.
EXPOSURE_800_53 = CONTROL_800_53

CONTROL_CIS: dict[str, list[str]] = {
    "Publish a DMARC policy": ["cis_9_5"],
    "Tighten DMARC beyond p=none": ["cis_9_5"],
    "Restrict SPF +all": ["cis_9_5"],
    "Publish an SPF record": ["cis_9_5"],
    "Tighten SPF softfail (~all)": ["cis_9_5"],
    "Publish DKIM for the listed selector": ["cis_9_5"],
    "Deploy endpoint detection and response": ["cis_13_2"],
    "Restore endpoint coverage": ["cis_13_2"],
    "Enable time synchronization": ["cis_8_4"],
    "Lock down sensitive perimeter hostnames": ["cis_1_1"],
    "Rotate and revoke exposed credentials": ["cis_3_3"],
}


MISCONFIG_WEAKNESS: dict[str, str] = {
    "nse-ftp-anon": "Anonymous FTP login is allowed",
    "nse-redis-noauth": "Redis accepts unauthenticated access",
    "nse-http-dirlist": "Web server directory listing is enabled",
    "nse-tls-deprecated-protocol": "Deprecated TLS protocols are offered",
    "nse-tls-weak-cipher": "Weak TLS cipher suites are offered",
    "nse-tls-self-signed": "TLS certificate is self-signed",
    "nse-tls-weak-key": "TLS certificate uses a weak key",
    "nse-smb-signing-not-required": "SMB message signing is not required",
    "nse-smb-guest": "SMB guest access is allowed",
    "nse-db-empty-password": "Database account has an empty password",
    "nse-default-credentials": "Vendor default credentials are accepted",
}


def _n53_tokens(ids: list[str]) -> list[str]:
    return [f"nist80053_{cid}" for cid in ids]


def _n53_base(cid: str) -> str:
    return str(cid or "").split("(", 1)[0].strip().upper()


def _n53_family(cid: str) -> str:
    return _n53_base(cid).split("-", 1)[0]


def _cis_control_num(token: str) -> int | None:
    raw = str(token or "").strip().lower().replace("-", "_")
    if not raw.startswith("cis_"):
        return None
    parts = raw.split("_")
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return None


def _csf_from_n53(cid: str) -> str | None:
    base = _n53_base(cid)
    if base in N53_CONTROL_CSF:
        return N53_CONTROL_CSF[base]
    return N53_FAMILY_CSF.get(_n53_family(cid))


def _csf_from_cis(token: str) -> str | None:
    num = _cis_control_num(token)
    if num is None:
        return None
    return CIS_CONTROL_CSF.get(num)


def _collect_csf_functions(n53: list[str], cis: list[str]) -> tuple[set[str], dict[str, int]]:
    counts: dict[str, int] = {fn: 0 for fn in CSF_FUNCTIONS}
    found: set[str] = set()
    for cid in n53:
        fn = _csf_from_n53(cid)
        if fn in counts:
            found.add(fn)
            counts[fn] += 1
    for token in cis:
        fn = _csf_from_cis(token)
        if fn in counts:
            found.add(fn)
            counts[fn] += 1
    return found, counts


def _primary_csf(found: set[str], counts: dict[str, int], topic: str | None) -> str:
    """One stamp for the CISO wire. Topic wins; else most votes, then CSF 2.0 order."""
    if topic in found:
        return topic
    ranked = sorted(found, key=lambda fn: (-counts.get(fn, 0), CSF_FUNCTIONS.index(fn)))
    return ranked[0]


def _lookup_control_ids(control_name: str) -> tuple[list[str], list[str]]:
    if control_name in CONTROL_800_53:
        return list(CONTROL_800_53[control_name]), list(CONTROL_CIS.get(control_name) or [])
    if control_name.startswith("Reduce unnecessary network exposure"):
        return ["CM-7", "SC-7"], []
    return [], []


def _derive_cpg(n53: list[str]) -> list[str]:
    """CPG from 800-53 only. Empty when no control honestly maps to a CPG."""
    out: list[str] = []
    for cid in n53:
        tag = N53_CPG.get(_n53_base(cid))
        if tag and tag not in out:
            out.append(tag)
    return out


def _stamp_csf(mapped: dict[str, Any], rec: dict[str, Any] | None = None) -> dict[str, Any]:
    """Attach CSF 2.0 function (PR #128) + class subcategory/CPG. Never from severity."""
    n53 = list(mapped.get("nist_800_53") or [])
    cis = list(mapped.get("cis") or [])
    name = str(mapped.get("control_name") or "")
    found, counts = _collect_csf_functions(n53, cis)
    topic = TOPIC_CSF.get(name)
    if topic:
        found.add(topic)
        counts[topic] = counts.get(topic, 0) + 1
    if found:
        primary = _primary_csf(found, counts, topic)
        unmapped = False
    else:
        primary = CSF_UNMAPPED_FUNCTION
        found = {primary}
        unmapped = True
    stamps: list[str] = []
    for fn in CSF_FUNCTIONS:
        if fn in found:
            stamps.append(CSF_STAMP[fn])
            stamps.append(f"csf_{fn}")
    if unmapped:
        stamps.append(CSF_UNMAPPED_STAMP)
    mapped["csf"] = stamps
    mapped["csf_function"] = primary
    mapped["csf_functions"] = [fn for fn in CSF_FUNCTIONS if fn in found]
    # CPG + CSF subcategory come from the weakness-class table, not a
    # CM-7/SC-7 catch-all and not a function-level csf_PR default.
    apply_class_mapping(mapped, rec)
    return mapped


_PKG_LINE_RE = re.compile(r"(?im)(?:^|\b)package:\s*([A-Za-z0-9._+-]+)")


def _pkg_from_rec(rec: dict[str, Any]) -> str:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    pkg = str(extra.get("pkg") or extra.get("package") or "").strip()
    if pkg:
        return pkg
    blob = f"{rec.get('name') or ''}\n{rec.get('description') or ''}"
    match = _PKG_LINE_RE.search(blob)
    return str(match.group(1) or "").strip() if match else ""


def _is_caa_finding(rec: dict[str, Any]) -> bool:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    sid = str(extra.get("id") or "").strip().lower().replace("-", "_")
    if sid == "dns_caarecord":
        return True
    blob = f"{rec.get('name') or ''} {rec.get('description') or ''}".lower()
    return "caa" in blob and ("dns" in blob or "record" in blob)


_HEADER_MSG_TOKS = (
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
    "referrer-policy",
)


def _is_missing_web_header_text(text: str) -> bool:
    blob = str(text or "").lower()
    return any(tok in blob for tok in _HEADER_MSG_TOKS)


def _is_package_cve(rec: dict[str, Any]) -> bool:
    """Trivy/SARIF/package CVE rows are patch findings, not TLS posture."""
    if not _cves_in(rec):
        return False
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    if extra.get("pkg") or extra.get("package"):
        return True
    labels = {str(x).lower() for x in (rec.get("labels") or [])}
    if labels & {"trivy", "sarif"}:
        return True
    return bool(_pkg_from_rec(rec))


def _cves_in(rec: dict[str, Any]) -> list[str]:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    found: list[str] = []
    for raw in (extra.get("cve"), rec.get("ref_id"), rec.get("name"), rec.get("description")):
        for match in _CVE_RE.findall(str(raw or "")):
            up = match.upper()
            if up not in found:
                found.append(up)
    return found


def _is_vuln_finding(rec: dict[str, Any]) -> bool:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    cat = str(rec.get("category") or "").lower()
    if cat == "vulnerability":
        return True
    if _cves_in(rec):
        return True
    cve = str(extra.get("cve") or "")
    return bool(_CVE_RE.search(cve))


def _is_ssh_weak_crypto(rec: dict[str, Any]) -> bool:
    """Greenbone/Nessus SSH weak encryption or MAC — config, not a package CVE."""
    blob = _blob(rec)
    if "ssh" not in blob:
        return False
    return bool(
        re.search(r"weak\s+encryption\s+algorithms", blob)
        or re.search(r"weak\s+mac\s+algorithms", blob)
    )


def _ssh_weak_crypto_playbook(rec: dict[str, Any]) -> dict[str, Any]:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    solution = str(extra.get("solution") or "").strip()
    blob = _blob(rec)
    if re.search(r"weak\s+mac\s+algorithms", blob):
        default = "Disable the weak MAC algorithms."
        weakness = "SSH offers weak MAC algorithms"
    else:
        default = "Disable the weak encryption algorithms."
        weakness = "SSH offers weak encryption algorithms"
    fix = solution if solution else default
    if fix and not fix.endswith("."):
        fix += "."
    return {
        "control_name": "Disable weak SSH cryptographic algorithms",
        "recommended_fix": (
            f"{fix} This is a dropped scanner finding, not a live SSH probe."
        ),
        "nist_800_53": ["CM-6", "SC-8(1)", "SC-13"],
        "cis": [],
        "generic": False,
        "finding_type": "ssh_weak_crypto",
        "weakness_name": weakness,
        "include_poam": canon_severity(rec.get("severity")) != "info",
    }


def _vuln_playbook(rec: dict[str, Any]) -> dict[str, Any]:
    if _is_ssh_weak_crypto(rec):
        return _ssh_weak_crypto_playbook(rec)
    cves = _cves_in(rec)
    cve = cves[0] if cves else ""
    pkg = _pkg_from_rec(rec)
    known = KNOWN_CVE_REMEDIATION.get(cve) or {}
    raw_name = str(rec.get("name") or "").strip()
    safari_m = re.search(r"safari\s*<\s*([0-9.]+)", raw_name, re.I)
    if known:
        weakness = known["weakness_name"]
        control = known["control_name"]
        fix = known["fix"]
    elif safari_m:
        ver = safari_m.group(1)
        weakness = raw_name if raw_name and not _looks_like_pass_title(raw_name) else (
            f"Safari is older than {ver}"
        )
        control = f"Upgrade to Safari {ver} or later"
        fix = (
            f"Upgrade to Safari {ver} or later so the reported Safari "
            "vulnerabilities are not present. This is a vulnerability "
            "finding, not a config-drift playbook."
        )
    elif _is_caa_finding(rec):
        weakness = raw_name if raw_name and not _looks_like_pass_title(raw_name) else (
            "CAA DNS record is missing or invalid"
        )
        control = "Apply vulnerability remediation"
        fix = (
            "Publish a CAA DNS record that names the approved certificate issuers "
            "and an iodef contact. This is a dropped testssl export, not a live DNS query."
        )
    elif cve and pkg:
        weakness = raw_name if raw_name and not _looks_like_pass_title(raw_name) else (
            f"{cve} is present in {pkg}"
        )
        control = f"Patch {pkg} for {cve}"
        fix = (
            f"Upgrade {pkg} to a release that remediates {cve}. "
            "This is a vulnerability finding, not a config-drift playbook."
        )
    elif cve:
        weakness = raw_name if raw_name and not _looks_like_pass_title(raw_name) else (
            f"{cve} is present"
        )
        control = f"Patch {cve}"
        fix = (
            f"Upgrade the affected component to a release that remediates {cve}. "
            "This is a vulnerability finding, not a config-drift playbook."
        )
    else:
        weakness = raw_name or "Unpatched vulnerability is present"
        control = "Apply vulnerability remediation"
        fix = (
            "Identify the affected package or service and upgrade or isolate it "
            "so the reported vulnerability is not present. "
            "This is a vulnerability finding, not a config-drift playbook."
        )
    return {
        "control_name": control,
        "recommended_fix": fix,
        "nist_800_53": list(CVE_N53),
        "cis": list(CVE_CIS),
        "generic": False,
        "finding_type": cve.lower() or "vulnerability",
        "weakness_name": weakness,
        "include_poam": canon_severity(rec.get("severity")) != "info",
    }


def _looks_like_pass_title(name: str) -> bool:
    key = re.sub(r"[^a-z0-9]+", " ", str(name or "").lower()).strip()
    if key in CHECK_TITLE_FAILURE:
        return True
    compact = key.replace(" ", "")
    if compact in {k.replace(" ", "") for k in CHECK_TITLE_FAILURE}:
        return True
    needles = (
        " mfa enabled",
        "prohibits public",
        "not publicly accessible",
        "restricts all traffic",
        "trail exists",
        "does not have administrator",
    )
    return any(n in f" {key} " or n in key for n in needles)


def weakness_name_for(rec: dict[str, Any], mapped: dict[str, Any]) -> str:
    """Weakness column must state the failure, not the pass-style check title."""
    raw = str(rec.get("name") or "").strip()
    key = raw.lower()
    compact = re.sub(r"[^a-z0-9]+", "", key)
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    control = str(mapped.get("control_name") or extra.get("control_name") or "")
    scanner_id = str(extra.get("id") or extra.get("risk_id") or "").strip()
    check_id = str(extra.get("check_id") or extra.get("id") or "").strip().lower()
    if check_id == "alf" or "application firewall" in key:
        return "macOS ALF is disabled"
    typed_name = str(mapped.get("weakness_name") or "").strip()
    if typed_name and scanner_id:
        raw_l = raw.lower()
        sid_l = scanner_id.lower()
        if raw_l == sid_l or raw_l.endswith(sid_l) or f" {sid_l}" in f" {raw_l}":
            return typed_name
    for title, failure in CHECK_TITLE_FAILURE.items():
        if key == title or compact == title.replace(" ", ""):
            return failure
    # HK / Lynis / oscap check titles are policy names ("EnableFirewall",
    # "Length of password history maintained"), not the failure.
    hardening = str(extra.get("control_key") or "") in HARDENING_CONTROL_KEYS
    if hardening or key.startswith("hardeningkitty"):
        if control in CONTROL_WEAKNESS:
            return CONTROL_WEAKNESS[control]
    if raw and _looks_like_pass_title(raw):
        pass
    elif raw and not hardening:
        return raw
    explicit = str(mapped.get("weakness_name") or "").strip()
    if explicit:
        return explicit
    ftype = str(mapped.get("finding_type") or "")
    if ftype in TYPE_WEAKNESS_NAME:
        return TYPE_WEAKNESS_NAME[ftype]
    check = str(extra.get("check_id") or "")
    if check in MISCONFIG_WEAKNESS:
        return MISCONFIG_WEAKNESS[check]
    if control in CONTROL_WEAKNESS:
        return CONTROL_WEAKNESS[control]
    return explicit or control or raw or str(rec.get("ref_id") or "finding")


def _typed_map(rec: dict[str, Any], typed: dict[str, Any]) -> dict[str, Any]:
    """Type-specific remediations; CSF/CPG from 800-53, not severity."""
    sev = canon_severity(rec.get("severity"))
    n53 = list(typed.get("nist_800_53") or [])
    mapped = _stamp_csf(
        {
            "control_name": typed["control_name"],
            "recommended_fix": typed["recommended_fix"],
            "cpg": [],
            "include_poam": sev != "info",
            "nist_800_53": n53,
            "cis": list(typed.get("cis") or []),
            "generic": bool(typed.get("generic")),
            "finding_type": typed.get("finding_type") or "",
            "weakness_name": str(typed.get("weakness_name") or ""),
            "key_medium": bool(typed.get("key_medium")),
            "source": str(typed.get("source") or ""),
        },
        rec,
    )
    mapped["weakness_name"] = weakness_name_for(rec, mapped)
    return mapped


def _canon_exclude_reason(reason: str) -> str:
    """One spelling: not_a_weakness. Accept the old Custodian NOT_A_WEAKNESS."""
    raw = str(reason or "").strip()
    if raw.upper() == "NOT_A_WEAKNESS":
        return "not_a_weakness"
    return raw


def _is_custodian_not_a_weakness(rec: dict[str, Any]) -> bool:
    """Custodian cost/ops only. nmap extra.not_a_weakness stays on the nmap path."""
    if str(rec.get("source") or "") != "cloud-prowler":
        return False
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    return _canon_exclude_reason(
        extra.get("exclude_reason") or extra.get("poam_exclude") or ""
    ) == "not_a_weakness"


def map_finding(rec: dict[str, Any]) -> dict[str, Any]:
    """Return stamps + a recommended fix. Does not invent CVEs or due dates."""
    mapped = _map_finding_body(rec)
    if rec.get("kind") == "excluded":
        mapped = dict(mapped)
        mapped["include_poam"] = False
    if is_telemetry_finding(rec) and not keep_telemetry_on_plan(rec):
        mapped = dict(mapped)
        mapped["include_poam"] = False
    return mapped


def _is_unauth_redis(rec: dict[str, Any]) -> bool:
    """Nuclei exposed-redis / nmap redis-info — auth gap, not a patch finding."""
    if any(tid in REDIS_AUTH_TEMPLATE_IDS for tid in redis_auth_template_ids(rec)):
        return True
    text = _blob(rec)
    if "redis" not in text:
        return False
    return any(
        tok in text
        for tok in (
            "without auth",
            "unauthenticated",
            "noauth",
            "no auth",
            "requirepass",
            "accessible without authentication",
            "unprotected by password",
        )
    )


def _is_needs_review(rec: dict[str, Any]) -> bool:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    if extra.get("needs_review") is True:
        return True
    return str(extra.get("classification") or "").strip().lower() == "needs-review"


def _map_finding_body(rec: dict[str, Any]) -> dict[str, Any]:
    """Return stamps + a recommended fix. Does not invent CVEs or due dates."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    if _is_needs_review(rec):
        n_hit = extra.get("affected_count")
        try:
            n_hit_i = int(n_hit)
        except (TypeError, ValueError):
            n_hit_i = 0
        count_bit = (
            f" Rolled up {n_hit_i} affected resources into this row."
            if n_hit_i
            else ""
        )
        return _stamp_csf(
            {
                "control_name": "Needs review (unclassified Cloud Custodian policy)",
                "recommended_fix": (
                    "This Cloud Custodian policy matched no known security or "
                    "cost/ops classification. It stays on the POA&M as "
                    "needs-review until an operator maps it. Do not drop it."
                    + ((" " + count_bit) if count_bit else "")
                ),
                "cpg": [],
                "include_poam": True,
                "generic": False,
                "finding_type": "needs_review",
                "weakness_name": "Needs review (unclassified Cloud Custodian policy)",
                "key_medium": True,
            },
            rec,
        )
    if _is_custodian_not_a_weakness(rec):
        return _stamp_csf(
            {
                "control_name": "Cost or operations signal (not a control weakness)",
                "recommended_fix": (
                    "This Cloud Custodian match is a cost/ops policy, "
                    "not a security control failure. Do not open a High POA&M. "
                    "Map the policy to a control if it should be treated as a finding."
                ),
                "cpg": [],
                "include_poam": False,
                "generic": False,
                "finding_type": "not_a_weakness",
                "weakness_name": "Not a weakness (cost/ops Custodian policy)",
            },
            rec,
        )
    check = str(extra.get("check_id") or "")
    # Nuclei extra.rule/template_id is exposed-redis; extra.check_id may be a
    # CVE or matcher id. Alias + every extra id must still reach this class.
    if _is_unauth_redis(rec) or finding_type(rec) in REDIS_AUTH_TEMPLATE_IDS:
        check = "nse-redis-noauth"
    rule = MISCONFIG_RULES.get(check)
    if rule:
        mapped = _stamp_csf(
            {
                "control_name": rule["name"],
                "recommended_fix": rule["fix"],
                "cpg": [],
                "include_poam": True,
                "nist_800_53": list(rule["nist_800_53"]),
                "cis": list(rule["cis"]),
                "generic": False,
                "finding_type": check,
                "weakness_name": MISCONFIG_WEAKNESS.get(check, ""),
            },
            rec,
        )
        mapped["weakness_name"] = weakness_name_for(rec, mapped)
        return mapped
    typed = type_remediation(rec)
    if typed and not typed.get("generic"):
        return _typed_map(rec, typed)
    if _is_package_cve(rec):
        play = _vuln_playbook(rec)
        mapped = _stamp_csf(
            {
                **play,
                "cpg": [],
            },
            rec,
        )
        mapped["weakness_name"] = weakness_name_for(rec, mapped)
        return mapped
    if typed and typed.get("generic") and _is_vuln_finding(rec):
        play = _vuln_playbook(rec)
        mapped = _stamp_csf(
            {
                **play,
                "cpg": [],
            },
            rec,
        )
        mapped["weakness_name"] = weakness_name_for(rec, mapped)
        return mapped
    if typed and not (
        typed.get("generic")
        and str(extra.get("control_key") or "") in HARDENING_CONTROL_KEYS
    ):
        return _typed_map(rec, typed)
    mapped = _map_finding_legacy(rec)
    if mapped.get("generic") and _is_vuln_finding(rec):
        play = _vuln_playbook(rec)
        mapped.update(play)
    n53, cis = _lookup_control_ids(mapped["control_name"])
    if mapped.get("nist_800_53"):
        n53 = list(mapped["nist_800_53"])
    extra_n53 = extra.get("nist_800_53") or []
    if isinstance(extra_n53, list):
        for cid in extra_n53:
            if cid and cid not in n53:
                n53.append(str(cid))
    mapped["nist_800_53"] = n53
    # Never copy extra.cis_v8_internal (INTERNAL-ONLY) into client outputs.
    if mapped.get("cis"):
        cis = list(mapped["cis"])
    mapped["cis"] = cis
    mapped.setdefault("generic", False)
    mapped.setdefault("finding_type", "")
    mapped = _stamp_csf(mapped, rec)
    mapped["weakness_name"] = weakness_name_for(rec, mapped)
    return mapped


_PINGCASTLE_RULES: dict[str, dict[str, str]] = {
    "A-MinPwdLen": {
        "name": "Raise domain minimum password length",
        "fix": (
            "Set the domain minimum password length per NIST SP 800-63B-4 "
            "(15 characters password-only, or 8 with MFA) or at least 8 as "
            "PingCastle A-MinPwdLen scores. File-drop only, not a live AD call."
        ),
    },
    "A-Krbtgt": {
        "name": "Rotate the krbtgt password twice",
        "fix": (
            "Reset the krbtgt password twice, at least 10 hours apart, so old "
            "KRBTGT keys die. This is PingCastle A-Krbtgt from a file-drop, "
            "not a live DC call."
        ),
    },
    "P-Delegated": {
        "name": "Mark privileged accounts sensitive and cannot be delegated",
        "fix": (
            "Set 'Account is sensitive and cannot be delegated' on admins, or "
            "add them to Protected Users. P-Delegated is that flag, not the "
            "P-UnconstrainedDelegation RiskId."
        ),
    },
    "P-UnconstrainedDelegation": {
        "name": "Remove unconstrained Kerberos delegation",
        "fix": (
            "Disable unconstrained delegation; prefer constrained or resource-based. "
            "This is PingCastle P-UnconstrainedDelegation from a file-drop."
        ),
    },
    "S-NoPreAuth": {
        "name": "Require Kerberos preauthentication",
        "fix": (
            "Uncheck 'Do not require Kerberos preauthentication' on the account. "
            "This is PingCastle S-NoPreAuth from a file-drop, not a live AD call."
        ),
    },
    "S-NoPreAuthAdmin": {
        "name": "Require Kerberos preauthentication on admin accounts",
        "fix": (
            "Uncheck 'Do not require Kerberos preauthentication' on privileged "
            "accounts. This is PingCastle S-NoPreAuthAdmin from a file-drop."
        ),
    },
    "A-DsHeuristicsLDAPSecurity": {
        "name": "Set dSHeuristics LDAP security (CVE-2021-42291)",
        "fix": (
            "Set dSHeuristics characters 28 (LDAPAddAuthZVerifications) and 29 "
            "(LDAPOwnerModify) to 1 for Enforcement after watching events "
            "3044-3056 in audit mode. The 10th character must be 1 and the 20th "
            "character must be 2 per KB5008383 (CVE-2021-42291). File-drop only."
        ),
    },
    "A-ZeroPoint": {
        "name": "Review informational PingCastle finding",
        "fix": (
            "No score was assigned. Confirm the rationale is still true, then "
            "close or accept. This is a PingCastle file-drop finding, not a live AD call."
        ),
    },
    "P-BackupOperators": {
        "name": "Restrict Backup Operators membership",
        "fix": (
            "Remove standing Backup Operators members; the group can dump SAM. "
            "This is a PingCastle file-drop finding, not a live AD call."
        ),
    },
    "P-AccountOperators": {
        "name": "Restrict Account Operators membership",
        "fix": (
            "Empty Account Operators; members can create privileged accounts. "
            "This is a PingCastle file-drop finding, not a live AD call."
        ),
    },
    "P-PrintOperators": {
        "name": "Restrict Print Operators membership",
        "fix": (
            "Empty Print Operators; members can load a driver and seize SYSTEM. "
            "This is a PingCastle file-drop finding, not a live AD call."
        ),
    },
    "P-ServerOperators": {
        "name": "Restrict Server Operators membership",
        "fix": (
            "Empty Server Operators; members can take control of DCs. "
            "This is a PingCastle file-drop finding, not a live AD call."
        ),
    },
    "P-SchemaAdmins": {
        "name": "Restrict Schema Admins membership",
        "fix": (
            "Keep Schema Admins empty except during a documented schema update. "
            "This is a PingCastle file-drop finding, not a live AD call."
        ),
    },
    "P-EnterpriseAdmins": {
        "name": "Restrict Enterprise Admins membership",
        "fix": (
            "Minimize Enterprise Admins to break-glass accounts only. "
            "This is a PingCastle file-drop finding, not a live AD call."
        ),
    },
    "P-DomainAdmins": {
        "name": "Restrict Domain Admins membership",
        "fix": (
            "Minimize Domain Admins; no standing workstation logons. "
            "This is a PingCastle file-drop finding, not a live AD call."
        ),
    },
    "P-Administrators": {
        "name": "Restrict Administrators membership",
        "fix": (
            "Minimize builtin Administrators; prefer Domain Admins only on DCs. "
            "This is a PingCastle file-drop finding, not a live AD call."
        ),
    },
    "S-PwdNeverExpires": {
        "name": "Disable password-never-expires on accounts",
        "fix": (
            "Clear 'Password never expires' on the flagged accounts, roll those "
            "passwords now, use a gMSA for service accounts, and enroll them in "
            "the domain password policy. This is PingCastle S-PwdNeverExpires "
            "from a file-drop, not a live AD call."
        ),
    },
    "S-PwdNotRequired": {
        "name": "Require passwords on every account",
        "fix": (
            "Clear PASSWD_NOTREQD so every account must have a password. "
            "This is PingCastle S-PwdNotRequired from a file-drop, not a live AD call."
        ),
    },
    "A-LAPS-Not-Installed": {
        "name": "Deploy LAPS for local administrator passwords",
        "fix": (
            "Install Windows LAPS (or legacy LAPS) and store unique local-admin "
            "passwords in the directory. This is PingCastle A-LAPS-Not-Installed "
            "from a file-drop, not a live AD call."
        ),
    },
    "A-LAPS-Joined-Computers": {
        "name": "Change the computer object owner after a LAPS join",
        "fix": (
            "The account that joined the computer can still read its LAPS "
            "password. Change the computer object's owner (for example to "
            "Domain Admins) and remove that creator's write-owner, DACL write, "
            "and All extended rights. This is PingCastle A-LAPS-Joined-Computers "
            "from a file-drop, not a live AD call."
        ),
    },
    "P-DNSAdmin": {
        "name": "Restrict DnsAdmins membership",
        "fix": (
            "Empty DnsAdmins except break-glass. CVE-2021-40469 (October 2021) "
            "fixes the DLL-load path; PingCastle has scored this informative "
            "since 2.10.1. File-drop only, not a live AD call."
        ),
    },
    "S-SIDHistory": {
        "name": "Remove SID History from trusted accounts",
        "fix": (
            "Re-permission ACLs and security descriptors to the new SID before "
            "removing SID History. This is PingCastle S-SIDHistory from a "
            "file-drop, not a live AD call."
        ),
    },
    "T-SIDHistoryDangerous": {
        "name": "Remove SID History from trusted accounts",
        "fix": (
            "Re-permission ACLs and security descriptors to the new SID before "
            "removing dangerous SID History (privileged SIDs from another domain). "
            "This is PingCastle T-SIDHistoryDangerous from a file-drop, not a live AD call."
        ),
    },
    "T-SIDHistorySameDomain": {
        "name": "Remove SID History from trusted accounts",
        "fix": (
            "Same-domain SID History is not a leftover from migration — "
            "investigate the principal for compromise, then re-permission "
            "descriptors to the new SID before removing SID History. This is "
            "PingCastle T-SIDHistorySameDomain from a file-drop, not a live AD call."
        ),
    },
    "T-SIDHistoryUnknownDomain": {
        "name": "Remove SID History from trusted accounts",
        "fix": (
            "Re-permission ACLs and security descriptors to the new SID before "
            "removing SID History that points at an unknown domain. This is "
            "PingCastle T-SIDHistoryUnknownDomain from a file-drop, not a live AD call."
        ),
    },
    "T-SIDFiltering": {
        "name": "Enable SID filtering on trusts",
        "fix": (
            "On a domain trust run netdom /quarantine:yes. On a forest trust "
            "run netdom /enablesidhistory:no — never /quarantine on a forest "
            "trust. This is PingCastle T-SIDFiltering from a file-drop, not a live AD call."
        ),
    },
    "S-DesEnabled": {
        "name": "Disable DES encryption types for Kerberos",
        "fix": (
            "Clear 'Use Kerberos DES encryption types' on the flagged accounts. "
            "This is PingCastle S-DesEnabled from a file-drop, not a live AD call."
        ),
    },
}


def _pingcastle_playbook(rec: dict[str, Any]) -> dict[str, str] | None:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    rid = str(extra.get("risk_id") or "").strip()
    return _PINGCASTLE_RULES.get(rid)


# Specific group names first so Schema/Enterprise/DnsAdmins do not fall through
# to the builtin Administrators playbook.
_HIGHVALUE_GROUP_RULES: tuple[tuple[str, str], ...] = (
    ("schema admin", "P-SchemaAdmins"),
    ("enterprise admin", "P-EnterpriseAdmins"),
    ("domain admin", "P-DomainAdmins"),
    ("backup operator", "P-BackupOperators"),
    ("account operator", "P-AccountOperators"),
    ("print operator", "P-PrintOperators"),
    ("server operator", "P-ServerOperators"),
    ("dnsadmin", "P-DNSAdmin"),
    ("dns admin", "P-DNSAdmin"),
)


def _is_highvalue_identity(rec: dict[str, Any]) -> bool:
    name = str(rec.get("name") or "").strip().lower()
    if name == "high-value identity":
        return True
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    if extra.get("risk_id"):
        return False
    blob = _blob(rec)
    return "high-value" in blob or "highvalue" in blob.replace("-", "")


def _highvalue_identity_playbook(rec: dict[str, Any]) -> dict[str, str]:
    """Paraphrase only. Do not reuse Restrict-* control names (those stamp n53)."""
    assets = " ".join(str(a) for a in (rec.get("assets") or []))
    blob = f"{assets} {rec.get('name') or ''} {rec.get('description') or ''}".lower()
    fix = (
        "Confirm the high-value principal still needs standing privilege and "
        "remove unused members. This is a BloodHound/PingCastle file-drop "
        "finding, not a live AD call."
    )
    for needle, rid in _HIGHVALUE_GROUP_RULES:
        if needle in blob:
            play = _PINGCASTLE_RULES.get(rid)
            if play:
                fix = play["fix"]
                break
    else:
        if re.search(r"(?<![a-z])administrators?(?![a-z])", blob):
            play = _PINGCASTLE_RULES.get("P-Administrators")
            if play:
                fix = play["fix"]
    return {
        "name": "Review high-value directory group membership",
        "fix": fix,
    }


def _map_finding_legacy(rec: dict[str, Any]) -> dict[str, Any]:
    """Return stamps + a recommended fix. Does not invent CVEs or due dates."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    port = str(extra.get("port") or "")
    text = _blob(rec)
    sev = canon_severity(rec.get("severity"))
    key_medium = False
    generic = False
    source = str(rec.get("source") or "").lower()
    category = str(rec.get("category") or "").lower()
    if (
        source in {"honeypot", "honeypot-sensor"}
        or category in {"honeypot", "deception-sensor"}
        or extra.get("honesty") == "deception-sensor"
        or "deception-sensor" in text
    ):
        return {
            "control_name": "Review deception-sensor telemetry",
            "recommended_fix": (
                "Treat this as deception-sensor evidence / an agent-behavior signal. "
                "A honeypot stage hit is not a full control failure and does not mean "
                "the network is compromised. Review the trap session; do not open a "
                "compromise incident from the stage hit alone."
            ),
            "cpg": [],
            "include_poam": False,
            "generic": False,
            "finding_type": "honeypot",
            "weakness_name": "Deception-sensor hit (not a client weakness)",
        }

    if (
        "admin$" in text
        or "c$" in text
        or "ipc$" in text
        or "admin share" in text
        or "administrative share" in text
    ):
        name = "Restrict Windows admin shares"
        fix = (
            "Disable or ACL C$/ADMIN$/IPC$ so they are not reachable off the admin network. "
            "Restrict TCP/445 (SMB) to the admin network. "
            "Confirm SMBv1 is disabled. This is a share-exposure finding, not a dialect or CVE."
        )
        key_medium = True
    elif port == "445" or "smb" in text or "microsoft-ds" in text:
        name = "Harden or restrict SMB file sharing"
        fix = (
            "Restrict TCP/445 (SMB) to required admin or file-share hosts. "
            "Confirm SMBv1 is disabled on the endpoint. "
            "This finding is an open-port exposure, not a dialect or CVE."
        )
        key_medium = True
    elif port == "23" or "telnet" in text:
        name = "Disable Telnet; require encrypted remote admin"
        fix = "Disable Telnet (TCP/23). Use SSH or an approved jump host. Do not leave cleartext remote admin on the network."
    elif port == "21" or "ftp exposed" in text:
        name = "Disable or lock down cleartext FTP"
        fix = "Disable FTP (TCP/21) or replace with SFTP/FTPS. Restrict any remaining listener to a management VLAN."
    elif port == "3389" or re.search(r"(?<![a-z0-9_])rdp(?![a-z0-9_])", text):
        name = "Restrict RDP to approved paths"
        fix = "Restrict TCP/3389 (RDP) to VPN/jump hosts. Require NLA. This is an exposure finding, not a specific RDP CVE."
        key_medium = True
    elif "dmarc missing" in text or "dmarc_missing" in text.replace(" ", "").replace("-", "_"):
        name = "Publish a DMARC policy"
        fix = (
            "Publish a _dmarc TXT record (start at p=none, move to quarantine/reject). "
            "This is a Seen DNS control-gap candidate, not mailbox compromise and not a breach."
        )
        key_medium = True
    elif "dmarc p=none" in text or "dmarc_monitor_only" in text.replace(" ", "").replace("-", "_"):
        name = "Tighten DMARC beyond p=none"
        fix = (
            "Move DMARC from p=none to quarantine or reject after reviewing aggregate reports. "
            "A TXT record is Seen, not Shown mailbox protection."
        )
    elif "spf +all" in text or "spf_pass_all" in text.replace(" ", "").replace("-", "_"):
        name = "Restrict SPF +all"
        fix = (
            "Replace SPF +all with -all (or a scoped include). "
            "This is a Seen DNS control-gap candidate, not a breach."
        )
        key_medium = True
    elif "spf missing" in text or "spf_missing" in text.replace(" ", "").replace("-", "_"):
        name = "Publish an SPF record"
        fix = (
            "Publish a v=spf1 TXT that names approved senders and ends in -all. "
            "This is a Seen DNS control-gap candidate, not a breach."
        )
        key_medium = True
    elif "spf softfail" in text or "spf_softfail_only" in text.replace(" ", "").replace("-", "_"):
        name = "Tighten SPF softfail (~all)"
        fix = (
            "Move SPF from ~all to -all once senders are inventoried. "
            "Softfail-only is a hygiene gap, not a breach."
        )
    elif "dkim" in text and ("missing" in text or "selector" in text):
        name = "Publish DKIM for the listed selector"
        fix = (
            "Publish v=DKIM1 at <selector>._domainkey for in-SCOPE domains. "
            "This is a Seen DNS control-gap candidate, not a breach."
        )
        key_medium = True
    elif "heartbleed" in text:
        name = "Remediate Heartbleed-vulnerable TLS"
        fix = (
            "Upgrade the TLS stack so Heartbleed is not offered, then regenerate "
            "private keys and reissue certificates (CISA TA14-098A). "
            "This is a dropped TLS export, not a live probe."
        )
    elif "tls 1.0" in text or "tlsv1.0" in text or "tls1 offered" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Disable TLS 1.0"
        fix = (
            "Disable TLS 1.0 and require TLS 1.2 or newer. "
            "This is a dropped TLS export, not a live probe."
        )
    elif _is_missing_web_header_text(text):
        header_fix = (
            "Add the flagged response header (HSTS, X-Frame-Options, "
            "X-Content-Type-Options, or Content-Security-Policy) on the public "
            "listener. This is a Nikto file-drop finding, not a TLS cipher change."
        )
        if (
            port == "443"
            or re.search(r"(?<![a-z0-9_])tls(?![a-z0-9_])", text)
            or re.search(r"(?<![a-z0-9_])ssl(?![a-z0-9_])", text)
            or re.search(r"(?<![a-z0-9_])certificate(?![a-z0-9_])", text)
        ):
            name = "Harden TLS on the exposed service"
            key_medium = True
        else:
            name = f"Reduce unnecessary network exposure ({rec.get('name') or port or 'service'})"
        fix = header_fix
    elif not _is_package_cve(rec) and (
        port == "443"
        or re.search(r"(?<![a-z0-9_])tls(?![a-z0-9_])", text)
        or re.search(r"(?<![a-z0-9_])ssl(?![a-z0-9_])", text)
        or re.search(r"(?<![a-z0-9_])certificate(?![a-z0-9_])", text)
    ):
        name = "Harden TLS on the exposed service"
        if "wildcard" in text or str(extra.get("id") or "").lower() == "cert_trust_wildcard":
            fix = (
                "Replace the shared wildcard certificate with hostname-scoped "
                "certificates. This is a dropped testssl export, not a live TLS probe."
            )
        else:
            fix = (
                "Require TLS 1.2 or newer, disable weak ciphers, and use a valid certificate. "
                "This is a posture finding, not a specific TLS CVE."
            )
        key_medium = True
    elif (
        (
            "public access" in text
            or "public-access" in text
            or "allusers" in text
            or "public acl" in text
            or "publicly" in text
            or "public list" in text
            or "public get" in text
            or "public read" in text
            or "allows public" in text
        )
        and ("s3" in text or "bucket" in text)
    ):
        name = "Block public object-storage access"
        fix = "Remove public ACL/policy on the bucket. Keep the object private unless a documented exception exists."
    elif "administratoraccess" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Remove standing IAM AdministratorAccess"
        fix = (
            "Detach AdministratorAccess from users. Prefer a role or break-glass group. "
            "This is an IAM posture finding, not a CVE."
        )
    elif "root" in text and "mfa" in text:
        name = "Require MFA on the cloud root account"
        fix = (
            "Enable MFA on the root account. Prefer a hardware key. "
            "This is an identity posture finding, not a CVE."
        )
    elif ("0.0.0.0/0" in text or "0.0.0.0 / 0" in text) and any(
        tok in text
        for tok in ("security group", "security_group", "securitygroup", "ingress", "sg-")
    ):
        name = "Restrict security-group ingress from the internet"
        fix = (
            "Remove 0.0.0.0/0 ingress. Allow only required CIDRs or prefix lists. "
            "This is a network-exposure finding, not a CVE."
        )
    elif "rds" in text and ("public" in text or "publiclyaccessible" in text.replace(" ", "").replace("_", "").replace("-", "")):
        name = "Disable public accessibility on RDS"
        fix = (
            "Set PubliclyAccessible=false and place the instance in private subnets. "
            "This is an exposure finding, not a CVE."
        )
    elif (
        "s3" in text or "bucket" in text or "ebs" in text
    ) and (
        "unencrypted" in text
        or "not encrypted" in text
        or "encryption not" in text
        or "without default encryption" in text
        or "default_encryption" in text
        or "defaultencryption" in text.replace(" ", "").replace("_", "").replace("-", "")
    ):
        name = "Enable encryption at rest on cloud storage"
        fix = (
            "Enable default encryption (SSE-S3/SSE-KMS or EBS encryption). "
            "This is a posture finding, not a CVE."
        )
    elif "sql-injection" in text or "sqli" in text or "sql injection" in text:
        name = "Stop SQL injection in the application"
        fix = (
            "Parameterize queries. Do not concatenate untrusted input into SQL. "
            "This is a SAST/SARIF finding, not a CVE."
        )
    elif "command-injection" in text or "os command" in text or "shell injection" in text:
        name = "Stop OS command injection"
        fix = (
            "Do not pass untrusted input to a shell. Use argv arrays or a safe API. "
            "This is a SAST/SARIF finding, not a CVE."
        )
    elif "log4j" in text or "log4shell" in text or "jndi" in text:
        name = "Patch Log4Shell-vulnerable services"
        fix = (
            "Upgrade Log4j to a fixed release and block JNDI lookups. "
            "This is a dropped Nuclei finding, not a live scan."
        )
    elif (
        (
            "nuclei" in {str(x).lower() for x in (rec.get("labels") or [])}
            or bool(extra.get("template_id"))
        )
        and (
            "remote code execution" in text
            or text.endswith(" rce")
            or " rce " in f" {text} "
        )
    ):
        name = "Stop remote code execution"
        fix = (
            "Patch or isolate the service that Nuclei flagged as RCE. "
            "This is a dropped Nuclei finding, not a live scan."
        )
    elif has_xss_signal(rec):
        name = "Stop cross-site scripting"
        fix = (
            "Encode untrusted output for the HTML context. Avoid raw innerHTML. "
            "This is a SAST/SARIF finding, not a CVE."
        )
    elif "dcsync" in text:
        name = "Remove non-DC DCSync rights"
        fix = (
            "Revoke Replicating Directory Changes / All from non-DC principals. "
            "This is a BloodHound file-drop finding, not a live AD call."
        )
    elif "genericall" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Remove GenericAll on privileged objects"
        fix = (
            "Remove GenericAll ACE from the principal. "
            "This is a BloodHound file-drop finding, not a live AD call."
        )
    elif "as-rep" in text or "asrep" in text.replace("-", "").replace(" ", "") or "does not require kerberos preauth" in text:
        name = "Require Kerberos preauthentication"
        fix = (
            "Uncheck 'Do not require Kerberos preauthentication'. "
            "This is a BloodHound file-drop finding, not a live AD call."
        )
    elif "roastable" in text or "kerberoast" in text:
        name = "Harden kerberoastable service accounts"
        fix = (
            "Use a gMSA or rotate the SPN password; avoid user accounts with SPNs. "
            "This is a BloodHound file-drop finding, not a live AD call."
        )
    elif "unconstrained delegation" in text:
        name = "Remove unconstrained Kerberos delegation"
        fix = (
            "Disable unconstrained delegation; prefer constrained or resource-based. "
            "This is a BloodHound file-drop finding, not a live AD call."
        )
    elif "backup operators" in text:
        name = "Restrict Backup Operators membership"
        fix = (
            "Remove standing Backup Operators members. "
            "This is a BloodHound/PingCastle file-drop finding, not a live AD call."
        )
    elif "domain admins" in text:
        name = "Restrict Domain Admins membership"
        fix = (
            "Remove standing Domain Admins members. "
            "This is a dropped identity export, not a live directory call."
        )
    elif (
        "disk encryption" in text
        or "filevault" in text
        or "bitlocker" in text
        or "encryption compliance" in text
    ):
        name = "Enable full-disk encryption"
        fix = (
            "Enable FileVault, BitLocker, or LUKS on the endpoint. "
            "This is a Fleet/Intune/Jamf file-drop finding, not a live agent query."
        )
    elif "missing edr" in text or ("edr" in text and "missing" in text):
        name = "Deploy endpoint detection and response"
        fix = (
            "Install the approved EDR/antivirus agent and confirm it reports healthy. "
            "This is an MDM file-drop assessment finding, not a live agent query."
        )
    elif "mdm" in text and (
        "enroll" in text or "unenroll" in text or "enrollment off" in text or "not enrolled" in text
    ):
        name = "Enroll the endpoint in MDM"
        fix = (
            "Enroll the host in the approved MDM. "
            "This is a Fleet/Intune/Jamf file-drop finding, not a live agent query."
        )
    elif "stale guest" in text or ("guest" in text and "stale" in text):
        name = "Review and expire stale guest accounts"
        fix = (
            "Disable or remove guest accounts with stale last-sign-in. "
            "This is an IdP file-drop assessment finding, not a Graph/Okta API call."
        )
    elif "coverage gap" in text or "agent disconnected" in text:
        name = "Restore endpoint coverage"
        fix = (
            "Reconnect the agent or enroll the host in Fleet/Wazuh. "
            "This is a coverage finding from a dropped export, not a live query."
        )
    elif (
        category == "secrets"
        or "gitleaks" in text
        or "trufflehog" in text
        or (source == "code-secrets" and ("secret" in text or "api key" in text or "hardcoded" in text or "credential" in text))
        or ("hardcoded" in text and ("password" in text or "credential" in text or "secret" in text))
    ):
        name = "Rotate and revoke exposed credentials"
        fix = "Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material."
    elif "phishing-resistant" in text and "mfa" in text:
        name = "Require phishing-resistant MFA for privileged users"
        fix = (
            "Require FIDO2 or another phishing-resistant method for privileged Entra roles. "
            "This is a Maester posture finding from a dropped export, not a Graph API call."
        )
    elif (
        ("okta" in text and "mfa" in text)
        or "privileged users require mfa" in text
        or "admin mfa" in text
        or "mfa enrollment" in text
        or "mfa not enforced" in text
        or "mfa not registered" in text
        or "mfa gap" in text
        or "privileged mfa" in text
    ):
        name = "Require MFA for privileged SaaS admins"
        fix = (
            "Enforce MFA on privileged Okta/Entra/Google roles from the dropped ScubaGear or Okta export. "
            "This is not a Graph or Okta API call."
        )
    elif "global administrator" in text and (
        "permanently" in text
        or "pim" in text
        or "standing" in text
        or "via graph" in text
    ):
        name = "Remove standing Global Administrator assignment"
        fix = (
            "Use PIM eligible assignments instead of standing Global Administrator. "
            "This is a dropped Scuba/Graph export finding, not a Graph API call."
        )
    elif "privileged role" in text:
        name = "Review privileged directory role"
        fix = (
            "Confirm the admin role from the dropped IdP export. "
            "isAdmin means any admin role, not Global Administrator. "
            "This is not a Graph or Okta API call."
        )
    elif "standing privileged" in text or (
        "standing" in text and "role" in text and "administrator" not in text
    ):
        name = "Remove standing privileged role assignment"
        fix = (
            "Replace the standing privileged role with an eligible/JIT assignment. "
            "This is a dropped IdP export finding, not a live directory call."
        )
    elif "legacy authentication" in text or "legacy auth" in text:
        name = "Disable legacy authentication protocols"
        fix = (
            "Disable IMAP/SMTP basic auth and other legacy authentication protocols. "
            "This is a dropped Scuba/IdP export finding, not a Graph API call."
        )
    elif "external sharing" in text:
        name = "Restrict external sharing"
        fix = (
            "Disable Anyone links and restrict external sharing to approved domains. "
            "This is a dropped Scuba/SharePoint export finding, not a live API call."
        )
    elif extra.get("control_key") == "account_lockout" or "lockout" in text:
        name = "Enforce account lockout"
        fix = (
            "Set an account lockout threshold and duration. "
            "This is a HardeningKitty MS Security Baseline posture finding, not a CVE."
        )
    elif extra.get("control_key") == "session_lock" or "inactivity limit" in text:
        name = "Enforce session lock"
        fix = (
            "Lock the session after inactivity. "
            "This is a HardeningKitty MS Security Baseline posture finding, not a CVE."
        )
    elif extra.get("control_key") == "audit_logging" or "advanced audit" in text:
        name = "Enable audit logging"
        fix = (
            "Turn on advanced audit policy so security events are recorded. "
            "This is a HardeningKitty MS Security Baseline posture finding, not a CVE."
        )
    elif extra.get("control_key") == "malware_protection" or "real-time protection" in text:
        name = "Enable malware protection"
        fix = (
            "Keep Microsoft Defender real-time protection enabled. "
            "This is a HardeningKitty MS Security Baseline posture finding, not a CVE."
        )
    elif extra.get("control_key") == "encryption_in_transit" or (
        "encryption level" in text and ("rdp" in text or "client connection" in text)
    ):
        name = "Require encryption in transit"
        fix = (
            "Require encrypted remote sessions. "
            "This is a HardeningKitty MS Security Baseline posture finding, not a CVE."
        )
    elif "brute force" in text:
        name = "Review SSH brute-force activity"
        fix = (
            "Confirm the attempts failed, restrict SSH to the admin network or VPN, "
            "and keep host alerting on repeated input_userauth failures. "
            "This is a Wazuh file-drop alert, not a live SSH probe."
        )
    elif "password history" in text:
        name = "Enforce Windows password history"
        fix = (
            "Set password history to the recommended length. "
            "This is a HardeningKitty MS Security Baseline posture finding, not a CVE."
        )
    elif (
        "lm hash" in text
        or "lan manager hash" in text
        or "lmhash" in text.replace(" ", "").replace("_", "").replace("-", "")
    ):
        name = "Disable LM hash storage"
        fix = (
            "Disable storage of LAN Manager hashes. Prefer NTLMv2. "
            "This is a HardeningKitty MS Security Baseline posture finding, not a CVE."
        )
    elif extra.get("control_key") == "password_policy":
        name = "Enforce password policy"
        fix = (
            "Set a minimum password length and aging policy. "
            "This is a HardeningKitty MS Security Baseline posture finding, not a CVE."
        )
    elif "firewall" in text and (
        "no firewall" in text
        or "not installed" in text
        or "inactive" in text
        or "disabled" in text
    ):
        name = "Enable a host firewall"
        fix = (
            "Install and enable a host firewall. This is a Lynis/OpenSCAP posture finding, not a CVE."
        )
    elif "permitrootlogin" in text.replace(" ", "").replace("_", "").replace("-", "") or (
        "ssh" in text and "root login" in text
    ):
        name = "Disable SSH root login"
        fix = (
            "Set PermitRootLogin no and use a named sudo account. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        )
    elif extra.get("control_key") == "ssh_empty_passwords" or (
        "empty password" in text and ("ssh" in text or "permitemptypasswords" in text.replace(" ", ""))
    ) or "permitemptypasswords" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Disable SSH empty passwords"
        fix = (
            "Set PermitEmptyPasswords no. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        )
    elif extra.get("control_key") == "patching" or "security patch" in text or (
        "package update" in text
    ):
        name = "Apply security updates"
        fix = (
            "Install outstanding security patches. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        )
    elif extra.get("control_key") == "time_sync" or "chrony" in text or (
        re.search(r"(?<![a-z0-9_])ntp(?:d)?(?![a-z0-9_])", text)
        and (
            "enable" in text
            or "synchron" in text
            or re.search(r"(?<![a-z0-9_])time(?![a-z0-9_])", text)
        )
    ):
        name = "Enable time synchronization"
        fix = (
            "Run chrony or ntpd so audit timestamps stay trustworthy. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        )
    elif extra.get("control_key") == "host_firewall":
        name = "Enable a host firewall"
        fix = (
            "Install and enable a host firewall. This is a Lynis/OpenSCAP "
            "posture finding, not a CVE."
        )
    elif "privileged" in text and (
        "container" in text or "pod" in text or "admission" in text
    ):
        name = "Deny privileged Kubernetes containers"
        fix = (
            "Do not run privileged=true. This is a Kubescape/kube-bench finding "
            "from a dropped export, not a live kubectl call."
        )
    elif "anonymous" in text and (
        "auth" in text or "api" in text or "kubernetes" in text
    ):
        name = "Disable anonymous Kubernetes API access"
        fix = (
            "Set --anonymous-auth=false. This is a dropped CIS/kube-bench finding, "
            "not a live cluster call."
        )
    elif "privilege escalation" in text or "allowprivilegeescalation" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Block Kubernetes privilege escalation"
        fix = (
            "Set allowPrivilegeEscalation=false. This is a dropped Kubescape finding, "
            "not a live kubectl call."
        )
    elif "hostnetwork" in text.replace(" ", "").replace("_", "").replace("-", "") or "host network" in text:
        name = "Avoid hostNetwork on Kubernetes workloads"
        fix = (
            "Unset hostNetwork unless the workload is a documented system DaemonSet. "
            "This is a dropped Kubescape finding, not a live cluster call."
        )
    elif (
        "admin interface" in text
        or "admin login" in text
        or "admin panel" in text
        or "admin console" in text
    ):
        name = "Restrict exposed admin interfaces"
        fix = (
            "Move the admin UI off the public perimeter or put it behind SSO/VPN. "
            "This is a dropped httpx/EASM finding, not a live HTTP probe."
        )
    elif "sensitive external hostname" in text or "public perimeter" in text:
        name = "Lock down sensitive perimeter hostnames"
        fix = (
            "Do not publish vpn/admin/dev hostnames on the open internet. "
            "This is a dropped EASM finding, not a live DNS/HTTP probe."
        )
    elif extra.get("risk_id"):
        play = _pingcastle_playbook(rec)
        if play:
            name = play["name"]
            fix = play["fix"]
        else:
            name = f"Remediate PingCastle {extra.get('risk_id') or rec.get('name')}"
            fix = (
                f"Apply the PingCastle {extra.get('risk_id') or 'risk'} remediation "
                "from the healthcheck rationale. This is a PingCastle file-drop finding, "
                "not a live AD call."
            )
    elif _is_highvalue_identity(rec):
        play = _highvalue_identity_playbook(rec)
        name = play["name"]
        fix = play["fix"]
    elif str(rec.get("category") or "") == "exposure":
        name = f"Reduce unnecessary network exposure ({rec.get('name') or port or 'service'})"
        fix = (
            f"Limit the exposed service on {', '.join(rec.get('assets') or []) or 'the asset'} "
            "to required networks. Confirm the listener is still needed."
        )
        key_medium = port in {"3389", "445"}
    else:
        ref = rec.get("ref_id") or rec.get("name") or "unknown"
        extra_id = str(extra.get("check_id") or extra.get("control") or extra.get("id") or ref)
        name = f"Review and remediate per control {extra_id}"
        fix = (
            f"Review and remediate per control {extra_id}. "
            "Generic fallback — no type-specific playbook is mapped for this finding type."
        )
        generic = True

    include = sev != "info"
    return {
        "control_name": name,
        "recommended_fix": fix,
        "cpg": [],
        "include_poam": include,
        "generic": generic,
        "finding_type": "",
        "key_medium": key_medium,
    }


# Named reasons for POA&M include/exclude. Every weakness gets exactly one.
# Default plan puts Lows and non-key Mediums on the POA&M. Infos and honeypot
# stay off. Aggregated SIEM alerts are telemetry (excluded) unless rule.level
# is >= 12 or the rule is a known compromise indicator. Info-level telemetry
# is telemetry_info (not one 180-day row per alert). Repeated included
# telemetry lows that share (rule/check id, asset) collapse; the extras are
# telemetry_duplicate. A bare nmap-style port-open row on a host+port that
# already has a specific finding (nuclei/Nessus/testssl/NSE/…) is
# superseded_by_specific. UDP open|filtered is not_a_weakness (not a
# confirmed open port). A lighter plan
# (GRC_POAM_LIGHTER) restores the old exclude set.
POAM_INCLUDE_REASONS = frozenset(
    {
        "nse_misconfig",
        "severity_high_critical",
        "key_medium",
        "severity_low",
        "severity_medium",
        "needs_review",
    }
)
POAM_EXCLUDE_REASONS = frozenset(
    {
        "honeypot",
        "NOT_A_WEAKNESS",
        "severity_info",
        "severity_low",
        "severity_medium_not_key",
        "telemetry",
        "telemetry_info",
        "telemetry_duplicate",
        "superseded_by_specific",
        "DUPLICATE_INSTANCE",
        "not_a_weakness",
        "unmapped",
    }
)
LIGHTER_ENV = "GRC_POAM_LIGHTER"
TELEMETRY_SOURCES = frozenset({"host-wazuh", "wazuh"})
TELEMETRY_CATEGORIES = frozenset({"incident", "alert", "telemetry", "siem-alert"})
TELEMETRY_LABELS = frozenset({"alert", "telemetry"})


def _is_honeypot(rec: dict[str, Any]) -> bool:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    source = str(rec.get("source") or "").lower()
    category = str(rec.get("category") or "").lower()
    text = _blob(rec)
    return (
        source in {"honeypot", "honeypot-sensor"}
        or category in {"honeypot", "deception-sensor"}
        or extra.get("honesty") == "deception-sensor"
        or "deception-sensor" in text
    )


def keep_telemetry_on_plan(rec: dict[str, Any]) -> bool:
    """High Wazuh levels and known compromise indicators stay on the POA&M."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    if extra.get("compromise") is True:
        return True
    raw = extra.get("rule_level")
    try:
        level = int(raw)
    except (TypeError, ValueError):
        level = 0
    return level >= 12


def is_telemetry_finding(rec: dict[str, Any]) -> bool:
    """Wazuh alerts and other telemetry-only rows — not hardening/posture checks."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    if extra.get("telemetry") is True:
        return True
    source = str(rec.get("source") or "").lower()
    category = str(rec.get("category") or "").lower()
    labels = {str(item).lower() for item in (rec.get("labels") or [])}
    if source in TELEMETRY_SOURCES and (
        category in TELEMETRY_CATEGORIES or bool(labels & TELEMETRY_LABELS)
    ):
        return True
    return category in TELEMETRY_CATEGORIES and bool(labels & TELEMETRY_LABELS)


def telemetry_collapse_key(rec: dict[str, Any]) -> tuple[str, str]:
    """(rule/check id or title, asset). Empty rule falls back to the alert name."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    rule = ""
    for key in ("rule_id", "check_id", "rule", "plugin_id", "id"):
        rule = str(extra.get(key) or "").strip().lower()
        if rule:
            break
    if not rule:
        rule = str(rec.get("name") or rec.get("ref_id") or "").strip().lower()
    assets = rec.get("assets") or []
    asset = "|".join(str(item) for item in assets if item).strip().lower()
    if not asset:
        extra_asset = str(extra.get("agent") or extra.get("hostname") or "").strip().lower()
        asset = extra_asset
    return (rule, asset)


def poam_lighter_requested() -> bool:
    raw = str(os.environ.get(LIGHTER_ENV) or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def poam_decision(rec: dict[str, Any], *, lighter: bool | None = None) -> dict[str, Any]:
    """Why this weakness is on or off the POA&M. Never a silent drop.

    Default (full) plan includes every non-info, non-honeypot weakness.
    NSE misconfig is always included. Honeypot / deception-sensor is always
    excluded. Cost/ops Custodian policies are NOT_A_WEAKNESS. Unclassified
    Custodian policies stay on the plan as needs_review (never a silent
    drop). kind:excluded rows (osquery unmapped, Custodian cost) land in
    excluded.csv. Informational is excluded (telemetry_info for telemetry-only
    rows). Status is not a gate. Repeated telemetry lows are collapsed by
    iter_poam_decisions, not here.

    GRC_POAM_LIGHTER=1 restores the lighter plan: Lows and non-key Mediums
    are excluded (severity_low / severity_medium_not_key) and recorded.
    """
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    check = str(extra.get("check_id") or "")
    sev = canon_severity(rec.get("severity"))
    mapped = map_finding(rec)
    key_medium = bool(mapped.get("key_medium"))
    if lighter is None:
        lighter = poam_lighter_requested()
    if rec.get("kind") == "excluded":
        reason = str(extra.get("exclude_reason") or extra.get("poam_exclude") or "")
        if reason.lower() in {"unmapped", "unmapped query"} or "unmapped" in reason.lower():
            reason = "NOT_A_WEAKNESS"
        else:
            reason = _canon_exclude_reason(reason or "unmapped")
        if reason not in POAM_EXCLUDE_REASONS:
            reason = "NOT_A_WEAKNESS"
        return {"include": False, "reason": reason, "severity": sev}
    if _is_needs_review(rec):
        return {"include": True, "reason": "needs_review", "severity": sev}
    if _is_custodian_not_a_weakness(rec):
        return {"include": False, "reason": "not_a_weakness", "severity": sev}
    if check in MISCONFIG_RULES:
        return {"include": True, "reason": "nse_misconfig", "severity": sev}
    if _is_honeypot(rec):
        return {"include": False, "reason": "honeypot", "severity": sev}
    if extra.get("not_a_weakness") or str(extra.get("exclude_reason") or "") == "not_a_weakness":
        return {"include": False, "reason": "not_a_weakness", "severity": sev}
    if is_telemetry_finding(rec) and not keep_telemetry_on_plan(rec):
        if sev == "info":
            return {"include": False, "reason": "telemetry_info", "severity": sev}
        return {"include": False, "reason": "telemetry", "severity": sev}
    if sev == "info":
        return {"include": False, "reason": "severity_info", "severity": sev}
    if sev in {"high", "critical"}:
        return {"include": True, "reason": "severity_high_critical", "severity": sev}
    if key_medium:
        return {"include": True, "reason": "key_medium", "severity": sev}
    if sev == "low":
        if lighter:
            return {"include": False, "reason": "severity_low", "severity": sev}
        return {"include": True, "reason": "severity_low", "severity": sev}
    if sev == "medium":
        if lighter:
            return {"include": False, "reason": "severity_medium_not_key", "severity": sev}
        return {"include": True, "reason": "severity_medium", "severity": sev}
    included = bool(mapped.get("include_poam"))
    return {
        "include": included,
        "reason": "severity_high_critical" if included else "unexplained",
        "severity": sev,
    }


def iter_poam_decisions(
    findings: list[dict[str, Any]], *, lighter: bool | None = None
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Per-finding POA&M decisions with telemetry flood-guard collapse.

    Multiple low telemetry rows that share (rule/check id, asset) become one
    included row. The extras are excluded as telemetry_duplicate so
    weaknesses_total == poam_included + sum(excluded_by_reason).

    A port-only row that shares a normalized host+port with a specific
    finding is excluded as superseded_by_specific (winner = highest
    severity, then lowest EGP- id). The row stays in the finding set.
    """
    from shared.port_fold import SUPERSEDED_REASON, egp_id_for, port_only_superseders

    if lighter is None:
        lighter = poam_lighter_requested()
    seen: set[tuple[str, str]] = set()
    superseders = port_only_superseders(findings)
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for rec in findings:
        decision = dict(poam_decision(rec, lighter=lighter))
        if (
            decision.get("include")
            and decision.get("severity") == "low"
            and is_telemetry_finding(rec)
        ):
            key = telemetry_collapse_key(rec)
            if key[0] and key in seen:
                decision["include"] = False
                decision["reason"] = "telemetry_duplicate"
            elif key[0]:
                seen.add(key)
        winner = superseders.get(str(rec.get("ref_id") or ""))
        if winner is not None:
            decision["include"] = False
            decision["reason"] = SUPERSEDED_REASON
            decision["superseded_by"] = egp_id_for(winner)
            decision["superseded_by_ref"] = str(winner.get("ref_id") or "")
        out.append((rec, decision))
    return out


def poam_breakdown(findings: list[dict[str, Any]], *, lighter: bool | None = None) -> dict[str, Any]:
    """weaknesses_total == poam_included + sum(excluded_by_reason)."""
    if lighter is None:
        lighter = poam_lighter_requested()
    excluded: dict[str, int] = {}
    included = 0
    for _rec, decision in iter_poam_decisions(findings, lighter=lighter):
        if decision["include"]:
            included += 1
            continue
        reason = str(decision["reason"] or "unexplained")
        excluded[reason] = excluded.get(reason, 0) + 1
    return {
        "weaknesses_total": len(findings),
        "poam_included": included,
        "excluded_by_reason": excluded,
        "poam_plan": "lighter" if lighter else "full",
    }


def extra_labels(rec: dict[str, Any] | None = None) -> list[str]:
    """Wizard-safe CPG + CSF stamps. No colons on the CISO wire.

    Findings get the same class-based CSF/CPG stamps as poam.csv
    (subcategory + CPG 2.0 goal). Assets and other kinds get none.
    Never the blanket ``csf_PR`` / ``csf_protect`` or retired
    ``cpg_2_W`` / ``cpg_1_E``.
    """
    if rec and rec.get("kind") == "finding":
        mapped = map_finding(rec)
        csf, cpg = csf_cpg_tag_set(str(mapped.get("framework_refs") or ""))
        stamps = [t for t in list(cpg) + list(csf) if t not in BLANKET_REGISTER_STAMPS]
        if any(t.startswith("cpg_") for t in stamps):
            stamps.append("cisa_cpg")
        if any(t.startswith("csf_") for t in stamps):
            stamps.append("nist_csf")
    elif rec:
        stamps = []
    else:
        stamps = [
            "nist_csf",
            "cisa_cpg",
            "cpg_3_S",
            "cpg_3_I",
            "cpg_2_B",
            "csf_PR_IR_01",
            "csf_unmapped",
            "cpg_unmapped",
        ]
    out: list[str] = []
    for stamp in stamps:
        if stamp and ":" not in stamp and stamp not in BLANKET_REGISTER_STAMPS and stamp not in out:
            out.append(stamp)
    return out
