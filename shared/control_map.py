"""Finding → CISA CPG + NIST CSF stamps and a POA&M fix line.

Wizard-safe labels only (no colons). Honest: port-open is not a CVE.
"""

from __future__ import annotations

import os
import re
from typing import Any

from shared.finding_types import TYPE_WEAKNESS_NAME, type_remediation
from shared.framework_class_map import apply_class_mapping
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
    "Lock down sensitive perimeter hostnames": "identify",
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
            extra.get("cve"),
            extra.get("check_id"),
            extra.get("id"),
            extra.get("control"),
            extra.get("edge"),
            extra.get("access"),
        )
    ).lower()
