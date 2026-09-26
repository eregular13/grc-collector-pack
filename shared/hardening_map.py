"""Lynis + OpenSCAP + HardeningKitty → pack control keys (CSF/CPG).

Lynis: only mapped warnings/suggestions become findings.
OpenSCAP: fail/error always become findings; this map stamps controls
and lets Lynis+oscap+HK dedupe the same gap on the same host.
HardeningKitty: Failed (TestResult/Result) become findings; Passed silent.
Hardening index is a score, not a finding.
Not a CIS benchmark / CIS-CAT deliverable.

CIS Controls v8 safeguard IDs live only in extra.cis_v8_internal
(INTERNAL-ONLY). Never copy them into client-facing reports, CISO
exports, or POA&M text. The owner has not licensed CIS content for
client deliverables.
"""

from __future__ import annotations

from typing import Any

# Pack control keys already used by shared.control_map (underscore CSF/CPG).
# Reuse the same keys across OS so (host, control_key) dedupe stays consistent.
HOST_FIREWALL = "host_firewall"
SSH_ROOT_LOGIN = "ssh_root_login"
SSH_EMPTY_PASSWORDS = "ssh_empty_passwords"
PASSWORD_POLICY = "password_policy"
PATCHING = "patching"
TIME_SYNC = "time_sync"
ACCOUNT_LOCKOUT = "account_lockout"
SESSION_LOCK = "session_lock"
AUDIT_LOGGING = "audit_logging"
MALWARE_PROTECTION = "malware_protection"
ENCRYPTION_IN_TRANSIT = "encryption_in_transit"

# INTERNAL-ONLY CIS Controls v8 tokens. Distinct from nmap cis_* framework_refs.
# Never rendered into CISO / POA&M / OpenGRC / Probo / console reports.
CIS_V8_INTERNAL_FIELD = "cis_v8_internal"
CIS_V8_PREFIX = "CIS-v8-"

_POSTURE = (
    "This is a host-hardening posture finding (MS Security Baseline / "
    "Lynis / OpenSCAP), not a CVE."
)

CONTROL_META: dict[str, dict[str, Any]] = {
    HOST_FIREWALL: {
        "control_name": "Enable a host firewall",
        "recommended_fix": f"Install and enable a host firewall. {_POSTURE}",
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
        "nist_800_53": ["CM-6", "CM-7"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}4.5"],
    },
    SSH_ROOT_LOGIN: {
        "control_name": "Disable SSH root login",
        "recommended_fix": (
            f"Set PermitRootLogin no and use a named sudo account. {_POSTURE}"
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
        "nist_800_53": ["IA-2", "CM-6"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}5.4"],
    },
    SSH_EMPTY_PASSWORDS: {
        "control_name": "Disable SSH empty passwords",
        "recommended_fix": f"Set PermitEmptyPasswords no. {_POSTURE}",
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
        "nist_800_53": ["IA-5", "CM-6"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}5.2"],
    },
    PASSWORD_POLICY: {
        "control_name": "Enforce password policy",
        "recommended_fix": (
            f"Set a minimum password length and aging policy. {_POSTURE}"
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
        "nist_800_53": ["IA-5"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}5.2"],
    },
    PATCHING: {
        "control_name": "Apply security updates",
        "recommended_fix": f"Install outstanding security patches. {_POSTURE}",
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
        "nist_800_53": ["SI-2", "CM-6"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}7.3"],
    },
    TIME_SYNC: {
        "control_name": "Enable time synchronization",
        "recommended_fix": (
            f"Run chrony, ntpd, or W32Time so audit timestamps stay trustworthy. "
            f"{_POSTURE}"
        ),
        "csf": "csf_DE",
        "cpg": "cpg_1_E",
        "nist_800_53": ["AU-8"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}8.4"],
    },
    ACCOUNT_LOCKOUT: {
        "control_name": "Enforce account lockout",
        "recommended_fix": (
            f"Set an account lockout threshold and duration so brute-force "
            f"password attempts stop. {_POSTURE}"
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
        "nist_800_53": ["AC-7"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}6.2"],
    },
    SESSION_LOCK: {
        "control_name": "Enforce session lock",
        "recommended_fix": (
            f"Lock the session after inactivity (machine inactivity limit / "
            f"screensaver). {_POSTURE}"
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
        "nist_800_53": ["AC-11"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}4.3"],
    },
    AUDIT_LOGGING: {
        "control_name": "Enable audit logging",
        "recommended_fix": (
            f"Turn on advanced audit policy (logon, account management, "
            f"object access) so events are recorded. {_POSTURE}"
        ),
        "csf": "csf_DE",
        "cpg": "cpg_1_E",
        "nist_800_53": ["AU-2", "AU-12"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}8.2"],
    },
    MALWARE_PROTECTION: {
        "control_name": "Enable malware protection",
        "recommended_fix": (
            f"Keep Microsoft Defender (or equivalent) real-time protection on. "
            f"{_POSTURE}"
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
        "nist_800_53": ["SI-3"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}10.1"],
    },
    ENCRYPTION_IN_TRANSIT: {
        "control_name": "Require encryption in transit",
        "recommended_fix": (
            f"Require encrypted remote sessions (RDP / SMB / TLS). {_POSTURE}"
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
        "nist_800_53": ["SC-8"],
        "cis_v8_internal": [f"{CIS_V8_PREFIX}3.10"],
    },
}

# Lynis check IDs with a clear control mapping. Unmapped suggestions stay silent.
LYNIS_MAP: dict[str, str] = {
    "FIRE-4512": HOST_FIREWALL,
    "FIRE-4520": HOST_FIREWALL,
    "FIRE-4590": HOST_FIREWALL,
    "SSH-7408": SSH_ROOT_LOGIN,
    "SSH-7402": SSH_EMPTY_PASSWORDS,
    "AUTH-9204": PASSWORD_POLICY,
    "AUTH-9230": PASSWORD_POLICY,
    "PKGS-7345": PATCHING,
    "PKGS-7394": PATCHING,
    "TIME-3104": TIME_SYNC,
    "TIME-3170": TIME_SYNC,
}

# HardeningKitty MS Security Baseline IDs
# (finding_list_msft_security_baseline_windows_11_24h2_machine.csv).
# Never finding_list_cis_*.
HK_MAP: dict[str, str] = {
    "10100": PASSWORD_POLICY,  # Length of password history maintained
    "10101": PASSWORD_POLICY,  # Minimum password length
    "10102": PASSWORD_POLICY,  # Password must meet complexity requirements
    "10103": PASSWORD_POLICY,  # Store passwords using reversible encryption
    "10219": PASSWORD_POLICY,  # Do not store LAN Manager hash value
    "10000": ACCOUNT_LOCKOUT,  # Account lockout duration
    "10001": ACCOUNT_LOCKOUT,  # Account lockout threshold
    "10002": ACCOUNT_LOCKOUT,  # Reset account lockout counter
    "10003": ACCOUNT_LOCKOUT,  # Allow Administrator account lockout
    "10208": SESSION_LOCK,  # Interactive logon: Machine inactivity limit
    "10400": AUDIT_LOGGING,  # Credential Validation
    "10407": AUDIT_LOGGING,  # Logon
    "10201": AUDIT_LOGGING,  # Force audit policy subcategory settings
    "10501": HOST_FIREWALL,  # EnableFirewall (Domain Profile)
    "10515": HOST_FIREWALL,  # EnableFirewall (Private Profile)
    "10529": HOST_FIREWALL,  # EnableFirewall (Public Profile)
    "11014": MALWARE_PROTECTION,  # Turn off real-time protection
    "10972": MALWARE_PROTECTION,  # Configure detection for PUAs
    "10964": ENCRYPTION_IN_TRANSIT,  # RDP client connection encryption level
}

# SSG rule short names (last component of xccdf_org.ssgproject.content_rule_*).
OSCAP_MAP: dict[str, str] = {
    "sshd_disable_root_login": SSH_ROOT_LOGIN,
    "sshd_permit_root_login": SSH_ROOT_LOGIN,
    "sshd_disable_empty_passwords": SSH_EMPTY_PASSWORDS,
    "no_empty_passwords": SSH_EMPTY_PASSWORDS,
    "package_iptables_installed": HOST_FIREWALL,
    "service_iptables_enabled": HOST_FIREWALL,
    "package_firewalld_installed": HOST_FIREWALL,
    "service_firewalld_enabled": HOST_FIREWALL,
    "service_ufw_enabled": HOST_FIREWALL,
    "set_firewalld_default_zone": HOST_FIREWALL,
    "package_ufw_installed": HOST_FIREWALL,
    "iptables_default_deny": HOST_FIREWALL,
    "security_patches_up_to_date": PATCHING,
    "ensure_debian_gpgcheck": PATCHING,
    "accounts_password_pam_minlen": PASSWORD_POLICY,
    "accounts_password_minlen_login_defs": PASSWORD_POLICY,
    "service_chronyd_enabled": TIME_SYNC,
    "chronyd_or_ntpd_specified": TIME_SYNC,
    "service_ntpd_enabled": TIME_SYNC,
}


def lynis_control(check_id: str, title: str = "") -> str | None:
    """Return a pack control key or None (no finding)."""
    cid = (check_id or "").strip().upper()
    if cid in LYNIS_MAP:
        return LYNIS_MAP[cid]
    return _keyword_control(f"{cid} {title}")


def hk_control(check_id: str, name: str = "", category: str = "") -> str | None:
    """Return a pack control key for a HardeningKitty MS baseline check."""
    hid = (check_id or "").strip()
    if hid in HK_MAP:
        return HK_MAP[hid]
    return _keyword_control(f"{hid} {category} {name}")


def oscap_control(rule_id: str, title: str = "") -> str | None:
    """Return a pack control key when the SSG rule is a known alias."""
    short = oscap_short_id(rule_id)
    if short in OSCAP_MAP:
        return OSCAP_MAP[short]
    return _keyword_control(f"{short} {title}")


def oscap_short_id(rule_id: str) -> str:
    raw = (rule_id or "").strip()
    if "content_rule_" in raw:
        return raw.rsplit("content_rule_", 1)[-1]
    if "_" in raw and raw.startswith("xccdf_"):
        return raw.rsplit("_", 1)[-1]
    return raw


def _keyword_control(text: str) -> str | None:
    blob = (text or "").lower().replace("_", " ").replace("-", " ")
    compact = blob.replace(" ", "")
    if "permitrootlogin" in compact or ("ssh" in blob and "root login" in blob):
        return SSH_ROOT_LOGIN
    if "permitemptypasswords" in compact or ("empty password" in blob and "ssh" in blob):
        return SSH_EMPTY_PASSWORDS
    if "firewall" in blob and (
        "no firewall" in blob
        or "not installed" in blob
        or "inactive" in blob
        or "firewalld" in blob
        or "iptables" in blob
        or "ufw" in blob
        or "enablefirewall" in compact
        or "windows firewall" in blob
    ):
        return HOST_FIREWALL
    if (
        "password history" in blob
        or "password min" in blob
        or "pam minlen" in blob
        or "minimum password length" in blob
        or "password complexity" in blob
        or "reversible encryption" in blob
        or "lan manager hash" in blob
        or "lm hash" in blob
    ):
        return PASSWORD_POLICY
    if "lockout" in blob:
        return ACCOUNT_LOCKOUT
    if "inactivity limit" in blob or "screen saver" in blob or "screensaver" in blob:
        return SESSION_LOCK
    if "audit policy" in blob or (
        "advanced audit" in blob and ("logon" in blob or "credential" in blob)
    ):
        return AUDIT_LOGGING
    if "real-time protection" in blob or (
        "defender" in blob and ("antivirus" in blob or "turn off" in blob)
    ):
        return MALWARE_PROTECTION
    if "encryption level" in blob or (
        "require encryption" in blob and ("rdp" in blob or "smb" in blob or "tls" in blob)
    ):
        return ENCRYPTION_IN_TRANSIT
    if "security patch" in blob or "package update" in blob or "windows update" in blob:
        return PATCHING
    if "chrony" in blob or "w32time" in blob or ("ntp" in blob and "enable" in blob):
        return TIME_SYNC
    return None


def control_meta(key: str | None) -> dict[str, str]:
    if not key:
        return {}
    return dict(CONTROL_META.get(key) or {})


def extra_control_fields(
    key: str | None, *, include_cis_internal: bool = False
) -> dict[str, Any]:
    meta = control_meta(key)
    if not key or not meta:
        return {}
    out: dict[str, Any] = {
        "control_key": key,
        "control_name": meta.get("control_name") or "",
        "csf": meta.get("csf") or "csf_PR",
        "cpg": meta.get("cpg") or "cpg_2_W",
        "nist_800_53": list(meta.get("nist_800_53") or []),
    }
    if include_cis_internal:
        # INTERNAL-ONLY. Callers must not copy this into client-facing text.
        out[CIS_V8_INTERNAL_FIELD] = list(meta.get("cis_v8_internal") or [])
    return out


def all_cis_v8_internal_tokens() -> frozenset[str]:
    """Every INTERNAL-ONLY CIS v8 token this map may stamp on HK rows."""
    tokens: set[str] = set()
    for meta in CONTROL_META.values():
        for tok in meta.get("cis_v8_internal") or []:
            if tok:
                tokens.add(str(tok))
    return frozenset(tokens)
