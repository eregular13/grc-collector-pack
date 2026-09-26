"""Lynis + OpenSCAP → pack control keys (CSF/CPG vocabulary).

Lynis: only mapped warnings/suggestions become findings.
OpenSCAP: fail/error always become findings; this map stamps controls
and lets Lynis+oscap dedupe the same gap on the same host.
Hardening index is a score, not a finding.
Not a CIS benchmark / CIS-CAT deliverable.
"""

from __future__ import annotations

from typing import Any

# Pack control keys already used by shared.control_map (underscore CSF/CPG).
HOST_FIREWALL = "host_firewall"
SSH_ROOT_LOGIN = "ssh_root_login"
SSH_EMPTY_PASSWORDS = "ssh_empty_passwords"
PASSWORD_POLICY = "password_policy"
PATCHING = "patching"
TIME_SYNC = "time_sync"

CONTROL_META: dict[str, dict[str, str]] = {
    HOST_FIREWALL: {
        "control_name": "Enable a host firewall",
        "recommended_fix": (
            "Install and enable a host firewall. This is a Lynis/OpenSCAP "
            "posture finding, not a CVE."
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
    },
    SSH_ROOT_LOGIN: {
        "control_name": "Disable SSH root login",
        "recommended_fix": (
            "Set PermitRootLogin no and use a named sudo account. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
    },
    SSH_EMPTY_PASSWORDS: {
        "control_name": "Disable SSH empty passwords",
        "recommended_fix": (
            "Set PermitEmptyPasswords no. This is a Lynis/OpenSCAP "
            "posture finding, not a CVE."
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
    },
    PASSWORD_POLICY: {
        "control_name": "Enforce password policy",
        "recommended_fix": (
            "Set a minimum password length and aging policy. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
    },
    PATCHING: {
        "control_name": "Apply security updates",
        "recommended_fix": (
            "Install outstanding security patches. This is a Lynis/OpenSCAP "
            "posture finding, not a CVE."
        ),
        "csf": "csf_PR",
        "cpg": "cpg_2_W",
    },
    TIME_SYNC: {
        "control_name": "Enable time synchronization",
        "recommended_fix": (
            "Run chrony or ntpd so audit timestamps stay trustworthy. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        ),
        "csf": "csf_PR",
        "cpg": "cpg_1_E",
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
    ):
        return HOST_FIREWALL
    if "password history" in blob or "password min" in blob or "pam minlen" in blob:
        return PASSWORD_POLICY
    if "security patch" in blob or "package update" in blob:
        return PATCHING
    if "chrony" in blob or ("ntp" in blob and "enable" in blob):
        return TIME_SYNC
    return None


def control_meta(key: str | None) -> dict[str, str]:
    if not key:
        return {}
    return dict(CONTROL_META.get(key) or {})


def extra_control_fields(key: str | None) -> dict[str, Any]:
    meta = control_meta(key)
    if not key or not meta:
        return {}
    return {
        "control_key": key,
        "control_name": meta.get("control_name") or "",
        "csf": meta.get("csf") or "csf_PR",
        "cpg": meta.get("cpg") or "cpg_2_W",
    }
