"""Evergreen control map — sensor + finding → multi-framework controls + remediation.

Used by risk register / POA&M leave-behinds. Defensive GRC mapping only.
Frameworks: NIST CSF 2.0, NIST SP 800-53 Rev.5, CIS Controls v8, ISO/IEC 27001:2022.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ControlHit:
    controls: tuple[str, ...]
    action: str
    priority: str = "medium"  # remediation priority hint
    frameworks: tuple[str, ...] = ()
    rule_id: str = ""


def _hit(rule_id: str, controls: list[str], action: str, priority: str = "medium") -> ControlHit:
    fws = []
    for c in controls:
        if c.startswith("NIST.CSF"):
            fws.append("NIST_CSF")
        elif c.startswith("NIST.800-53") or c.startswith("NIST.SP.800-53"):
            fws.append("NIST_800_53")
        elif c.startswith("CIS."):
            fws.append("CIS_v8")
        elif c.startswith("ISO27001"):
            fws.append("ISO27001")
    return ControlHit(
        controls=tuple(controls),
        action=action,
        priority=priority,
        frameworks=tuple(dict.fromkeys(fws)),
        rule_id=rule_id,
    )


# --- Sensor-first map (preferred: exact env-eval sensor id) ---
SENSOR_MAP: dict[str, ControlHit] = {
    "sense-cleartext-http": _hit(
        "cleartext-http",
        ["NIST.CSF.PR.DS-02", "NIST.800-53.SC-8", "NIST.800-53.SC-7", "CIS.3.3", "ISO27001.A.8.24"],
        "Terminate TLS on the edge/app; 301 HTTP→HTTPS; disable HTTP-only listeners where feasible.",
        "high",
    ),
    "sense-cleartext-ftp": _hit(
        "cleartext-ftp",
        ["NIST.CSF.PR.DS-02", "NIST.800-53.SC-8", "CIS.3.3", "ISO27001.A.8.24"],
        "Disable FTP; use SFTP/FTPS or managed transfer with encryption in transit.",
        "high",
    ),
    "sense-http-https-redirect": _hit(
        "http-https-redirect",
        ["NIST.CSF.PR.DS-02", "NIST.800-53.SC-8", "CIS.3.3", "ISO27001.A.8.24"],
        "Configure edge to redirect all HTTP to HTTPS (301/308); enable HSTS after validation.",
        "medium",
    ),
    "sense-http-headers": _hit(
        "security-headers",
        [
            "NIST.CSF.PR.PT-03",
            "NIST.800-53.SC-7",
            "NIST.800-53.SC-18",
            "CIS.5.2",
            "ISO27001.A.8.27",
        ],
        "Deploy baseline headers: CSP, X-Frame-Options or frame-ancestors, X-Content-Type-Options, "
        "Referrer-Policy, Permissions-Policy; prefer reverse-proxy defaults.",
        "medium",
    ),
    "sense-cookie-flags": _hit(
        "cookie-flags",
        ["NIST.CSF.PR.DS-02", "NIST.800-53.SC-8", "NIST.800-53.SC-23", "CIS.5.2", "ISO27001.A.8.24"],
        "Set Secure + HttpOnly + SameSite=Lax/Strict on session cookies; review domain/path scope.",
        "medium",
    ),
    "sense-cors": _hit(
        "cors-misconfig",
        ["NIST.CSF.PR.AC-03", "NIST.800-53.AC-3", "NIST.800-53.AC-4", "CIS.5.2", "ISO27001.A.8.3"],
        "Replace Access-Control-Allow-Origin * with explicit allowlist; never combine * with credentials.",
        "medium",
    ),
    "sense-ssh-banner": _hit(
        "ssh-exposure",
        ["NIST.CSF.PR.AC-05", "NIST.800-53.CM-7", "NIST.800-53.AC-17", "CIS.5.2", "CIS.12.2", "ISO27001.A.8.20"],
        "Restrict SSH to jump hosts/VPN; disable password auth; keys + MFA where possible; current OpenSSH.",
        "medium",
    ),
    "sense-surface": _hit(
        "network-surface",
        ["NIST.CSF.ID.AM-01", "NIST.CSF.PR.AC-05", "NIST.800-53.CM-7", "NIST.800-53.CM-8", "CIS.16.2", "ISO27001.A.8.9"],
        "Inventory listeners; close unused ports; document approved exposure; segment admin planes.",
        "medium",
    ),
    "sense-tls": _hit(
        "tls-service",
        ["NIST.CSF.PR.DS-02", "NIST.800-53.SC-8", "NIST.800-53.SC-13", "CIS.3.3", "ISO27001.A.8.24"],
        "Ensure TLS service is present where HTTPS is expected; disable weak protocols/ciphers.",
        "medium",
    ),
    "sense-tls-expiry": _hit(
        "tls-cert-lifecycle",
        ["NIST.CSF.PR.DS-02", "NIST.800-53.SC-17", "CIS.3.3", "ISO27001.A.8.24"],
        "Automate issuance/renewal (ACME); monitor notAfter; alert at 30/14/7 days; validate chain post-renew.",
        "high",
    ),
    "sense-service-exposure": _hit(
        "dangerous-service-exposure",
        ["NIST.CSF.PR.AC-05", "NIST.800-53.SC-7", "NIST.800-53.CM-7", "CIS.16.2", "CIS.12.2", "ISO27001.A.8.20"],
        "Remove public exposure of data/admin services (DB/cache/RDP/SMB/etc.); bind to private nets + auth.",
        "critical",
    ),
    "sense-dir-listing": _hit(
        "dir-listing",
        ["NIST.CSF.PR.DS-01", "NIST.800-53.CM-7", "NIST.800-53.AC-3", "CIS.5.2", "ISO27001.A.8.12"],
        "Disable autoindex/directory browsing; deny listing in nginx/apache; review backup files.",
        "medium",
    ),
    "sense-git-exposed": _hit(
        "git-exposed",
        ["NIST.CSF.PR.DS-01", "NIST.CSF.PR.AC-04", "NIST.800-53.AC-3", "NIST.800-53.CM-7", "CIS.5.2", "ISO27001.A.8.12"],
        "Block /.git at edge immediately; purge VCS metadata from web roots; rotate any exposed secrets.",
        "critical",
    ),
    "sense-tech-disclosure": _hit(
        "tech-disclosure",
        ["NIST.CSF.PR.PT-03", "NIST.800-53.CM-7", "CIS.5.2", "ISO27001.A.8.27"],
        "Strip Server/X-Powered-By version tokens at reverse proxy; reduce fingerprinting surface.",
        "low",
    ),
    "sense-default-page": _hit(
        "default-content",
        ["NIST.CSF.PR.IP-01", "NIST.800-53.CM-2", "NIST.800-53.CM-6", "CIS.5.2", "ISO27001.A.8.9"],
        "Replace default welcome/error pages; ensure production vhost content is intentional.",
        "medium",
    ),
    "sense-http-methods": _hit(
        "http-methods",
        ["NIST.CSF.PR.PT-03", "NIST.800-53.CM-7", "NIST.800-53.SC-7", "CIS.5.2", "ISO27001.A.8.27"],
        "Disable TRACE/TRACK; allow only required verbs (typically GET/HEAD/POST); block PUT/DELETE at edge if unused.",
        "medium",
    ),
}

# Title/description heuristics when sensor missing or generic
HEURISTIC_RULES: list[tuple[re.Pattern[str], ControlHit]] = [
    (re.compile(r"smbv?1|smb\s*v1", re.I),
     _hit("smb-v1", ["NIST.CSF.PR.AA-01", "NIST.800-53.CM-7", "CIS.5.1", "ISO27001.A.8.9"],
          "Disable SMBv1; enforce SMB signing; remove legacy dependencies.", "high")),
    (re.compile(r"s3.*public|public.*bucket|block public access", re.I),
     _hit("s3-public", ["NIST.CSF.PR.DS-01", "NIST.800-53.AC-3", "CIS.3.3", "ISO27001.A.8.12"],
          "Enable S3 Block Public Access; remove public ACLs/policies; audit bucket policies.", "critical")),
    (re.compile(r"rdp|3389|remote desktop", re.I),
     _hit("rdp", ["NIST.CSF.PR.AC-05", "NIST.800-53.AC-17", "CIS.12.2", "ISO27001.A.8.20"],
          "Do not expose RDP to Internet; jump host + NLA + MFA; geo/IP allowlists.", "high")),
    (re.compile(r"\bredis\b|\b6379\b", re.I),
     _hit("redis", ["NIST.CSF.PR.AC-05", "NIST.800-53.SC-7", "CIS.16.2", "ISO27001.A.8.20"],
          "Bind Redis to localhost/private; require AUTH/ACL; disable dangerous commands.", "critical")),
    (re.compile(r"mongodb|27017", re.I),
     _hit("mongodb", ["NIST.CSF.PR.AC-05", "NIST.800-53.SC-7", "CIS.16.2", "ISO27001.A.8.20"],
          "Do not expose MongoDB publicly; auth + TLS; network policy.", "critical")),
    (re.compile(r"mysql|3306|postgres|5432", re.I),
     _hit("sql-db", ["NIST.CSF.PR.AC-05", "NIST.800-53.SC-7", "CIS.16.2", "ISO27001.A.8.20"],
          "Bind DB to private network; require auth/TLS; no public 3306/5432.", "high")),
    (re.compile(r"elasticsearch|9200|kibana", re.I),
     _hit("elastic", ["NIST.CSF.PR.AC-05", "NIST.800-53.SC-7", "CIS.16.2", "ISO27001.A.8.20"],
          "Require auth on Elasticsearch; private network only; disable anonymous.", "high")),
    (re.compile(r"memcached|11211", re.I),
     _hit("memcached", ["NIST.CSF.PR.AC-05", "NIST.800-53.SC-7", "CIS.16.2"],
          "Do not expose memcached; bind localhost; firewall UDP/TCP 11211.", "high")),
    (re.compile(r"telnet|\b23\b", re.I),
     _hit("telnet", ["NIST.CSF.PR.DS-02", "NIST.800-53.SC-8", "CIS.3.3"],
          "Disable telnet; replace with SSH.", "critical")),
    (re.compile(r"\bvnc\b|5900", re.I),
     _hit("vnc", ["NIST.CSF.PR.AC-05", "NIST.800-53.AC-17", "CIS.12.2"],
          "Tunnel VNC; require strong auth; prefer no direct exposure.", "high")),
    (re.compile(r"weak cipher|sslv3|tlsv1\.0|tls 1\.0|heartbleed", re.I),
     _hit("weak-tls", ["NIST.CSF.PR.DS-02", "NIST.800-53.SC-8", "NIST.800-53.SC-13", "CIS.3.3", "ISO27001.A.8.24"],
          "Disable SSLv3/TLS1.0/1.1; enforce TLS1.2+ with modern cipher suites.", "high")),
    (re.compile(r"open.?relay|smtp captur|anonymous bind", re.I),
     _hit("insecure-service", ["NIST.CSF.PR.AC-03", "NIST.800-53.AC-3", "CIS.5.2"],
          "Disable anonymous/open relay paths; require authenticated submission.", "high")),
    (re.compile(r"world.?writ|0?777|permissions too open", re.I),
     _hit("perms", ["NIST.CSF.PR.AC-04", "NIST.800-53.AC-3", "CIS.5.2", "ISO27001.A.8.3"],
          "Harden filesystem permissions; remove world-writable paths.", "medium")),
]


UNMAPPED = _hit(
    "unmapped",
    ["UNMAPPED"],
    "Triage manually: assign asset owner, map to framework control, set due date.",
    "medium",
)


def map_finding(
    *,
    title: str = "",
    sensor: str = "",
    description: str = "",
    template_id: str = "",
    labels: list[str] | None = None,
) -> ControlHit:
    """Map a finding to controls. Sensor id wins; then heuristics on text."""
    s = (sensor or "").strip().lower()
    if s in SENSOR_MAP:
        return SENSOR_MAP[s]
    # normalize sense_ vs sense-
    s2 = s.replace("_", "-")
    if s2 in SENSOR_MAP:
        return SENSOR_MAP[s2]

    blob = " ".join(
        x for x in [title, description, template_id, " ".join(labels or [])] if x
    )
    for pat, hit in HEURISTIC_RULES:
        if pat.search(blob):
            return hit

    # light generic fallbacks
    tl = blob.lower()
    if "header" in tl:
        return SENSOR_MAP["sense-http-headers"]
    if "cookie" in tl:
        return SENSOR_MAP["sense-cookie-flags"]
    if "cors" in tl:
        return SENSOR_MAP["sense-cors"]
    if "open port" in tl or "listener" in tl:
        return SENSOR_MAP["sense-surface"]
    if "tls" in tl or "https" in tl or "certificate" in tl:
        return SENSOR_MAP["sense-tls"]
    if "ssh" in tl:
        return SENSOR_MAP["sense-ssh-banner"]
    if "cleartext" in tl or "http without" in tl:
        return SENSOR_MAP["sense-cleartext-http"]

    return UNMAPPED


def map_controls_dict(title: str = "", template_id: str = "", sensor: str = "", description: str = "") -> dict[str, Any]:
    """Pack-compatible dict shape for poam_export."""
    h = map_finding(title=title, sensor=sensor, description=description, template_id=template_id)
    return {
        "controls": list(h.controls),
        "action": h.action,
        "priority": h.priority,
        "frameworks": list(h.frameworks),
        "rule_id": h.rule_id,
    }


def catalog() -> dict[str, Any]:
    """Export map catalog for docs/tests."""
    return {
        "sensors": {k: {"controls": list(v.controls), "action": v.action, "priority": v.priority, "rule_id": v.rule_id} for k, v in SENSOR_MAP.items()},
        "heuristic_count": len(HEURISTIC_RULES),
    }
