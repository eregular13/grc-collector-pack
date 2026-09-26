"""Nmap NSE script output -> misconfiguration finding specs.

Parse-only: reads <script id=... output=...> from a dropped nmap XML. Does not
run nmap. Each spec is evidence-backed by one NSE script; no NSE output, no
claim. Never echoes credentials found by a script.
"""

from __future__ import annotations

import re
from typing import Any

_TLS_OLD = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
_WEAK_CIPHER_TOKENS = ("_anon_", "_NULL_", "_EXPORT", "_RC4_", "_DES_", "3DES", "_MD5")
_GRADE_RE = re.compile(r"least strength:\s*([A-F])")
_BITS_RE = re.compile(r"Public Key bits:\s*(\d+)")
_CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.I)
_CVE_CVSS_RE = re.compile(r"(CVE-\d{4}-\d+)\s+([\d.]+)", re.I)


def _clip(text: str, limit: int = 240) -> str:
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def _spec(check: str, script: str, name: str, desc: str, sev: str, evidence: str) -> dict[str, Any]:
    return {
        "check_id": check,
        "nse_script": script,
        "name": name,
        "description": desc,
        "severity": sev,
        "evidence": _clip(evidence),
    }


def _tls(where: str, script: str, out: str) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    offered = [p for p in _TLS_OLD if re.search(rf"^\s*{re.escape(p)}:\s*$", out, re.M)]
    if offered:
        specs.append(
            _spec(
                "nse-tls-deprecated-protocol",
                script,
                f"Deprecated TLS protocol offered ({'/'.join(offered)})",
                f"{where} accepts {', '.join(offered)} (TLS 1.0 / TLS 1.1 or older) per nmap ssl-enum-ciphers.",
                "high" if any(p.startswith("SSL") for p in offered) else "medium",
                f"offered: {', '.join(offered)}",
            )
        )
    grade_m = _GRADE_RE.search(out)
    grade = grade_m.group(1) if grade_m else ""
    weak = sorted({line.strip().split(" ")[0] for line in out.splitlines() if any(t in line for t in _WEAK_CIPHER_TOKENS)})
    if grade in {"C", "D", "E", "F"} or weak:
        specs.append(
            _spec(
                "nse-tls-weak-cipher",
                script,
                f"Weak TLS cipher suites offered (least strength {grade or '?'})",
                f"{where} offers weak cipher suites (e.g. anonymous/NULL/EXPORT/RC4/3DES); "
                f"nmap ssl-enum-ciphers least strength {grade or 'unknown'}.",
                "high" if grade == "F" or any("_anon_" in c or "_NULL_" in c for c in weak) else "medium",
                f"least strength {grade or '?'}; weak: {', '.join(weak[:6])}",
            )
        )
    return specs


def _cert(where: str, script: str, out: str) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    subj = re.search(r"^Subject:\s*(.+)$", out, re.M)
    issuer = re.search(r"^Issuer:\s*(.+)$", out, re.M)
    if subj and issuer and subj.group(1).strip() == issuer.group(1).strip():
        specs.append(
            _spec(
                "nse-tls-self-signed",
                script,
                "Self-signed TLS certificate",
                f"{where} presents a self-signed certificate (subject == issuer: {_clip(subj.group(1), 100)}).",
                "medium",
                f"subject=issuer={_clip(subj.group(1), 100)}",
            )
        )
    bits_m = _BITS_RE.search(out)
    ktype = re.search(r"Public Key type:\s*(\w+)", out)
    if bits_m and ktype and ktype.group(1).lower() in {"rsa", "dsa"} and int(bits_m.group(1)) < 2048:
        specs.append(
            _spec(
                "nse-tls-weak-key",
                script,
                f"Weak TLS certificate key ({ktype.group(1).upper()} {bits_m.group(1)}-bit)",
                f"{where} certificate uses a {ktype.group(1).upper()} {bits_m.group(1)}-bit key (below 2048).",
                "medium",
                f"{ktype.group(1)} {bits_m.group(1)} bits",
            )
        )
    return specs


def _cvss_severity(score: str) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "medium"
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low"


def vulners_cves(output: str, elems: list[tuple[str, str]] | None = None) -> list[dict[str, str]]:
    """Extract CVE id + CVSS from a vulners NSE script (elem key=id/cvss or output text)."""
    found: dict[str, str] = {}
    pending_cve = ""
    pending_cvss = ""
    for key, value in elems or []:
        low = (key or "").lower()
        token = (value or "").strip()
        if low == "id" and token.upper().startswith("CVE-"):
            pending_cve = token.upper()
        elif low == "cvss":
            pending_cvss = token
        if pending_cve and pending_cvss:
            found.setdefault(pending_cve, pending_cvss)
            pending_cve, pending_cvss = "", ""
        elif pending_cve and low == "type" and token.lower() == "cve":
            found.setdefault(pending_cve, pending_cvss or "")
    if pending_cve:
        found.setdefault(pending_cve, pending_cvss)
    if not found:
        for match in _CVE_CVSS_RE.finditer(output or ""):
            found.setdefault(match.group(1).upper(), match.group(2))
        if not found:
            for match in _CVE_RE.finditer(output or ""):
                found.setdefault(match.group(1).upper(), "")
    rows = []
    for cve, cvss in found.items():
        rows.append({"cve": cve, "cvss": cvss, "severity": _cvss_severity(cvss) if cvss else "medium"})
    return rows


def nse_findings(
    name: str,
    addr: str,
    port: str,
    service: str,
    product: str,
    scripts: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Return misconfig specs for one port (or host scripts when port == '')."""
    where = f"{name} TCP/{port}" if port else name
    specs: list[dict[str, Any]] = []
    for sid, raw in scripts:
        out = str(raw or "")
        low = out.lower()
        if sid == "ftp-anon" and "anonymous ftp login allowed" in low:
            specs.append(_spec("nse-ftp-anon", sid, "Anonymous FTP login allowed",
                               f"{where} accepts anonymous FTP login (nmap ftp-anon, FTP code 230).",
                               "high", out.splitlines()[0] if out else ""))
        elif sid == "redis-info" and re.search(r"^\s*Version:\s*\S+", out, re.M):
            specs.append(_spec("nse-redis-noauth", sid, "Redis accessible without authentication",
                               f"{where} answered Redis INFO without credentials (nmap redis-info).",
                               "high", _clip(" ".join(l.strip() for l in out.splitlines()[:3]))))
        elif sid == "http-enum" and "directory listing" in low:
            paths = [l.split(":")[0].strip() for l in out.splitlines() if "directory listing" in l.lower()]
            specs.append(_spec("nse-http-dirlist", sid, "HTTP directory listing enabled",
                               f"{where} serves auto-generated directory listings at {', '.join(paths[:5])} (nmap http-enum).",
                               "medium", f"paths: {', '.join(paths[:5])}"))
        elif sid == "http-title" and out.strip().lower().startswith("index of /"):
            # Only when http-enum did not already report it for this port.
            if not any(s == "http-enum" and "directory listing" in str(o).lower() for s, o in scripts):
                specs.append(_spec("nse-http-dirlist", sid, "HTTP directory listing enabled",
                                   f"{where} serves an auto-generated directory index (title '{_clip(out, 60)}').",
                                   "medium", f"title: {_clip(out, 60)}"))
        elif sid == "ssl-enum-ciphers":
            specs.extend(_tls(where, sid, out))
        elif sid == "ssl-cert":
            specs.extend(_cert(where, sid, out))
        elif sid == "smb2-security-mode" and "not required" in low:
            specs.append(_spec("nse-smb-signing-not-required", sid, "SMB message signing not required",
                               f"{where} does not require SMB message signing (nmap smb2-security-mode), enabling NTLM relay.",
                               "medium", _clip(out)))
        elif sid == "smb-security-mode":
            if "message_signing: disabled" in low and not any(
                s == "smb2-security-mode" and "not required" in str(o).lower() for s, o in scripts
            ):
                specs.append(_spec("nse-smb-signing-not-required", sid, "SMB message signing not required",
                                   f"{where} has SMB message signing disabled (nmap smb-security-mode).",
                                   "medium", "message_signing: disabled"))
            if "account_used: guest" in low:
                specs.append(_spec("nse-smb-guest", sid, "SMB guest access allowed",
                                   f"{where} accepted an SMB session as guest (nmap smb-security-mode account_used=guest).",
                                   "medium", "account_used: guest"))
        elif sid in {"mysql-empty-password", "ms-sql-empty-password"} and "empty password" in low:
            accounts = [l.strip().split(" ")[0] for l in out.splitlines() if "empty password" in l.lower()]
            specs.append(_spec("nse-db-empty-password", sid, "Database account with empty password",
                               f"{where} database account(s) {', '.join(accounts)} accept an empty password ({sid}).",
                               "critical", f"accounts with empty password: {', '.join(accounts)}"))
        elif sid == "http-default-accounts":
            apps = re.findall(r"\[([^\]]+)\]\s+at\s+(\S+)", out)
            if apps:
                listing = "; ".join(f"{a} at {p}" for a, p in apps)
                specs.append(_spec("nse-default-credentials", sid, "Default credentials accepted",
                                   f"{where} accepts vendor default credentials for {listing} (nmap http-default-accounts; credentials redacted).",
                                   "critical", f"default creds valid for: {listing} [credentials redacted]"))
    return specs
