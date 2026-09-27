"""Sensory organs — non-destructive client surface probes."""
from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def sense_surface(host: str, ports: list[int]) -> list[dict[str, Any]]:
    open_ports = [p for p in ports if _tcp_open(host, p)]
    closedish = [p for p in ports if p not in open_ports]
    findings = []
    if open_ports:
        sev = "high" if any(p in open_ports for p in (22, 3389, 445, 23)) and 443 not in open_ports else "medium"
        if 22 in open_ports or 3389 in open_ports:
            sev = "medium"
        findings.append(
            {
                "id": f"surf-{uuid4().hex[:10]}",
                "sensor": "sense-surface",
                "source": "sensory-organs",
                "target": host,
                "title": f"Open ports on {host}: {open_ports}",
                "description": (
                    f"Authorized TCP connect probe. Open={open_ports}. "
                    f"Not responding (in set)={closedish}. "
                    "Map exposure to asset inventory and need-for-access."
                ),
                "severity": sev,
                "evidence": {"open_ports": open_ports, "tested_ports": ports},
                "tags": ["surface", "network", "exposure"],
                "controls": {
                    "CIS": ["CIS-16.2"],
                    "NIST_CSF": ["ID.AM-1", "PR.AC-5"],
                    "ISO27001": ["A.8.20", "A.5.15"],
                    "NIST_800_53": ["CM-7", "AC-4"],
                },
                "remediation": "Close unused listeners; restrict admin ports to jump hosts/VPN; document exceptions.",
            }
        )
    return findings


def sense_http_headers(url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Evergreen-env-eval/0.1"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            status = resp.status
            headers = {k.lower(): v for k, v in resp.headers.items()}
            server = headers.get("server", "")
    except urllib.error.HTTPError as e:
        status = e.code
        headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        server = headers.get("server", "")
    except Exception as e:  # noqa: BLE001
        findings.append(
            {
                "id": f"http-{uuid4().hex[:10]}",
                "sensor": "sense-http-headers",
                "source": "sensory-organs",
                "target": url,
                "title": f"HTTP probe failed for {url}",
                "description": f"{type(e).__name__}: {e}",
                "severity": "info",
                "evidence": {"error": str(e)},
                "tags": ["http", "probe-fail"],
                "controls": {},
                "remediation": "Confirm URL in scope and service is reachable during window.",
            }
        )
        return findings

    missing = [h for h in SECURITY_HEADERS if h not in headers]
    if missing:
        findings.append(
            {
                "id": f"hdr-{uuid4().hex[:10]}",
                "sensor": "sense-http-headers",
                "source": "sensory-organs",
                "target": url,
                "title": f"Missing security headers on {url}",
                "description": (
                    f"HTTP {status}; Server={server or 'n/a'}; missing={missing}. "
                    "Baseline edge/app headers reduce clickjacking, MIME sniffing, and downgrade risk."
                ),
                "severity": "high" if "content-security-policy" in missing or "strict-transport-security" in missing else "medium",
                "evidence": {"status": status, "server": server, "missing": missing, "present": sorted(set(headers) & set(SECURITY_HEADERS))},
                "tags": ["headers", "web", "hardening"],
                "controls": {
                    "CIS": ["CIS-16.11"],
                    "NIST_CSF": ["PR.PT-3", "PR.DS-2"],
                    "ISO27001": ["A.8.20", "A.8.24"],
                    "NIST_800_53": ["SC-7", "SC-8"],
                },
                "remediation": "Add HSTS (HTTPS), CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.",
            }
        )
    if server and any(x in server.lower() for x in ("apache/", "nginx/", "iis/", "microsoft-iis")):
        findings.append(
            {
                "id": f"bann-{uuid4().hex[:10]}",
                "sensor": "sense-http-info",
                "source": "sensory-organs",
                "target": url,
                "title": f"Server banner disclosed: {server}",
                "description": "Server header reveals stack/version useful for attackers. Prefer generic or omit.",
                "severity": "low",
                "evidence": {"server": server, "status": status},
                "tags": ["banner", "information-disclosure"],
                "controls": {"CIS": ["CIS-16.11"], "NIST_CSF": ["PR.PT-3"], "ISO27001": ["A.8.9"]},
                "remediation": "Suppress or genericize Server/X-Powered-By headers at reverse proxy.",
            }
        )
    return findings


def sense_tls(host: str, port: int = 443) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not _tcp_open(host, port):
        findings.append(
            {
                "id": f"tls-{uuid4().hex[:10]}",
                "sensor": "sense-tls",
                "source": "sensory-organs",
                "target": f"{host}:{port}",
                "title": f"No TLS listener on {host}:{port}",
                "description": "Port closed or filtered. If HTTPS is expected, service may be down or HTTP-only.",
                "severity": "medium",
                "evidence": {"port": port, "open": False},
                "tags": ["tls", "availability"],
                "controls": {"NIST_CSF": ["PR.DS-2"], "ISO27001": ["A.8.24"], "NIST_800_53": ["SC-8"]},
                "remediation": "Enable TLS on public web endpoints; redirect HTTP→HTTPS.",
            }
        )
        return findings
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                findings.append(
                    {
                        "id": f"tls-{uuid4().hex[:10]}",
                        "sensor": "sense-tls",
                        "source": "sensory-organs",
                        "target": f"{host}:{port}",
                        "title": f"TLS accepted on {host}:{port}",
                        "description": f"Handshake OK. subject={cert.get('subject') if cert else 'n/a'}",
                        "severity": "info",
                        "evidence": {"port": port, "open": True, "tls": True, "cert_present": bool(cert)},
                        "tags": ["tls", "ok"],
                        "controls": {},
                        "remediation": "n/a — maintain cert lifecycle and modern ciphers.",
                    }
                )
                # cert expiry window
                if cert and cert.get("notAfter"):
                    try:
                        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days = (exp - datetime.now(timezone.utc)).days
                        if days < 0:
                            sev, title = "critical", f"TLS certificate EXPIRED on {host}:{port}"
                        elif days <= 14:
                            sev, title = "high", f"TLS certificate expires in {days}d on {host}:{port}"
                        elif days <= 30:
                            sev, title = "medium", f"TLS certificate expires in {days}d on {host}:{port}"
                        else:
                            sev, title = None, None
                        if sev:
                            findings.append(
                                {
                                    "id": f"tlse-{uuid4().hex[:10]}",
                                    "sensor": "sense-tls-expiry",
                                    "source": "sensory-organs",
                                    "target": f"{host}:{port}",
                                    "title": title,
                                    "description": f"notAfter={cert.get('notAfter')}; days_remaining={days}. Short-lived or expired certs cause outages and MITM risk during renewal gaps.",
                                    "severity": sev,
                                    "evidence": {"notAfter": cert.get("notAfter"), "days_remaining": days, "port": port},
                                    "tags": ["tls", "certificate", "expiry"],
                                    "controls": {
                                        "NIST_CSF": ["PR.DS-2"],
                                        "ISO27001": ["A.8.24"],
                                        "NIST_800_53": ["SC-17"],
                                    },
                                    "remediation": "Automate certificate renewal (e.g. ACME); alert at 30/14 days; verify chain after renew.",
                                }
                            )
                    except Exception:
                        pass
    except ssl.SSLCertVerificationError as e:
        findings.append(
            {
                "id": f"tls-{uuid4().hex[:10]}",
                "sensor": "sense-tls",
                "source": "sensory-organs",
                "target": f"{host}:{port}",
                "title": f"TLS certificate trust problem on {host}:{port}",
                "description": str(e),
                "severity": "high",
                "evidence": {"error": str(e), "port": port},
                "tags": ["tls", "certificate"],
                "controls": {"NIST_CSF": ["PR.DS-2"], "ISO27001": ["A.8.24"], "NIST_800_53": ["SC-17"]},
                "remediation": "Install valid publicly trusted cert; fix hostname mismatch; automate renewal.",
            }
        )
    except Exception as e:  # noqa: BLE001
        findings.append(
            {
                "id": f"tls-{uuid4().hex[:10]}",
                "sensor": "sense-tls",
                "source": "sensory-organs",
                "target": f"{host}:{port}",
                "title": f"TLS probe error on {host}:{port}",
                "description": f"{type(e).__name__}: {e}",
                "severity": "medium",
                "evidence": {"error": str(e)},
                "tags": ["tls", "error"],
                "controls": {"NIST_CSF": ["PR.DS-2"]},
                "remediation": "Investigate TLS configuration and cipher suite support.",
            }
        )
    return findings



def sense_cookie_flags(url: str) -> list[dict[str, Any]]:
    """Flag Set-Cookie without Secure/HttpOnly/SameSite on HTTP(S) responses."""
    findings: list[dict[str, Any]] = []
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Evergreen-env-eval/0.2"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.headers.get_all("Set-Cookie") or []
    except Exception:
        return findings
    if not raw:
        return findings
    weak = []
    for c in raw:
        cl = c.lower()
        issues = []
        if "httponly" not in cl:
            issues.append("missing_HttpOnly")
        if url.startswith("https://") and "secure" not in cl:
            issues.append("missing_Secure")
        if "samesite" not in cl:
            issues.append("missing_SameSite")
        if issues:
            weak.append({"cookie_prefix": c.split("=", 1)[0][:40], "issues": issues})
    if weak:
        findings.append(
            {
                "id": f"ck-{uuid4().hex[:10]}",
                "sensor": "sense-cookie-flags",
                "source": "sensory-organs",
                "target": url,
                "title": f"Weak cookie flags on {url}",
                "description": f"{len(weak)} Set-Cookie header(s) lack Secure/HttpOnly/SameSite. Session cookies without these flags raise theft/CSRF risk.",
                "severity": "medium",
                "evidence": {"weak_cookies": weak[:10], "count": len(weak)},
                "tags": ["cookies", "web", "session"],
                "controls": {
                    "CIS": ["CIS-16.11"],
                    "NIST_CSF": ["PR.AC-1", "PR.DS-2"],
                    "ISO27001": ["A.8.24", "A.5.17"],
                    "NIST_800_53": ["SC-23", "AC-12"],
                },
                "remediation": "Set HttpOnly; Secure on HTTPS; SameSite=Lax or Strict as appropriate.",
            }
        )
    return findings


def sense_cors(url: str) -> list[dict[str, Any]]:
    """Detect overly permissive Access-Control-Allow-Origin."""
    findings: list[dict[str, Any]] = []
    try:
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": "Evergreen-env-eval/0.2", "Origin": "https://evil.example"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            acao = (resp.headers.get("Access-Control-Allow-Origin") or "").strip()
            acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
    except Exception:
        return findings
    if acao == "*":
        sev = "high" if acac == "true" else "medium"
        findings.append(
            {
                "id": f"cors-{uuid4().hex[:10]}",
                "sensor": "sense-cors",
                "source": "sensory-organs",
                "target": url,
                "title": f"Permissive CORS ACAO=* on {url}",
                "description": f"Access-Control-Allow-Origin=*; Allow-Credentials={acac or 'n/a'}. Wildcard CORS can enable cross-origin data reads depending on API design.",
                "severity": sev,
                "evidence": {"acao": acao, "acac": acac},
                "tags": ["cors", "web", "api"],
                "controls": {
                    "CIS": ["CIS-16.11"],
                    "NIST_CSF": ["PR.AC-3", "PR.PT-3"],
                    "ISO27001": ["A.8.20"],
                    "NIST_800_53": ["AC-3", "SC-7"],
                },
                "remediation": "Reflect only trusted origins; never combine ACAO=* with credentials.",
            }
        )
    elif acao and "evil.example" in acao:
        findings.append(
            {
                "id": f"cors-{uuid4().hex[:10]}",
                "sensor": "sense-cors",
                "source": "sensory-organs",
                "target": url,
                "title": f"CORS reflects arbitrary Origin on {url}",
                "description": f"Server reflected Origin evil.example as ACAO={acao}. Indicates dynamic reflection without allowlist.",
                "severity": "high",
                "evidence": {"acao": acao},
                "tags": ["cors", "web", "api"],
                "controls": {"NIST_CSF": ["PR.AC-3"], "NIST_800_53": ["AC-3", "SC-7"]},
                "remediation": "Allowlist trusted origins only; do not reflect Origin blindly.",
            }
        )
    return findings


def sense_ssh_banner(host: str, port: int = 22) -> list[dict[str, Any]]:
    """Read SSH banner only — no auth, no user enum."""
    findings: list[dict[str, Any]] = []
    if not _tcp_open(host, port, timeout=2.0):
        return findings
    banner = ""
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.settimeout(3.0)
            data = s.recv(256)
            banner = data.decode("utf-8", errors="replace").strip()
    except OSError as e:
        findings.append(
            {
                "id": f"ssh-{uuid4().hex[:10]}",
                "sensor": "sense-ssh-banner",
                "source": "sensory-organs",
                "target": f"{host}:{port}",
                "title": f"SSH open but banner read failed on {host}:{port}",
                "description": str(e),
                "severity": "info",
                "evidence": {"error": str(e)},
                "tags": ["ssh", "banner"],
                "controls": {},
                "remediation": "Confirm SSH is required; restrict by ACL.",
            }
        )
        return findings
    sev = "low"
    if any(x in banner.lower() for x in ("ubuntu", "debian", "openssh_7.", "openssh_6.")):
        sev = "low"
    findings.append(
        {
            "id": f"ssh-{uuid4().hex[:10]}",
            "sensor": "sense-ssh-banner",
            "source": "sensory-organs",
            "target": f"{host}:{port}",
            "title": f"SSH service banner on {host}:{port}",
            "description": f"Banner (no auth attempted): {banner[:120]}. Version disclosure aids targeted exploits; restrict exposure.",
            "severity": sev,
            "evidence": {"banner": banner[:200], "port": port},
            "tags": ["ssh", "banner", "exposure"],
            "controls": {
                "CIS": ["CIS-5.2"],
                "NIST_CSF": ["PR.AC-5", "PR.PT-3"],
                "ISO27001": ["A.8.20", "A.8.9"],
                "NIST_800_53": ["CM-7", "AC-17"],
            },
            "remediation": "Limit SSH to management networks; disable password auth; keep OpenSSH current; consider banner obfuscation only as defense-in-depth.",
        }
    )
    return findings


def sense_cleartext_admin(host: str, open_ports: list[int]) -> list[dict[str, Any]]:
    """High signal: admin protocols without TLS companion."""
    findings: list[dict[str, Any]] = []
    if 80 in open_ports and 443 not in open_ports:
        findings.append(
            {
                "id": f"clr-{uuid4().hex[:10]}",
                "sensor": "sense-cleartext-http",
                "source": "sensory-organs",
                "target": host,
                "title": f"HTTP without HTTPS on {host}",
                "description": "Port 80 open and 443 closed/filtered in probe set — cleartext web exposure.",
                "severity": "high",
                "evidence": {"open_ports": open_ports},
                "tags": ["http", "cleartext", "tls"],
                "controls": {"NIST_CSF": ["PR.DS-2"], "ISO27001": ["A.8.24"], "NIST_800_53": ["SC-8"]},
                "remediation": "Terminate TLS; redirect HTTP→HTTPS; HSTS.",
            }
        )
    if 21 in open_ports:
        findings.append(
            {
                "id": f"ftp-{uuid4().hex[:10]}",
                "sensor": "sense-cleartext-ftp",
                "source": "sensory-organs",
                "target": f"{host}:21",
                "title": f"FTP listener on {host}:21",
                "description": "FTP is cleartext credential/file transfer. Prefer SFTP/HTTPS.",
                "severity": "high",
                "evidence": {"port": 21},
                "tags": ["ftp", "cleartext"],
                "controls": {"NIST_CSF": ["PR.DS-2"], "NIST_800_53": ["SC-8"]},
                "remediation": "Disable FTP; use SFTP or managed transfer.",
            }
        )
    return findings



def sense_http_methods(url: str) -> list[dict[str, Any]]:
    """OPTIONS/TRACE method exposure (non-destructive)."""
    findings: list[dict[str, Any]] = []
    try:
        req = urllib.request.Request(url, method="OPTIONS", headers={"User-Agent": "Evergreen-env-eval/0.1"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            allow = (resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods") or "").upper()
            status = resp.status
    except urllib.error.HTTPError as e:
        allow = (e.headers.get("Allow") or "") if e.headers else ""
        allow = allow.upper()
        status = e.code
    except Exception:
        return findings
    dangerous = [m for m in ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT") if m in allow]
    if dangerous:
        findings.append(
            {
                "id": f"meth-{uuid4().hex[:10]}",
                "sensor": "sense-http-methods",
                "source": "sensory-organs",
                "target": url,
                "title": f"Potentially dangerous HTTP methods allowed: {dangerous}",
                "description": f"OPTIONS/Allow reported methods including {dangerous}. Status={status}. Validate need; disable TRACE/TRACK; restrict write verbs.",
                "severity": "medium" if "TRACE" in dangerous or "TRACK" in dangerous else "low",
                "evidence": {"allow": allow, "status": status, "dangerous": dangerous},
                "tags": ["http", "methods", "misconfig"],
                "controls": {"NIST_CSF": ["PR.PT-3"], "NIST_800_53": ["CM-7"], "CIS": ["CIS-5.2"]},
                "remediation": "Disable TRACE/TRACK; allow only required methods; block PUT/DELETE at edge if unused.",
            }
        )
    return findings


def sense_tech_disclosure(url: str) -> list[dict[str, Any]]:
    """Server/powered-by/version leakage and default app fingerprints."""
    findings: list[dict[str, Any]] = []
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Evergreen-env-eval/0.1"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(4096).decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        body = (e.read(4096) if hasattr(e, "read") else b"").decode("utf-8", errors="replace")
        status = e.code
    except Exception:
        return findings
    server = headers.get("server") or ""
    powered = headers.get("x-powered-by") or ""
    if server and any(c.isdigit() for c in server):
        findings.append(
            {
                "id": f"tech-{uuid4().hex[:10]}",
                "sensor": "sense-tech-disclosure",
                "source": "sensory-organs",
                "target": url,
                "title": f"Server header discloses version: {server[:80]}",
                "description": "Detailed Server tokens aid targeted exploits. Prefer generic tokens or omit.",
                "severity": "low",
                "evidence": {"server": server, "status": status},
                "tags": ["http", "information-disclosure", "hardening"],
                "controls": {"NIST_CSF": ["PR.PT-3"], "CIS": ["CIS-5.2"]},
                "remediation": "Strip or generalize Server header at reverse proxy.",
            }
        )
    if powered:
        findings.append(
            {
                "id": f"pow-{uuid4().hex[:10]}",
                "sensor": "sense-tech-disclosure",
                "source": "sensory-organs",
                "target": url,
                "title": f"X-Powered-By disclosed: {powered[:80]}",
                "description": "Framework/runtime disclosure via X-Powered-By.",
                "severity": "low",
                "evidence": {"x_powered_by": powered},
                "tags": ["http", "information-disclosure"],
                "controls": {"NIST_CSF": ["PR.PT-3"]},
                "remediation": "Remove X-Powered-By in app/server config.",
            }
        )
    # default pages / stack traces hints
    markers = [
        ("Welcome to nginx", "nginx default page"),
        ("Apache2 Ubuntu Default Page", "Apache default page"),
        ("IIS Windows Server", "IIS default page"),
        ("It works!", "generic default web page"),
        ("traceback (most recent call last)", "Python traceback"),
        ("Whitelabel Error Page", "Spring default error"),
    ]
    low = body.lower()
    for needle, label in markers:
        if needle.lower() in low:
            findings.append(
                {
                    "id": f"def-{uuid4().hex[:10]}",
                    "sensor": "sense-default-page",
                    "source": "sensory-organs",
                    "target": url,
                    "title": f"Possible default/error page: {label}",
                    "description": f"Response body matched fingerprint for {label}. May indicate unfinished deploy or verbose errors.",
                    "severity": "medium",
                    "evidence": {"fingerprint": label, "status": status},
                    "tags": ["http", "default-content", "misconfig"],
                    "controls": {"NIST_CSF": ["PR.IP-1"], "ISO27001": ["A.8.9"]},
                    "remediation": "Replace defaults with app content; custom error pages; no stack traces to clients.",
                }
            )
            break
    return findings


def sense_dir_listing(url: str) -> list[dict[str, Any]]:
    """Heuristic directory listing detection on common paths."""
    findings: list[dict[str, Any]] = []
    base = url if url.endswith("/") else url.rsplit("/", 1)[0] + "/"
    paths = ["", "static/", "assets/", "uploads/", "files/", ".git/HEAD"]
    for rel in paths:
        u = base + rel if not rel.startswith("http") else rel
        if rel == ".git/HEAD":
            # try origin root
            root = url.split("/", 3)
            if len(root) >= 3:
                u = "/".join(root[:3]) + "/.git/HEAD"
        try:
            req = urllib.request.Request(u, method="GET", headers={"User-Agent": "Evergreen-env-eval/0.1"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read(2048).decode("utf-8", errors="replace")
                status = resp.status
                ctype = (resp.headers.get("Content-Type") or "").lower()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            try:
                body = e.read(2048).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            status = e.code
            ctype = ""
        except Exception:
            continue
        if rel == ".git/HEAD" and status == 200 and body.startswith("ref:"):
            findings.append(
                {
                    "id": f"git-{uuid4().hex[:10]}",
                    "sensor": "sense-git-exposed",
                    "source": "sensory-organs",
                    "target": u,
                    "title": "Exposed .git/HEAD over HTTP",
                    "description": "Git metadata reachable via web — source and secrets risk.",
                    "severity": "critical",
                    "evidence": {"status": status, "sample": body[:80]},
                    "tags": ["git", "exposure", "critical"],
                    "controls": {"NIST_CSF": ["PR.DS-1", "PR.AC-4"], "NIST_800_53": ["AC-3", "CM-7"]},
                    "remediation": "Block /.git at edge; remove VCS dirs from web root.",
                }
            )
            continue
        if "index of /" in body.lower() or ("parent directory" in body.lower() and "href" in body.lower()):
            findings.append(
                {
                    "id": f"dir-{uuid4().hex[:10]}",
                    "sensor": "sense-dir-listing",
                    "source": "sensory-organs",
                    "target": u,
                    "title": f"Directory listing enabled: {u}",
                    "description": "Open directory index can leak filenames and backups.",
                    "severity": "medium",
                    "evidence": {"status": status, "content_type": ctype},
                    "tags": ["http", "dir-listing", "misconfig"],
                    "controls": {"CIS": ["CIS-5.2"], "NIST_800_53": ["CM-7"]},
                    "remediation": "Disable autoindex/directory browsing; deny listing in nginx/apache.",
                }
            )
    return findings


def sense_service_ports(host: str, ports: list[int]) -> list[dict[str, Any]]:
    """High-risk service exposure (connect-only)."""
    findings: list[dict[str, Any]] = []
    risky = {
        23: ("Telnet", "critical", "Disable telnet; use SSH."),
        445: ("SMB", "high", "Do not expose SMB to untrusted networks; require VPN."),
        3389: ("RDP", "high", "Restrict RDP to jump hosts; MFA; NLA."),
        3306: ("MySQL", "high", "Bind to localhost/private; require TLS auth."),
        5432: ("PostgreSQL", "high", "Do not expose Postgres publicly."),
        6379: ("Redis", "critical", "Redis without ACL on network is often full compromise."),
        27017: ("MongoDB", "critical", "Do not expose Mongo publicly."),
        9200: ("Elasticsearch", "high", "Require auth; private network only."),
        11211: ("Memcached", "high", "Do not expose memcached to Internet."),
        5900: ("VNC", "high", "Tunnel VNC; require strong auth."),
    }
    open_ports = [p for p in ports if _tcp_open(host, p)]
    for port, (name, sev, rem) in risky.items():
        if port in open_ports:
            findings.append(
                {
                    "id": f"svc-{uuid4().hex[:10]}",
                    "sensor": "sense-service-exposure",
                    "source": "sensory-organs",
                    "target": f"{host}:{port}",
                    "title": f"{name} port {port} reachable on {host}",
                    "description": f"TCP connect succeeded to {name} ({port}). Treat as exposure until proven segmented.",
                    "severity": sev,
                    "evidence": {"port": port, "service": name},
                    "tags": ["exposure", "service", name.lower()],
                    "controls": {"NIST_CSF": ["PR.AC-5"], "NIST_800_53": ["CM-7", "SC-7"], "CIS": ["CIS-16.2"]},
                    "remediation": rem,
                }
            )
    return findings



def sense_http_to_https_redirect(host: str, open_ports: list[int]) -> list[dict[str, Any]]:
    """If both 80 and 443 open, check whether HTTP redirects to HTTPS."""
    findings: list[dict[str, Any]] = []
    if 80 not in open_ports or 443 not in open_ports:
        return findings
    url = f"http://{host}/"
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Evergreen-env-eval/0.1"})
        # do not follow redirects automatically for status check — urlopen follows by default
        class NoRedir(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N803
                return None
        opener = urllib.request.build_opener(NoRedir)
        try:
            resp = opener.open(req, timeout=6)
            status = getattr(resp, "status", None) or resp.getcode()
            loc = ""
        except urllib.error.HTTPError as e:
            status = e.code
            loc = (e.headers.get("Location") if e.headers else "") or ""
        except Exception:
            return findings
        if status in (301, 302, 307, 308) and loc.lower().startswith("https://"):
            return findings  # good
        findings.append(
            {
                "id": f"redir-{uuid4().hex[:10]}",
                "sensor": "sense-http-https-redirect",
                "source": "sensory-organs",
                "target": url,
                "title": f"HTTP does not redirect to HTTPS on {host}",
                "description": f"Port 80 and 443 both open but HTTP response status={status} Location={loc!r}. Prefer forced HTTPS redirect + HSTS.",
                "severity": "medium",
                "evidence": {"status": status, "location": loc, "open_ports": open_ports},
                "tags": ["http", "https", "redirect", "misconfig"],
                "controls": {"NIST_CSF": ["PR.DS-2"], "NIST_800_53": ["SC-8", "SC-7"], "CIS": ["CIS-3.3"]},
                "remediation": "Configure edge/app to 301/302 HTTP→HTTPS and enable HSTS.",
            }
        )
    except Exception:
        return findings
    return findings


def collect(
    target: str,
    *,
    ports: list[int] | None = None,
    http_urls: list[str] | None = None,
    engagement_id: str = "",
) -> dict[str, Any]:
    ports = ports or [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200, 3389, 445]
    urls = list(http_urls or [f"http://{target}/"])
    # auto-add common HTTP URLs for open web ports
    if 8080 in ports and f"http://{target}:8080/" not in urls:
        urls.append(f"http://{target}:8080/")
    if 8443 in ports and f"https://{target}:8443/" not in urls:
        urls.append(f"https://{target}:8443/")
    if 443 in ports and f"https://{target}/" not in urls:
        urls.append(f"https://{target}/")
    findings: list[dict[str, Any]] = []
    findings.extend(sense_surface(target, ports))
    open_ports = [p for p in ports if _tcp_open(target, p)]
    findings.extend(sense_cleartext_admin(target, open_ports))
    findings.extend(sense_http_to_https_redirect(target, open_ports))
    findings.extend(sense_service_ports(target, ports))
    if 22 in ports:
        findings.extend(sense_ssh_banner(target, 22))
    for u in urls:
        findings.extend(sense_http_headers(u))
        findings.extend(sense_cookie_flags(u))
        findings.extend(sense_cors(u))
        findings.extend(sense_http_methods(u))
        findings.extend(sense_tech_disclosure(u))
        findings.extend(sense_dir_listing(u))
    if 443 in ports:
        findings.extend(sense_tls(target, 443))
    if 8443 in ports:
        findings.extend(sense_tls(target, 8443))
    return {
        "schema": "evergreen.client_env_eval.export.v1",
        "assessment_id": engagement_id or f"assess-{uuid4().hex[:10]}",
        "client_target": target,
        "scan_mode": "real",
        "sensors": sorted({f["sensor"] for f in findings}),
        "status": "completed",
        "findings": findings,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "method_limits": (
            "TCP connect + HTTP headers/cookies/CORS/methods/tech/dir + TLS + SSH banner + service exposure only — "
            "no exploit, brute, or credential use"
        ),
    }


def write_export(data: dict[str, Any], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return p
