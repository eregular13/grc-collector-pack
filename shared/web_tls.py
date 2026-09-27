"""Parse recorded web/TLS probe snapshots into canonical findings.

Parse-only. Does not open sockets or probe the network.
Live probes live in shared.web_tls_live behind --live + signed SCOPE.

24 non-destructive check types from the frozen freedom45 env-eval sensors,
replayed against recorded HTTP/TLS/SSH snapshots. IDs use make_ref
(stable slug), never random identifiers or salted builtin hashing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from shared.io_util import iso_now, read_text
from shared.schema import make_record, make_ref, slug

SOURCE = "web-tls"
LABELS = ["web-tls", "env-eval"]
HONEST = (
    "This is a non-destructive web/TLS probe finding (signed-SCOPE live "
    "collector or recorded snapshot replay), not a file-drop scanner "
    "export and not a client KEEP stamp."
)
SCHEMA = "web_tls.probe.v1"

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

RISKY_PORTS: dict[int, tuple[str, str, str]] = {
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

DEFAULT_PAGES = [
    ("Welcome to nginx", "nginx default page"),
    ("Apache2 Ubuntu Default Page", "Apache default page"),
    ("IIS Windows Server", "IIS default page"),
    ("It works!", "generic default web page"),
    ("traceback (most recent call last)", "Python traceback"),
    ("Whitelabel Error Page", "Spring default error"),
]


def _now() -> str:
    return iso_now()


def _host_of(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlsplit(raw).hostname or raw.split("://", 1)[-1]
    return raw.split("/")[0].split(":")[0].strip().lower().rstrip(".")


def _ref(sensor: str, target: str, *parts: Any) -> str:
    key = "-".join(str(p) for p in (sensor, target, *parts) if p not in (None, ""))
    return make_ref(SOURCE, slug(key, maxlen=None))


def _finding(
    *,
    sensor: str,
    target: str,
    name: str,
    description: str,
    severity: str,
    category: str,
    extra: dict[str, Any],
    labels: list[str] | None = None,
    collected_at: str = "",
) -> dict[str, Any]:
    host = _host_of(target) or str(target)
    extra_out = {
        "check_id": sensor,
        "sensor": sensor,
        "finding_id": sensor,
        **extra,
    }
    if not extra_out.get("cis_v8_internal"):
        from shared.framework_class_map import cis_v8_internal_ids

        cis = cis_v8_internal_ids(sensor=sensor, title=name, description=description)
        if cis:
            extra_out["cis_v8_internal"] = cis
    labs = list(LABELS)
    for item in labels or []:
        if item and item not in labs:
            labs.append(item)
    return make_record(
        kind="finding",
        source=SOURCE,
        ref_id=_ref(
            sensor,
            host,
            extra.get("port"),
            extra.get("url"),
            extra.get("service"),
            extra.get("disclosure"),
            extra.get("fingerprint"),
        ),
        name=name,
        description=f"{description} {HONEST}",
        severity=severity,
        category=category,
        assets=[host] if host else [],
        labels=labs,
        collected_at=collected_at or _now(),
        extra=extra_out,
    )


def _headers(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in raw.items() if k}


def _http_row(snapshot: dict[str, Any], url: str) -> dict[str, Any]:
    block = snapshot.get("http")
    if not isinstance(block, dict):
        return {}
    row = block.get(url)
    return row if isinstance(row, dict) else {}


def _open_ports(snapshot: dict[str, Any]) -> list[int]:
    raw = snapshot.get("open_ports")
    if isinstance(raw, list):
        out: list[int] = []
        for item in raw:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                continue
        return out
    return []


def _tested_ports(snapshot: dict[str, Any]) -> list[int]:
    raw = snapshot.get("ports") or snapshot.get("tested_ports")
    if isinstance(raw, list) and raw:
        out: list[int] = []
        for item in raw:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                continue
        return out
    return _open_ports(snapshot)


def sense_surface(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    host = str(snapshot.get("target") or "")
    ports = _tested_ports(snapshot)
    open_ports = _open_ports(snapshot)
    if not open_ports:
        return []
    closedish = [p for p in ports if p not in open_ports]
    sev = "high" if any(p in open_ports for p in (22, 3389, 445, 23)) and 443 not in open_ports else "medium"
    if 22 in open_ports or 3389 in open_ports:
        sev = "medium"
    return [
        _finding(
            sensor="sense-surface",
            target=host,
            name=f"Open ports on {host}: {open_ports}",
            description=(
                f"Authorized TCP connect probe. Open={open_ports}. "
                f"Not responding (in set)={closedish}."
            ),
            severity=sev,
            category="exposure",
            extra={"open_ports": open_ports, "tested_ports": ports},
        )
    ]


def sense_http_headers(url: str, row: dict[str, Any]) -> list[dict[str, Any]]:
    err = str(row.get("error") or "").strip()
    if err and not row.get("status"):
        return [
            _finding(
                sensor="sense-http-headers",
                target=url,
                name=f"HTTP probe failed for {url}",
                description=err,
                severity="info",
                category="telemetry",
                extra={"url": url, "error": err},
                labels=["http", "probe-fail"],
            )
        ]
    headers = _headers(row.get("headers"))
    status = row.get("status")
    server = str(row.get("server") or headers.get("server") or "")
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    out: list[dict[str, Any]] = []
    if missing:
        sev = "high" if "content-security-policy" in missing or "strict-transport-security" in missing else "medium"
        out.append(
            _finding(
                sensor="sense-http-headers",
                target=url,
                name=f"Missing security headers on {url}",
                description=(
                    f"HTTP {status}; Server={server or 'n/a'}; missing={missing}."
                ),
                severity=sev,
                category="hardening",
                extra={
                    "url": url,
                    "status": status,
                    "server": server,
                    "missing": missing,
                    "present": sorted(set(headers) & set(SECURITY_HEADERS)),
                },
                labels=["headers", "web", "hardening"],
            )
        )
    if server and any(x in server.lower() for x in ("apache/", "nginx/", "iis/", "microsoft-iis")):
        out.append(
            _finding(
                sensor="sense-http-info",
                target=url,
                name=f"Server banner disclosed: {server}",
                description="Server header reveals stack/version useful for attackers.",
                severity="low",
                category="information-disclosure",
                extra={"url": url, "server": server, "status": status},
                labels=["banner", "information-disclosure"],
            )
        )
    return out


def sense_tls(host: str, port: int, row: dict[str, Any]) -> list[dict[str, Any]]:
    target = f"{host}:{port}"
    if row.get("open") is False:
        return [
            _finding(
                sensor="sense-tls",
                target=target,
                name=f"No TLS listener on {host}:{port}",
                description="Port closed or filtered. If HTTPS is expected, service may be HTTP-only.",
                severity="medium",
                category="tls",
                extra={"port": port, "open": False},
                labels=["tls", "availability"],
            )
        ]
    verify = str(row.get("verify_error") or "").strip()
    if verify:
        return [
            _finding(
                sensor="sense-tls",
                target=target,
                name=f"TLS certificate trust problem on {host}:{port}",
                description=verify,
                severity="high",
                category="tls",
                extra={"port": port, "error": verify},
                labels=["tls", "certificate"],
            )
        ]
    err = str(row.get("error") or "").strip()
    if err and not row.get("tls"):
        return [
            _finding(
                sensor="sense-tls",
                target=target,
                name=f"TLS probe error on {host}:{port}",
                description=err,
                severity="medium",
                category="tls",
                extra={"port": port, "error": err},
                labels=["tls", "error"],
            )
        ]
    out: list[dict[str, Any]] = [
        _finding(
            sensor="sense-tls",
            target=target,
            name=f"TLS accepted on {host}:{port}",
            description=f"Handshake OK. subject={row.get('subject') or 'n/a'}",
            severity="info",
            category="tls",
            extra={"port": port, "open": True, "tls": True, "cert_present": bool(row.get("cert_present", True))},
            labels=["tls", "ok"],
        )
    ]
    not_after = str(row.get("notAfter") or "").strip()
    days = row.get("days_remaining")
    if days is None and not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
        except ValueError:
            days = None
    if isinstance(days, int):
        if days < 0:
            sev, title = "critical", f"TLS certificate EXPIRED on {host}:{port}"
        elif days <= 14:
            sev, title = "high", f"TLS certificate expires in {days}d on {host}:{port}"
        elif days <= 30:
            sev, title = "medium", f"TLS certificate expires in {days}d on {host}:{port}"
        else:
            sev, title = "", ""
        if sev:
            out.append(
                _finding(
                    sensor="sense-tls-expiry",
                    target=target,
                    name=title,
                    description=f"notAfter={not_after}; days_remaining={days}.",
                    severity=sev,
                    category="tls",
                    extra={"port": port, "notAfter": not_after, "days_remaining": days},
                    labels=["tls", "certificate", "expiry"],
                )
            )
    return out


def sense_cookie_flags(url: str, row: dict[str, Any]) -> list[dict[str, Any]]:
    raw = row.get("set_cookie") or row.get("cookies") or []
    if not isinstance(raw, list) or not raw:
        return []
    weak = []
    for cookie in raw:
        cl = str(cookie).lower()
        issues = []
        if "httponly" not in cl:
            issues.append("missing_HttpOnly")
        if str(url).startswith("https://") and "secure" not in cl:
            issues.append("missing_Secure")
        if "samesite" not in cl:
            issues.append("missing_SameSite")
        if issues:
            weak.append({"cookie_prefix": str(cookie).split("=", 1)[0][:40], "issues": issues})
    if not weak:
        return []
    return [
        _finding(
            sensor="sense-cookie-flags",
            target=url,
            name=f"Weak cookie flags on {url}",
            description=f"{len(weak)} Set-Cookie header(s) lack Secure/HttpOnly/SameSite.",
            severity="medium",
            category="hardening",
            extra={"url": url, "weak_cookies": weak[:10], "count": len(weak)},
            labels=["cookies", "web", "session"],
        )
    ]


def sense_cors(url: str, row: dict[str, Any]) -> list[dict[str, Any]]:
    headers = _headers(row.get("headers"))
    acao = str(row.get("acao") or headers.get("access-control-allow-origin") or "").strip()
    acac = str(row.get("acac") or headers.get("access-control-allow-credentials") or "").strip().lower()
    if acao == "*":
        sev = "high" if acac == "true" else "medium"
        return [
            _finding(
                sensor="sense-cors",
                target=url,
                name=f"Permissive CORS ACAO=* on {url}",
                description=f"Access-Control-Allow-Origin=*; Allow-Credentials={acac or 'n/a'}.",
                severity=sev,
                category="hardening",
                extra={"url": url, "acao": acao, "acac": acac},
                labels=["cors", "web", "api"],
            )
        ]
    if acao and "evil.example" in acao:
        return [
            _finding(
                sensor="sense-cors",
                target=url,
                name=f"CORS reflects arbitrary Origin on {url}",
                description=f"Server reflected Origin evil.example as ACAO={acao}.",
                severity="high",
                category="hardening",
                extra={"url": url, "acao": acao},
                labels=["cors", "web", "api"],
            )
        ]
    return []


def sense_ssh_banner(host: str, port: int, row: dict[str, Any]) -> list[dict[str, Any]]:
    target = f"{host}:{port}"
    err = str(row.get("error") or "").strip()
    banner = str(row.get("banner") or "").strip()
    if err and not banner:
        return [
            _finding(
                sensor="sense-ssh-banner",
                target=target,
                name=f"SSH open but banner read failed on {host}:{port}",
                description=err,
                severity="info",
                category="telemetry",
                extra={"port": port, "error": err},
                labels=["ssh", "banner"],
            )
        ]
    if not banner:
        return []
    return [
        _finding(
            sensor="sense-ssh-banner",
            target=target,
            name=f"SSH service banner on {host}:{port}",
            description=f"Banner (no auth attempted): {banner[:120]}.",
            severity="low",
            category="exposure",
            extra={"port": port, "banner": banner[:200]},
            labels=["ssh", "banner", "exposure"],
        )
    ]


def sense_cleartext_admin(host: str, open_ports: list[int]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if 80 in open_ports and 443 not in open_ports:
        out.append(
            _finding(
                sensor="sense-cleartext-http",
                target=host,
                name=f"HTTP without HTTPS on {host}",
                description="Port 80 open and 443 closed/filtered in probe set — cleartext web exposure.",
                severity="high",
                category="tls",
                extra={"open_ports": open_ports},
                labels=["http", "cleartext", "tls"],
            )
        )
    if 21 in open_ports:
        out.append(
            _finding(
                sensor="sense-cleartext-ftp",
                target=f"{host}:21",
                name=f"FTP listener on {host}:21",
                description="FTP is cleartext credential/file transfer. Prefer SFTP/HTTPS.",
                severity="high",
                category="exposure",
                extra={"port": 21},
                labels=["ftp", "cleartext"],
            )
        )
    return out


def sense_http_methods(url: str, row: dict[str, Any]) -> list[dict[str, Any]]:
    allow = str(row.get("allow") or _headers(row.get("headers")).get("allow") or "").upper()
    if not allow:
        allow = str(_headers(row.get("headers")).get("access-control-allow-methods") or "").upper()
    status = row.get("status")
    dangerous = [m for m in ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT") if m in allow]
    if not dangerous:
        return []
    sev = "medium" if "TRACE" in dangerous or "TRACK" in dangerous else "low"
    return [
        _finding(
            sensor="sense-http-methods",
            target=url,
            name=f"Potentially dangerous HTTP methods allowed: {dangerous}",
            description=f"OPTIONS/Allow reported methods including {dangerous}. Status={status}.",
            severity=sev,
            category="hardening",
            extra={"url": url, "allow": allow, "status": status, "dangerous": dangerous},
            labels=["http", "methods", "misconfig"],
        )
    ]


def sense_tech_disclosure(url: str, row: dict[str, Any]) -> list[dict[str, Any]]:
    headers = _headers(row.get("headers"))
    body = str(row.get("body") or "")
    status = row.get("status")
    server = str(row.get("server") or headers.get("server") or "")
    powered = str(row.get("x_powered_by") or headers.get("x-powered-by") or "")
    out: list[dict[str, Any]] = []
    if server and any(c.isdigit() for c in server):
        out.append(
            _finding(
                sensor="sense-tech-disclosure",
                target=url,
                name=f"Server header discloses version: {server[:80]}",
                description="Detailed Server tokens aid targeted exploits.",
                severity="low",
                category="information-disclosure",
                extra={"url": url, "server": server, "status": status, "disclosure": "server-version"},
                labels=["http", "information-disclosure", "hardening"],
            )
        )
    if powered:
        out.append(
            _finding(
                sensor="sense-tech-disclosure",
                target=url,
                name=f"X-Powered-By disclosed: {powered[:80]}",
                description="Framework/runtime disclosure via X-Powered-By.",
                severity="low",
                category="information-disclosure",
                extra={"url": url, "x_powered_by": powered, "disclosure": "x-powered-by"},
                labels=["http", "information-disclosure"],
            )
        )
    low = body.lower()
    for needle, label in DEFAULT_PAGES:
        if needle.lower() in low:
            out.append(
                _finding(
                    sensor="sense-default-page",
                    target=url,
                    name=f"Possible default/error page: {label}",
                    description=f"Response body matched fingerprint for {label}.",
                    severity="medium",
                    category="misconfig",
                    extra={"url": url, "fingerprint": label, "status": status},
                    labels=["http", "default-content", "misconfig"],
                )
            )
            break
    return out


def sense_dir_listing(url: str, row: dict[str, Any]) -> list[dict[str, Any]]:
    body = str(row.get("body") or "")
    status = row.get("status")
    ctype = str(row.get("content_type") or _headers(row.get("headers")).get("content-type") or "")
    target = str(row.get("url") or url)
    if row.get("git_head") or (status == 200 and body.startswith("ref:")):
        return [
            _finding(
                sensor="sense-git-exposed",
                target=target,
                name="Exposed .git/HEAD over HTTP",
                description="Git metadata reachable via web — source and secrets risk.",
                severity="critical",
                category="exposure",
                extra={"url": target, "status": status, "sample": body[:80]},
                labels=["git", "exposure", "critical"],
            )
        ]
    if "index of /" in body.lower() or ("parent directory" in body.lower() and "href" in body.lower()):
        return [
            _finding(
                sensor="sense-dir-listing",
                target=target,
                name=f"Directory listing enabled: {target}",
                description="Open directory index can leak filenames and backups.",
                severity="medium",
                category="misconfig",
                extra={"url": target, "status": status, "content_type": ctype},
                labels=["http", "dir-listing", "misconfig"],
            )
        ]
    return []


def sense_service_ports(host: str, open_ports: list[int]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for port, (name, sev, rem) in RISKY_PORTS.items():
        if port in open_ports:
            out.append(
                _finding(
                    sensor="sense-service-exposure",
                    target=f"{host}:{port}",
                    name=f"{name} port {port} reachable on {host}",
                    description=f"TCP connect succeeded to {name} ({port}). Treat as exposure until proven segmented.",
                    severity=sev,
                    category="exposure",
                    extra={"port": port, "service": name, "remediation": rem},
                    labels=["exposure", "service", name.lower()],
                )
            )
    return out


def sense_http_to_https_redirect(host: str, open_ports: list[int], row: dict[str, Any] | None) -> list[dict[str, Any]]:
    if 80 not in open_ports or 443 not in open_ports or not row:
        return []
    status = row.get("redirect_status")
    if status is None:
        status = row.get("status")
    loc = str(row.get("location") or _headers(row.get("headers")).get("location") or "")
    if status in (301, 302, 307, 308) and loc.lower().startswith("https://"):
        return []
    url = f"http://{host}/"
    return [
        _finding(
            sensor="sense-http-https-redirect",
            target=url,
            name=f"HTTP does not redirect to HTTPS on {host}",
            description=f"Port 80 and 443 both open but HTTP response status={status} Location={loc!r}.",
            severity="medium",
            category="hardening",
            extra={"url": url, "status": status, "location": loc, "open_ports": open_ports},
            labels=["http", "https", "redirect", "misconfig"],
        )
    ]


def parse_snapshot(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn a recorded probe snapshot into canonical findings. No I/O."""
    if not isinstance(snapshot, dict):
        return []
    host = str(snapshot.get("target") or snapshot.get("host") or "")
    if not host:
        return []
    findings: list[dict[str, Any]] = []
    findings.extend(sense_surface(snapshot))
    open_ports = _open_ports(snapshot)
    findings.extend(sense_cleartext_admin(host, open_ports))
    http_block = snapshot.get("http") if isinstance(snapshot.get("http"), dict) else {}
    root_http = http_block.get(f"http://{host}/") if isinstance(http_block.get(f"http://{host}/"), dict) else None
    findings.extend(sense_http_to_https_redirect(host, open_ports, root_http))
    findings.extend(sense_service_ports(host, open_ports))
    ssh_block = snapshot.get("ssh") if isinstance(snapshot.get("ssh"), dict) else {}
    for port_s, row in ssh_block.items():
        if isinstance(row, dict):
            try:
                port = int(port_s)
            except (TypeError, ValueError):
                port = 22
            findings.extend(sense_ssh_banner(host, port, row))
    for url, row in http_block.items():
        if not isinstance(row, dict):
            continue
        if row.get("kind") == "dir" or row.get("git_head") or str(url).endswith("/.git/HEAD"):
            findings.extend(sense_dir_listing(str(url), row))
            continue
        findings.extend(sense_http_headers(str(url), row))
        findings.extend(sense_cookie_flags(str(url), row))
        findings.extend(sense_cors(str(url), row))
        findings.extend(sense_http_methods(str(url), row))
        findings.extend(sense_tech_disclosure(str(url), row))
        if row.get("body") and ("index of /" in str(row.get("body")).lower() or "parent directory" in str(row.get("body")).lower()):
            findings.extend(sense_dir_listing(str(url), row))
    tls_block = snapshot.get("tls") if isinstance(snapshot.get("tls"), dict) else {}
    for port_s, row in tls_block.items():
        if not isinstance(row, dict):
            continue
        try:
            port = int(port_s)
        except (TypeError, ValueError):
            continue
        findings.extend(sense_tls(host, port, row))
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for rec in findings:
        rid = str(rec.get("ref_id") or "")
        if rid in seen:
            continue
        seen.add(rid)
        out.append(rec)
    return out


def parse_file(path: Path) -> list[dict[str, Any]]:
    raw = read_text(path).lstrip("\ufeff").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        rows: list[dict[str, Any]] = []
        for item in data:
            if isinstance(item, dict):
                rows.extend(parse_snapshot(item))
        return rows
    if not isinstance(data, dict):
        return []
    if data.get("schema") in {SCHEMA, "web_tls.probe.v1", "grc.web_tls.probe.v1"}:
        return parse_snapshot(data)
    if isinstance(data.get("snapshot"), dict):
        return parse_snapshot(data["snapshot"])
    if data.get("target") or data.get("host"):
        return parse_snapshot(data)
    return []


PORTED_SENSORS = (
    "sense-surface",
    "sense-http-headers",
    "sense-http-info",
    "sense-tls",
    "sense-tls-expiry",
    "sense-cookie-flags",
    "sense-cors",
    "sense-ssh-banner",
    "sense-cleartext-http",
    "sense-cleartext-ftp",
    "sense-http-methods",
    "sense-tech-disclosure",
    "sense-default-page",
    "sense-dir-listing",
    "sense-git-exposed",
    "sense-service-exposure",
    "sense-http-https-redirect",
)
