"""Live web/TLS probes. Default off. Signed SCOPE only. No RiskReady POST.

Collectors never import this module. Tests monkeypatch transports — no internet.

Every connect is fail-closed: bare host/IP target, parsed URLs only (http/https,
no userinfo), port in 1..65535 and in SCOPE, resolved IP re-checked and pinned.
Redirects are never followed. Pack DEMO SCOPE (path, DEMO consent digest,
or the pack DEMO client.name) is refused. The gate lives on the shared
connect path so ``build_snapshot`` cannot skip it. SCOPE is re-read
before every connect. Direct ``authorize_endpoint`` calls unbind after.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import socket
import ssl
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from dropbox.scope import (
    GateError,
    attestation_digest,
    load_scope,
    require_live_probe,
    resolve_attestation_path,
)
from dropbox.yaml_lite import load_yaml
from shared.io_util import estate_hint, root_dir, write_canonical, write_json
from shared.web_tls import SOURCE, parse_snapshot

_ACTIVE_SCOPE = None

# LF SHA-256 of dropbox/consent/DEMO-WRITTEN-CONSENT.md (also stamped on
# dropbox/SCOPE.yaml). Live mode refuses this digest regardless of filename.
PACK_DEMO_CONSENT_SHA256 = "ab5fb87300b944e1a95216ffa65f9ab697e5daba01012c23019b3608a2bc207c"
# Exact client.name from dropbox/SCOPE.yaml (em dash). Live mode refuses it
# even when the consent digest/path are not the pack DEMO files.
PACK_DEMO_CLIENT_NAME = "DEMO — not a client estate"


class LiveRefuse(SystemExit):
    """Live web/TLS refused. Exit non-zero."""

    def __init__(self, message: str) -> None:
        super().__init__(f"web-tls live: {message}")


DEFAULT_PORTS = [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200, 3389, 445, 21, 23]
HTTP_SCHEMES = frozenset({"http", "https"})
SCHEME_DEFAULT_PORT = {"http": 80, "https": 443}


@contextmanager
def _bind_scope(scope: Any) -> Iterator[None]:
    global _ACTIVE_SCOPE
    prev = _ACTIVE_SCOPE
    _ACTIVE_SCOPE = scope
    try:
        yield
    finally:
        _ACTIVE_SCOPE = prev


def is_bare_host(target: str) -> bool:
    """True for a host name or IP only — no URL, userinfo, path, or host:port."""
    raw = str(target or "")
    if not raw or raw != raw.strip() or any(c.isspace() for c in raw):
        return False
    raw = raw.strip()
    if any(tok in raw for tok in ("://", "/", "@", "\\", "?")):
        return False
    if raw.startswith("[") and raw.endswith("]"):
        return False
    if ":" in raw:
        return False
    return True


def parse_http_url(url: str) -> tuple[str, int, str, str]:
    """Return (host, port, scheme, path). Refuse userinfo and non-http(s)."""
    raw = str(url or "").strip()
    if not raw:
        raise LiveRefuse("empty URL")
    parts = urlsplit(raw)
    if parts.scheme.lower() not in HTTP_SCHEMES:
        raise LiveRefuse(f"URL scheme {parts.scheme!r} is not http/https")
    if parts.username is not None or parts.password is not None or "@" in (parts.netloc or ""):
        raise LiveRefuse("URL userinfo is refused")
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise LiveRefuse("URL has no host")
    if not is_bare_host(host) and not _is_ip(host):
        # hostname may contain only label chars; reject leftover junk
        if "/" in host or "@" in host or ":" in host:
            raise LiveRefuse(f"URL host {host!r} is not a bare host")
    try:
        port = int(parts.port) if parts.port is not None else SCHEME_DEFAULT_PORT[parts.scheme.lower()]
    except (TypeError, ValueError) as exc:
        raise LiveRefuse(f"URL port invalid: {url!r}") from exc
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return host, port, parts.scheme.lower(), path


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _digest_is_demo(value: str) -> bool:
    return str(value or "").strip().lower() == PACK_DEMO_CONSENT_SHA256


def _refuse_demo_scope(path: Path) -> None:
    """Refuse the pack DEMO SCOPE by path, text, or consent digest."""
    try:
        demo = (root_dir() / "dropbox" / "SCOPE.yaml").resolve()
        if path.resolve() == demo:
            raise LiveRefuse("refuses pack DEMO SCOPE")
    except LiveRefuse:
        raise
    except OSError:
        pass
    try:
        blob = path.read_text(encoding="utf-8")
    except OSError:
        return
    if "demo-written-consent" in blob.lower():
        raise LiveRefuse("refuses pack DEMO SCOPE")
    try:
        data = load_yaml(blob)
    except (ValueError, TypeError):
        return
    if not isinstance(data, dict):
        return
    client = data.get("client") if isinstance(data.get("client"), dict) else {}
    if str(client.get("name") or "").strip() == PACK_DEMO_CLIENT_NAME:
        raise LiveRefuse("refuses pack DEMO SCOPE")
    consent = data.get("consent") if isinstance(data.get("consent"), dict) else {}
    declared = str(consent.get("attestation_sha256") or "").strip().lower()
    if _digest_is_demo(declared):
        raise LiveRefuse("refuses pack DEMO SCOPE")
    att_rel = str(consent.get("attestation_path") or "").strip()
    if not att_rel:
        return
    try:
        att_path = resolve_attestation_path(att_rel)
        if att_path.is_file() and _digest_is_demo(attestation_digest(att_path.read_bytes())):
            raise LiveRefuse("refuses pack DEMO SCOPE")
    except LiveRefuse:
        raise
    except OSError:
        return


def _require_bound_scope(scope: Any = None) -> Any:
    """Re-read + re-validate SCOPE (incl. consent digest) before every connect.

    Fail closed when no scope is bound, the file cannot be read, or load_scope
    refuses (revoked / expired / hash mismatch / unknown status).
    """
    global _ACTIVE_SCOPE
    current = _ACTIVE_SCOPE if _ACTIVE_SCOPE is not None else scope
    if current is None:
        raise LiveRefuse("live probe requires a bound signed SCOPE")
    path = getattr(current, "path", None)
    if path is None:
        raise LiveRefuse("live probe requires a bound signed SCOPE")
    scope_path = Path(path)
    try:
        _refuse_demo_scope(scope_path)
        fresh = load_scope(scope_path)
    except LiveRefuse:
        raise
    except GateError as exc:
        raise LiveRefuse(str(exc)) from exc
    except OSError as exc:
        raise LiveRefuse(f"cannot re-read SCOPE: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        raise LiveRefuse(f"cannot re-read SCOPE: {exc}") from exc
    if str(getattr(fresh, "client_name", "") or "").strip() == PACK_DEMO_CLIENT_NAME:
        raise LiveRefuse("refuses pack DEMO SCOPE")
    if _digest_is_demo(getattr(fresh, "consent_sha256", "")):
        raise LiveRefuse("refuses pack DEMO SCOPE")
    try:
        consent_path = Path(fresh.consent_path)
        if _digest_is_demo(attestation_digest(consent_path.read_bytes())):
            raise LiveRefuse("refuses pack DEMO SCOPE")
    except LiveRefuse:
        raise
    except OSError as exc:
        raise LiveRefuse(f"cannot re-read SCOPE consent: {exc}") from exc
    _ACTIVE_SCOPE = fresh
    return fresh


def resolve_authorized(scope: Any, host: str, port: int) -> str:
    """Resolve host, require SCOPE on the name and on the resolved IP. Return IP."""
    try:
        require_live_probe(scope, host, [port])
    except GateError as exc:
        raise LiveRefuse(str(exc)) from exc
    try:
        infos = socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise LiveRefuse(f"cannot resolve {host!r}: {exc}") from exc
    if not infos:
        raise LiveRefuse(f"cannot resolve {host!r}")
    ip = str(infos[0][4][0])
    try:
        require_live_probe(scope, ip, [port])
    except GateError as exc:
        raise LiveRefuse(f"resolved IP {ip} outside authorized SCOPE") from exc
    return ip


def authorize_endpoint(scope: Any, host: str, port: int) -> str:
    """Gate one (host, port). Always re-reads the SCOPE file first.

    Direct calls do not leave ``_ACTIVE_SCOPE`` bound afterwards,
    including when the gate raises. A caller that already bound a
    SCOPE (``run_live`` / ``_bind_scope``) is restored to that binding.
    """
    global _ACTIVE_SCOPE
    prev = _ACTIVE_SCOPE
    try:
        current = _require_bound_scope(scope)
        if not is_bare_host(host) and not _is_ip(host):
            raise LiveRefuse(f"target must be a bare host or IP, not {host!r}")
        return resolve_authorized(current, host, port)
    finally:
        _ACTIVE_SCOPE = prev


def tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    dest = authorize_endpoint(_ACTIVE_SCOPE, host, port)
    try:
        with socket.create_connection((dest, port), timeout=timeout):
            return True
    except OSError:
        return False


def http_exchange(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,
    follow_redirects: bool = False,
) -> dict[str, Any]:
    """GET/HEAD/OPTIONS only. Redirects are never followed."""
    del follow_redirects  # never follow; Location is recorded only
    try:
        _require_bound_scope()
    except LiveRefuse:
        raise
    try:
        host, port, scheme, path = parse_http_url(url)
    except LiveRefuse as exc:
        return {"error": str(exc)}
    dest = host
    try:
        dest = authorize_endpoint(_ACTIVE_SCOPE, host, port)
    except LiveRefuse as exc:
        msg = str(exc)
        if any(
            tok in msg.lower()
            for tok in ("revoked", "cannot re-read", "demo scope", "consent", "bound signed")
        ):
            raise
        return {"error": msg}
    req_headers = {"User-Agent": "grc-collector-pack-web-tls/1.0", "Host": host}
    if headers:
        req_headers.update(headers)
    try:
        sock = socket.create_connection((dest, port), timeout=timeout)
        if scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.sock = sock
        conn.request(method, path or "/", headers=req_headers)
        resp = conn.getresponse()
        raw_headers = {k.lower(): v for k, v in resp.getheaders()}
        cookies = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
        body = resp.read(4096).decode("utf-8", errors="replace")
        out = {
            "status": resp.status,
            "headers": raw_headers,
            "set_cookie": cookies,
            "body": body,
            "allow": raw_headers.get("allow") or raw_headers.get("access-control-allow-methods") or "",
            "location": raw_headers.get("location") or "",
            "server": raw_headers.get("server") or "",
        }
        conn.close()
        return out
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


def tls_probe(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    dest = authorize_endpoint(_ACTIVE_SCOPE, host, port)
    if not tcp_open(host, port, timeout=2.0):
        return {"open": False, "port": port}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((dest, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                not_after = str(cert.get("notAfter") or "")
                days = None
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )
                        days = (exp - datetime.now(timezone.utc)).days
                    except ValueError:
                        days = None
                return {
                    "open": True,
                    "tls": True,
                    "cert_present": bool(cert),
                    "notAfter": not_after,
                    "days_remaining": days,
                    "subject": cert.get("subject"),
                    "port": port,
                }
    except ssl.SSLCertVerificationError as exc:
        return {"open": True, "port": port, "verify_error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"open": True, "port": port, "error": f"{type(exc).__name__}: {exc}"}


def ssh_banner(host: str, port: int = 22, timeout: float = 3.0) -> dict[str, Any]:
    dest = authorize_endpoint(_ACTIVE_SCOPE, host, port)
    if not tcp_open(host, port, timeout=2.0):
        return {}
    try:
        with socket.create_connection((dest, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
            return {"banner": data.decode("utf-8", errors="replace").strip(), "port": port}
    except OSError as exc:
        return {"error": str(exc), "port": port}


def default_http_urls(target: str, ports: list[int]) -> list[str]:
    """Only emit default URLs for ports that are actually allowed/requested."""
    urls: list[str] = []
    if 80 in ports:
        urls.append(f"http://{target}/")
    if 443 in ports:
        urls.append(f"https://{target}/")
    if 8080 in ports:
        urls.append(f"http://{target}:8080/")
    if 8443 in ports:
        urls.append(f"https://{target}:8443/")
    return urls


def build_snapshot(
    target: str,
    *,
    ports: list[int] | None = None,
    http_urls: list[str] | None = None,
) -> dict[str, Any]:
    """Record a live snapshot. Requires a bound signed SCOPE (run_live)."""
    _require_bound_scope()
    if not is_bare_host(target) and not _is_ip(target):
        raise LiveRefuse(f"target must be a bare host or IP, not {target!r}")
    ports = list(ports or DEFAULT_PORTS)
    urls = list(http_urls) if http_urls else default_http_urls(target, ports)
    open_ports = [p for p in ports if tcp_open(target, p)]
    http: dict[str, Any] = {}
    for url in urls:
        row = http_exchange(url)
        cors = http_exchange(
            url,
            headers={"Origin": "https://evil.example"},
        )
        if cors.get("headers"):
            row.setdefault("headers", {}).update(cors.get("headers") or {})
        methods = http_exchange(url, method="OPTIONS")
        if methods.get("allow"):
            row["allow"] = methods["allow"]
        if url.startswith("http://") and not url.startswith("https://"):
            redir = http_exchange(url)
            row["redirect_status"] = redir.get("status")
            row["location"] = redir.get("location") or ""
        base = url if url.endswith("/") else url.rsplit("/", 1)[0] + "/"
        for rel in ("static/", "uploads/", ".git/HEAD"):
            if rel == ".git/HEAD":
                parts = url.split("/", 3)
                probe_url = "/".join(parts[:3]) + "/.git/HEAD" if len(parts) >= 3 else base + rel
            else:
                probe_url = base + rel
            probed = http_exchange(probe_url)
            if probed.get("error"):
                continue
            kind = "dir"
            if rel == ".git/HEAD":
                probed["git_head"] = bool(str(probed.get("body") or "").startswith("ref:"))
            http[probe_url] = {**probed, "kind": kind, "url": probe_url}
        http[url] = row
    tls: dict[str, Any] = {}
    for port in (443, 8443):
        if port in ports:
            tls[str(port)] = tls_probe(target, port)
    ssh: dict[str, Any] = {}
    if 22 in ports:
        banner = ssh_banner(target, 22)
        if banner:
            ssh["22"] = banner
    return {
        "schema": "web_tls.probe.v1",
        "target": target,
        "ports": ports,
        "open_ports": open_ports,
        "http": http,
        "tls": tls,
        "ssh": ssh,
        "live": True,
        "method_limits": (
            "TCP connect + HTTP headers/cookies/CORS/methods/tech/dir + TLS + SSH banner "
            "+ service exposure only — no exploit, brute, or credential use"
        ),
    }


def _stamp_honesty(records: list[dict[str, Any]], *, live: bool) -> list[dict[str, Any]]:
    label = estate_hint()
    for rec in records:
        labels = rec.setdefault("labels", [])
        if isinstance(labels, list):
            if live and "live" not in labels:
                labels.append("live")
            if label in {"DEMO", "SAMPLE", "LAB"} and label.lower() not in [str(x).lower() for x in labels]:
                labels.append(label.lower() if label == "DEMO" else label)
            if "client" in [str(x).lower() for x in labels] and label != "CLIENT":
                rec["labels"] = [x for x in labels if str(x).lower() != "client"]
        extra = rec.setdefault("extra", {})
        if isinstance(extra, dict):
            extra["live"] = bool(live)
            extra["client"] = label == "CLIENT"
            extra["sample"] = label == "SAMPLE"
            extra["demo"] = label == "DEMO"
            extra["lab"] = label == "LAB"
            extra.setdefault("provenance", "signed-SCOPE live web/TLS; LAB/SAMPLE/DEMO ≠ client")
    return records


def _preflight(scope: Any, target: str, ports: list[int], http_urls: list[str] | None) -> None:
    if not is_bare_host(target):
        raise LiveRefuse("target must be a bare host or IP (no URL, userinfo, or host:port)")
    try:
        require_live_probe(scope, target, ports)
    except GateError as exc:
        raise LiveRefuse(str(exc)) from exc
    authorize_endpoint(scope, target, ports[0] if ports else 80)
    for port in ports:
        authorize_endpoint(scope, target, port)
    for url in http_urls or []:
        host, port, _scheme, _path = parse_http_url(url)
        authorize_endpoint(scope, host, port)


def run_live(
    *,
    scope_path: Path,
    target: str,
    ports: list[int] | None = None,
    http_urls: list[str] | None = None,
    dest: Path | None = None,
) -> dict[str, Any]:
    scope_path = Path(scope_path)
    _refuse_demo_scope(scope_path)
    try:
        scope = load_scope(scope_path)
    except GateError as exc:
        raise LiveRefuse(str(exc)) from exc
    want_ports = list(ports or DEFAULT_PORTS)
    with _bind_scope(scope):
        _preflight(scope, str(target).strip(), want_ports, http_urls)
        snapshot = build_snapshot(target, ports=want_ports, http_urls=http_urls)
    records = _stamp_honesty(parse_snapshot(snapshot), live=True)
    payload = {
        "schema": "web_tls.probe.v1",
        "live": True,
        "target": target,
        "snapshot": snapshot,
        "records": len(records),
    }
    if dest is not None:
        write_json(dest, snapshot)
    try:
        write_canonical(SOURCE, records)
    except SystemExit:
        pass
    payload["findings"] = records
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Live-only web/TLS collector. Signed SCOPE required. No RiskReady POST."
    )
    parser.add_argument("--live", action="store_true", help="Run probes. Off by default.")
    parser.add_argument("--scope", help="Signed SCOPE.yaml (required with --live).")
    parser.add_argument("--target", help="In-SCOPE bare host or IP (not a URL or host:port).")
    parser.add_argument("--port", action="append", dest="ports", type=int, help="TCP port (repeatable).")
    parser.add_argument("--url", action="append", dest="urls", help="In-SCOPE HTTP(S) URL (repeatable).")
    parser.add_argument("--out", help="Write recorded probe snapshot JSON.")
    args = parser.parse_args(argv)
    if not args.live:
        print(
            "web-tls live: offline (default). This collector is live-only. "
            "Pass --live --scope PATH --target HOST. No file-drop demo fallback.",
            file=sys.stderr,
        )
        return 0
    if not args.scope:
        raise LiveRefuse("--live requires --scope PATH")
    if not args.target:
        raise LiveRefuse("--live requires --target HOST")
    dest = Path(args.out) if args.out else None
    payload = run_live(
        scope_path=Path(args.scope),
        target=str(args.target).strip(),
        ports=args.ports,
        http_urls=args.urls,
        dest=dest,
    )
    print(f"web-tls live: target={payload['target']} findings={payload['records']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
