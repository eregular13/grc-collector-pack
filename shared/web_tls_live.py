"""Live web/TLS probes. Default off. Signed SCOPE only. No RiskReady POST.

Collectors never import this module. Tests monkeypatch transports — no internet.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dropbox.scope import GateError, default_scope_path, load_scope, require_live_probe
from shared.io_util import estate_hint, write_canonical, write_json
from shared.web_tls import SOURCE, parse_snapshot


class LiveRefuse(SystemExit):
    """Live web/TLS refused. Exit non-zero."""

    def __init__(self, message: str) -> None:
        super().__init__(f"web-tls live: {message}")


DEFAULT_PORTS = [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200, 3389, 445, 21, 23]


def tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def http_exchange(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    req_headers = {"User-Agent": "grc-collector-pack-web-tls/1.0"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, method=method, headers=req_headers)
    opener = urllib.request.build_opener()
    if not follow_redirects:

        class NoRedir(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N803
                return None

        opener = urllib.request.build_opener(NoRedir)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            cookies = []
            if hasattr(resp.headers, "get_all"):
                cookies = list(resp.headers.get_all("Set-Cookie") or [])
            body = resp.read(4096).decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "headers": raw_headers,
                "set_cookie": cookies,
                "body": body,
                "allow": raw_headers.get("allow") or raw_headers.get("access-control-allow-methods") or "",
                "location": raw_headers.get("location") or "",
                "server": raw_headers.get("server") or "",
            }
    except urllib.error.HTTPError as exc:
        raw_headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        cookies = []
        if exc.headers and hasattr(exc.headers, "get_all"):
            cookies = list(exc.headers.get_all("Set-Cookie") or [])
        try:
            body = exc.read(4096).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {
            "status": exc.code,
            "headers": raw_headers,
            "set_cookie": cookies,
            "body": body,
            "allow": raw_headers.get("allow") or "",
            "location": raw_headers.get("location") or "",
            "server": raw_headers.get("server") or "",
            "redirect_status": exc.code,
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


def tls_probe(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    if not tcp_open(host, port, timeout=2.0):
        return {"open": False, "port": port}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
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
    if not tcp_open(host, port, timeout=2.0):
        return {}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
            return {"banner": data.decode("utf-8", errors="replace").strip(), "port": port}
    except OSError as exc:
        return {"error": str(exc), "port": port}


def build_snapshot(
    target: str,
    *,
    ports: list[int] | None = None,
    http_urls: list[str] | None = None,
) -> dict[str, Any]:
    ports = list(ports or DEFAULT_PORTS)
    urls = list(http_urls or [f"http://{target}/"])
    if 8080 in ports and f"http://{target}:8080/" not in urls:
        urls.append(f"http://{target}:8080/")
    if 8443 in ports and f"https://{target}:8443/" not in urls:
        urls.append(f"https://{target}:8443/")
    if 443 in ports and f"https://{target}/" not in urls:
        urls.append(f"https://{target}/")
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
            redir = http_exchange(url, follow_redirects=False)
            row["redirect_status"] = redir.get("status") or redir.get("redirect_status")
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


def run_live(
    *,
    scope_path: Path,
    target: str,
    ports: list[int] | None = None,
    http_urls: list[str] | None = None,
    dest: Path | None = None,
) -> dict[str, Any]:
    try:
        scope = load_scope(scope_path)
    except GateError as exc:
        raise LiveRefuse(str(exc)) from exc
    want_ports = list(ports or DEFAULT_PORTS)
    try:
        require_live_probe(scope, target, want_ports)
        for url in http_urls or []:
            host = url.split("://")[-1].split("/")[0].split(":")[0]
            require_live_probe(scope, host, want_ports)
    except GateError as exc:
        raise LiveRefuse(str(exc)) from exc
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
    parser.add_argument("--target", help="In-SCOPE host or IP.")
    parser.add_argument("--port", action="append", dest="ports", type=int, help="TCP port (repeatable).")
    parser.add_argument("--url", action="append", dest="urls", help="In-SCOPE HTTP URL (repeatable).")
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
    scope_path = Path(args.scope) if args.scope else default_scope_path()
    dest = Path(args.out) if args.out else None
    payload = run_live(
        scope_path=scope_path,
        target=str(args.target).strip(),
        ports=args.ports,
        http_urls=args.urls,
        dest=dest,
    )
    print(f"web-tls live: target={payload['target']} findings={payload['records']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
