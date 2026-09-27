"""Metis #196: live web/TLS must not connect past the SCOPE gate."""

from __future__ import annotations

import hashlib
import socket
import threading
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from dropbox.scope import GateError, attestation_digest, load_scope
from shared.web_tls_live import (
    LiveRefuse,
    PACK_DEMO_CLIENT_NAME,
    PACK_DEMO_CONSENT_SHA256,
    default_http_urls,
    is_bare_host,
    parse_http_url,
    run_live,
)

ROOT = Path(__file__).resolve().parents[1]


def _consent(tmp_path: Path) -> tuple[Path, str]:
    att = tmp_path / "consent.md"
    att.write_text("web-tls live consent\n", encoding="utf-8")
    return att, hashlib.sha256(att.read_bytes()).hexdigest()


def _signed_scope(
    tmp_path: Path,
    *,
    extra_eng: str = "",
    extra_root: str = "",
    hosts: str = "    - 192.0.2.10\n    - 127.0.0.1\n",
    domains: str = "",
) -> Path:
    att, digest = _consent(tmp_path)
    today = date.today()
    start = (today - timedelta(days=1)).isoformat()
    end = (today + timedelta(days=30)).isoformat()
    path = tmp_path / "SCOPE.yaml"
    ext_domains = domains or ""
    path.write_text(
        "client:\n  name: lab-client\nconsent:\n"
        f"  attestation_path: {att}\n  attestation_sha256: {digest}\n"
        f"engagement:\n  start: {start}\n  end: {end}\n{extra_eng}"
        f"{extra_root}"
        f"internal:\n  hosts:\n{hosts}  cidrs:\n    - 192.0.2.0/24\n"
        "external:\n  hosts:\n    - vpn.example.invalid\n  ips:\n    - 192.0.2.10\n"
        f"{ext_domains}"
        "allow_tools:\n  - curl\n",
        encoding="utf-8",
    )
    return path


def _record_sockets(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    recorded: list[tuple[str, int]] = []
    real_cc = socket.create_connection
    real_gai = socket.getaddrinfo

    def wrap_cc(addr, timeout=None, *args, **kwargs):
        host, port = addr[0], addr[1]
        recorded.append((str(host), int(port)))
        if str(host) in {"127.0.0.1", "::1"}:
            return real_cc(addr, timeout, *args, **kwargs)
        raise OSError(f"blocked connect {host}:{port}")

    def wrap_gai(host, port, *args, **kwargs):
        recorded.append((f"gai:{host}", int(port or 0)))
        return real_gai(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", wrap_cc)
    monkeypatch.setattr(socket, "getaddrinfo", wrap_gai)
    return recorded


def test_redirects_are_not_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _record_sockets(monkeypatch)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/pwn")
            self.end_headers()

        def log_message(self, *_a: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scope = _signed_scope(tmp_path, extra_root=f"ports_allowed:\n  - {port}\n")
        monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
        (tmp_path / "out").mkdir()
        run_live(
            scope_path=scope,
            target="127.0.0.1",
            ports=[port],
            http_urls=[f"http://127.0.0.1:{port}/"],
        )
    finally:
        server.shutdown()
        server.server_close()
    hosts = {h for h, _p in recorded}
    assert "example.invalid" not in hosts
    assert not any(h.endswith("example.invalid") for h in hosts)


def test_default_http_url_not_generated_for_disallowed_port_80(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded = _record_sockets(monkeypatch)
    scope = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 443\n")
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    (tmp_path / "out").mkdir()
    from shared import web_tls_live as live

    monkeypatch.setattr(live, "tcp_open", lambda host, port, timeout=2.0: False)
    monkeypatch.setattr(live, "http_exchange", lambda url, **_k: {"status": 200, "headers": {}})
    monkeypatch.setattr(live, "tls_probe", lambda host, port=443, timeout=5.0: {"open": False, "port": port})
    monkeypatch.setattr(live, "ssh_banner", lambda host, port=22, timeout=3.0: {})
    payload = live.run_live(scope_path=scope, target="192.0.2.10", ports=[443])
    urls = list((payload.get("snapshot") or {}).get("http") or {})
    assert not any(":80" in u or u.startswith("http://192.0.2.10/") for u in urls)
    assert default_http_urls("192.0.2.10", [443]) == ["https://192.0.2.10/"]
    assert not any(p == 80 for _h, p in recorded if not str(_h).startswith("gai:"))


def test_url_port_is_gated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _record_sockets(monkeypatch)
    scope = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 443\n")
    with pytest.raises(LiveRefuse, match="port"):
        run_live(
            scope_path=scope,
            target="192.0.2.10",
            ports=[443],
            http_urls=["http://192.0.2.10:8081/"],
        )
    with pytest.raises(LiveRefuse):
        run_live(
            scope_path=scope,
            target="192.0.2.10",
            ports=[443],
            http_urls=["ftp://192.0.2.10:21/"],
        )
    with pytest.raises(LiveRefuse, match="port"):
        run_live(
            scope_path=scope,
            target="192.0.2.10",
            ports=[443],
            http_urls=["http://192.0.2.10/"],
        )
    assert not any(p in {8081, 21, 80} and not str(h).startswith("gai:") for h, p in recorded)


def test_target_host_port_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _record_sockets(monkeypatch)
    scope = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 443\n")
    with pytest.raises(LiveRefuse, match="bare host"):
        run_live(scope_path=scope, target="127.0.0.1:9999", ports=[443])
    assert not any(p == 9999 for _h, p in recorded)
    assert not is_bare_host("127.0.0.1:9999")
    assert is_bare_host("127.0.0.1")


def test_url_userinfo_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _record_sockets(monkeypatch)
    scope = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 80\n")
    with pytest.raises(LiveRefuse, match="userinfo"):
        run_live(
            scope_path=scope,
            target="127.0.0.1",
            ports=[80],
            http_urls=["http://127.0.0.1:x@example.invalid/"],
        )
    with pytest.raises(LiveRefuse, match="bare host"):
        run_live(scope_path=scope, target="http://127.0.0.1:x@example.invalid/", ports=[80])
    with pytest.raises(LiveRefuse, match="userinfo"):
        parse_http_url("http://127.0.0.1:80@example.invalid:80/")
    assert not any("example.invalid" in str(h) for h, _p in recorded)


def test_ports_outside_1_65535_refused_without_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded = _record_sockets(monkeypatch)
    scope = _signed_scope(tmp_path)
    for bad in (0, -1, 65536):
        with pytest.raises((LiveRefuse, GateError), match="range|port"):
            run_live(scope_path=scope, target="192.0.2.10", ports=[bad])
    assert not any(p in {0, -1, 65536} and not str(h).startswith("gai:") for h, p in recorded)


def test_resolved_ip_is_rechecked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorded_connects: list[tuple[str, int]] = []
    real_gai = socket.getaddrinfo
    real_cc = socket.create_connection

    def wrap_gai(host, port, *args, **kwargs):
        if str(host) == "vpn.example.invalid":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.7", int(port or 0)))]
        return real_gai(host, port, *args, **kwargs)

    def wrap_cc(addr, timeout=None, *args, **kwargs):
        host, port = addr[0], addr[1]
        recorded_connects.append((str(host), int(port)))
        if str(host) in {"127.0.0.1", "::1"}:
            return real_cc(addr, timeout, *args, **kwargs)
        raise OSError(f"blocked connect {host}:{port}")

    monkeypatch.setattr(socket, "getaddrinfo", wrap_gai)
    monkeypatch.setattr(socket, "create_connection", wrap_cc)
    scope = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 443\n")
    with pytest.raises(LiveRefuse, match="resolved IP"):
        run_live(scope_path=scope, target="vpn.example.invalid", ports=[443])
    assert recorded_connects == []
    assert not any(h == "198.51.100.7" for h, _p in recorded_connects)


def test_live_refuses_pack_demo_scope(tmp_path: Path) -> None:
    with pytest.raises(LiveRefuse, match="DEMO SCOPE"):
        run_live(scope_path=ROOT / "dropbox" / "SCOPE.yaml", target="127.0.0.1", ports=[80])


def _stamp_revoked(scope_path: Path) -> None:
    text = scope_path.read_text(encoding="utf-8")
    if not text.lower().startswith("revoked:"):
        scope_path.write_text("revoked: true\n" + text, encoding="utf-8")


def test_revocation_reread_before_every_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded: list[tuple[str, int]] = []
    scope = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 80\n  - 443\n")

    def wrap_cc(addr, timeout=None, *args, **kwargs):
        host, port = addr[0], addr[1]
        recorded.append((str(host), int(port)))
        _stamp_revoked(scope)
        raise OSError(f"blocked connect {host}:{port}")

    monkeypatch.setattr(socket, "create_connection", wrap_cc)
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    (tmp_path / "out").mkdir()
    with pytest.raises(LiveRefuse, match="revoked"):
        run_live(scope_path=scope, target="192.0.2.10", ports=[80, 443], http_urls=[])
    assert len(recorded) == 1


def test_scope_read_error_mid_run_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded: list[tuple[str, int]] = []
    scope = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 80\n  - 443\n")

    def wrap_cc(addr, timeout=None, *args, **kwargs):
        host, port = addr[0], addr[1]
        recorded.append((str(host), int(port)))
        scope.unlink()
        raise OSError(f"blocked connect {host}:{port}")

    monkeypatch.setattr(socket, "create_connection", wrap_cc)
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    (tmp_path / "out").mkdir()
    with pytest.raises(LiveRefuse):
        run_live(scope_path=scope, target="192.0.2.10", ports=[80, 443], http_urls=[])
    assert len(recorded) == 1
    assert not scope.is_file()


def test_live_refuses_demo_consent_digest_regardless_of_filename(tmp_path: Path) -> None:
    demo_consent = ROOT / "dropbox" / "consent" / "DEMO-WRITTEN-CONSENT.md"
    copied = tmp_path / "CLIENT-SIGNED-CONSENT.md"
    copied.write_bytes(demo_consent.read_bytes())
    digest = attestation_digest(copied.read_bytes())
    assert digest == PACK_DEMO_CONSENT_SHA256
    today = date.today()
    path = tmp_path / "client-SCOPE.yaml"
    path.write_text(
        "client:\n  name: lab-client\nconsent:\n"
        f"  attestation_path: {copied}\n  attestation_sha256: {digest}\n"
        f"engagement:\n  start: {(today - timedelta(days=1)).isoformat()}\n"
        f"  end: {(today + timedelta(days=30)).isoformat()}\n"
        "internal:\n  hosts:\n    - 127.0.0.1\n  cidrs:\n    - 192.0.2.0/24\n"
        "external:\n  hosts:\n    - vpn.example.invalid\n  ips:\n    - 192.0.2.10\n"
        "allow_tools:\n  - curl\n",
        encoding="utf-8",
    )
    assert "demo-written-consent" not in path.read_text(encoding="utf-8").lower()
    with pytest.raises(LiveRefuse, match="DEMO SCOPE"):
        run_live(scope_path=path, target="127.0.0.1", ports=[80])


def test_pack_demo_consent_digest_matches_repo_file() -> None:
    demo = ROOT / "dropbox" / "consent" / "DEMO-WRITTEN-CONSENT.md"
    assert attestation_digest(demo.read_bytes()) == PACK_DEMO_CONSENT_SHA256


def test_build_snapshot_without_bound_scope_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    from shared.web_tls_live import build_snapshot

    recorded = _record_sockets(monkeypatch)
    with pytest.raises(LiveRefuse, match="bound signed SCOPE"):
        build_snapshot("example.invalid", ports=[443])
    connects = [(h, p) for h, p in recorded if not str(h).startswith("gai:")]
    assert connects == []
    assert not any("example.invalid" in str(h) for h, _p in connects)


def test_authorize_endpoint_unbinds_scope_after_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from shared import web_tls_live as live

    recorded = _record_sockets(monkeypatch)
    scope_path = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 80\n")
    scope = load_scope(scope_path)
    live._ACTIVE_SCOPE = None
    dest = live.authorize_endpoint(scope, "192.0.2.10", 80)
    assert dest == "192.0.2.10"
    assert live._ACTIVE_SCOPE is None
    with pytest.raises(LiveRefuse, match="bound signed SCOPE"):
        live.build_snapshot("192.0.2.10", ports=[80])
    connects = [(h, p) for h, p in recorded if not str(h).startswith("gai:")]
    assert connects == []


def test_authorize_endpoint_unbinds_scope_on_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from shared import web_tls_live as live

    recorded = _record_sockets(monkeypatch)
    scope_path = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 80\n")
    scope = load_scope(scope_path)
    live._ACTIVE_SCOPE = None
    with pytest.raises(LiveRefuse, match="bare host"):
        live.authorize_endpoint(scope, "http://evil.example/", 80)
    assert live._ACTIVE_SCOPE is None
    with pytest.raises(LiveRefuse, match="bound signed SCOPE"):
        live.build_snapshot("192.0.2.10", ports=[80])
    connects = [(h, p) for h, p in recorded if not str(h).startswith("gai:")]
    assert connects == []


def test_live_refuses_demo_client_name_regardless_of_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded = _record_sockets(monkeypatch)
    att, digest = _consent(tmp_path)
    assert digest != PACK_DEMO_CONSENT_SHA256
    today = date.today()
    path = tmp_path / "client-SCOPE.yaml"
    path.write_text(
        f"client:\n  name: {PACK_DEMO_CLIENT_NAME}\nconsent:\n"
        f"  attestation_path: {att}\n  attestation_sha256: {digest}\n"
        f"engagement:\n  start: {(today - timedelta(days=1)).isoformat()}\n"
        f"  end: {(today + timedelta(days=30)).isoformat()}\n"
        "internal:\n  hosts:\n    - 127.0.0.1\n  cidrs:\n    - 192.0.2.0/24\n"
        "external:\n  hosts:\n    - vpn.example.invalid\n  ips:\n    - 192.0.2.10\n"
        "allow_tools:\n  - curl\n",
        encoding="utf-8",
    )
    assert "demo-written-consent" not in path.read_text(encoding="utf-8").lower()
    with pytest.raises(LiveRefuse, match="DEMO SCOPE"):
        run_live(scope_path=path, target="127.0.0.1", ports=[80])
    connects = [(h, p) for h, p in recorded if not str(h).startswith("gai:")]
    assert connects == []


def test_pack_demo_client_name_matches_repo_file() -> None:
    from dropbox.yaml_lite import load_yaml

    data = load_yaml((ROOT / "dropbox" / "SCOPE.yaml").read_text(encoding="utf-8"))
    assert data["client"]["name"] == PACK_DEMO_CLIENT_NAME
