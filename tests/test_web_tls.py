"""Live-only web/TLS collector: recorded fixtures, SCOPE refuse, no internet."""

from __future__ import annotations

import hashlib
import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from collectors import web_tls as collector
from shared.control_map import poam_decision
from shared.schema import make_ref
from shared.web_tls import (
    PORTED_SENSORS,
    SOURCE,
    parse_file,
    parse_snapshot,
    sense_cleartext_admin,
    sense_http_to_https_redirect,
    sense_service_ports,
    sense_surface,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples" / "web_tls"


def _consent(tmp_path: Path) -> tuple[Path, str]:
    att = tmp_path / "consent.md"
    att.write_text("web-tls live consent\n", encoding="utf-8")
    return att, hashlib.sha256(att.read_bytes()).hexdigest()


def _signed_scope(
    tmp_path: Path,
    *,
    extra_eng: str = "",
    extra_root: str = "",
    start: str | None = None,
    end: str | None = None,
    hosts: str = "    - 192.0.2.10\n    - 127.0.0.1\n",
) -> Path:
    att, digest = _consent(tmp_path)
    today = date.today()
    start = start or (today - timedelta(days=1)).isoformat()
    end = end or (today + timedelta(days=30)).isoformat()
    path = tmp_path / "SCOPE.yaml"
    path.write_text(
        "client:\n  name: lab-client\nconsent:\n"
        f"  attestation_path: {att}\n  attestation_sha256: {digest}\n"
        f"engagement:\n  start: {start}\n  end: {end}\n{extra_eng}"
        f"{extra_root}"
        f"internal:\n  hosts:\n{hosts}  cidrs:\n    - 192.0.2.0/24\n"
        "external:\n  hosts:\n    - vpn.example.com\n  ips:\n    - 192.0.2.10\n"
        "allow_tools:\n  - curl\n",
        encoding="utf-8",
    )
    return path


def test_cleartext_fixture_emits_expected_sensors() -> None:
    recs = parse_file(SAMPLES / "probe-cleartext-http.json")
    sensors = {str((r.get("extra") or {}).get("sensor")) for r in recs}
    assert "sense-cleartext-http" in sensors
    assert "sense-http-headers" in sensors
    assert "sense-http-info" in sensors
    assert "sense-git-exposed" in sensors
    assert "sense-dir-listing" in sensors
    assert "sense-tls" in sensors
    assert "sense-http-methods" in sensors
    assert "sense-tech-disclosure" in sensors
    assert "sense-default-page" in sensors
    assert "sense-cookie-flags" in sensors
    assert all(r["source"] == SOURCE for r in recs)
    assert all(r["ref_id"].startswith("WEB-") for r in recs)
    assert all("not a client KEEP" in (r.get("description") or "") for r in recs)
    git = next(r for r in recs if r["extra"]["sensor"] == "sense-git-exposed")
    assert git["severity"] == "critical"


def test_https_weak_fixture_cors_redirect_expiry_redis() -> None:
    recs = parse_file(SAMPLES / "probe-https-weak.json")
    sensors = {str((r.get("extra") or {}).get("sensor")) for r in recs}
    assert "sense-cors" in sensors
    assert "sense-http-https-redirect" in sensors
    assert "sense-tls-expiry" in sensors
    assert "sense-service-exposure" in sensors
    assert "sense-cookie-flags" in sensors
    redis = next(r for r in recs if "Redis" in r["name"])
    assert redis["severity"] == "critical"
    expiry = next(r for r in recs if r["extra"]["sensor"] == "sense-tls-expiry")
    assert expiry["severity"] == "critical"


def test_info_only_fixture_has_info_tls_and_probe_fail() -> None:
    recs = parse_file(SAMPLES / "probe-info-only.json")
    sevs = {r["severity"] for r in recs}
    assert "info" in sevs
    assert any(r["extra"]["sensor"] == "sense-tls" and r["severity"] == "info" for r in recs)
    assert any(r["extra"]["sensor"] == "sense-http-headers" and r["severity"] == "info" for r in recs)
    assert any(r["extra"]["sensor"] == "sense-ssh-banner" and r["severity"] == "info" for r in recs)


def test_ids_deterministic_across_parse_runs() -> None:
    a = [r["ref_id"] for r in parse_file(SAMPLES / "probe-cleartext-http.json")]
    b = [r["ref_id"] for r in parse_file(SAMPLES / "probe-cleartext-http.json")]
    assert a == b
    assert len(a) == len(set(a))
    src = (ROOT / "shared" / "web_tls.py").read_text(encoding="utf-8")
    assert "from uuid" not in src
    assert "uuid4(" not in src
    assert "hash(" not in src
    assert "make_ref" in src


def test_empty_and_hostile_invent_nothing(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("{}", encoding="utf-8")
    assert parse_file(empty) == []
    trunc = tmp_path / "trunc.json"
    trunc.write_text('{"target":', encoding="utf-8")
    assert parse_file(trunc) == []
    assert parse_snapshot({}) == []
    assert parse_snapshot({"schema": "web_tls.probe.v1"}) == []


def test_surface_empty_when_no_ports_open() -> None:
    assert sense_surface({"target": "192.0.2.1", "ports": [22, 80], "open_ports": []}) == []


def test_service_ports_flags_redis() -> None:
    recs = sense_service_ports("192.0.2.1", [6379, 80])
    assert any("Redis" in r["name"] for r in recs)


def test_cleartext_http_when_80_only() -> None:
    recs = sense_cleartext_admin("192.0.2.1", [80])
    assert any(r["extra"]["sensor"] == "sense-cleartext-http" for r in recs)


def test_https_redirect_skips_without_both_ports() -> None:
    assert sense_http_to_https_redirect("example.com", [80], {"status": 200}) == []
    assert sense_http_to_https_redirect("example.com", [443], {"status": 200}) == []


def test_ported_sensor_catalog() -> None:
    assert len(PORTED_SENSORS) == 17
    needed = [
        "sense-surface",
        "sense-http-headers",
        "sense-cleartext-http",
        "sense-ssh-banner",
        "sense-tls",
        "sense-tls-expiry",
        "sense-cookie-flags",
        "sense-cors",
        "sense-service-exposure",
        "sense-git-exposed",
        "sense-dir-listing",
        "sense-http-methods",
        "sense-tech-disclosure",
        "sense-default-page",
        "sense-http-https-redirect",
        "sense-http-info",
        "sense-cleartext-ftp",
    ]
    assert set(needed) == set(PORTED_SENSORS)


def test_collector_has_no_live_imports() -> None:
    src = (ROOT / "collectors" / "web_tls.py").read_text(encoding="utf-8")
    assert "import shared.web_tls_live" not in src
    assert "from shared.web_tls_live" not in src
    assert "import socket" not in src
    assert "import urllib" not in src
    assert "urllib.request" not in src
    assert "/api/risks" not in src
    parser = (ROOT / "shared" / "web_tls.py").read_text(encoding="utf-8")
    assert "import socket" not in parser
    assert "urllib.request" not in parser
    assert "urllib.error" not in parser
    assert "uuid4(" not in parser


def test_collector_live_flag_refuses_without_delegating() -> None:
    import sys

    old = sys.argv
    try:
        sys.argv = ["web_tls.py", "--live"]
        assert collector.main() == 2
    finally:
        sys.argv = old


def test_collector_parse_no_demo_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    in_root = tmp_path / "in"
    (in_root / "web_tls").mkdir(parents=True)
    out_root = tmp_path / "out"
    out_root.mkdir()
    monkeypatch.setenv("IN_DIR", str(in_root))
    monkeypatch.setenv("OUT_DIR", str(out_root))
    monkeypatch.setenv("FIXTURES_DIR", str(ROOT / "fixtures" / "demo"))
    assert collector.main() == 0
    dest = out_root / "canonical" / "web-tls.jsonl"
    assert not dest.exists()


def test_collector_parse_recorded_writes_canonical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    in_root = tmp_path / "in" / "web_tls"
    in_root.mkdir(parents=True)
    (in_root / "probe.json").write_bytes((SAMPLES / "probe-cleartext-http.json").read_bytes())
    out_root = tmp_path / "out"
    out_root.mkdir()
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("OUT_DIR", str(out_root))
    assert collector.main() == 0
    dest = out_root / "canonical" / "web-tls.jsonl"
    rows = [json.loads(line) for line in dest.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert rows
    assert all(r["source"] == SOURCE for r in rows)
    assert "/api/risks" not in dest.read_text(encoding="utf-8")


def test_live_offline_default() -> None:
    from shared.web_tls_live import main

    assert main([]) == 0


def test_live_refuses_no_scope() -> None:
    from shared.web_tls_live import LiveRefuse, main

    with pytest.raises(SystemExit, match="requires --scope"):
        main(["--live", "--target", "192.0.2.10"])
    with pytest.raises(LiveRefuse, match="requires --scope"):
        main(["--live", "--target", "192.0.2.10"])


def test_live_refuses_no_target(tmp_path: Path) -> None:
    from shared.web_tls_live import LiveRefuse, main

    scope = _signed_scope(tmp_path)
    with pytest.raises(LiveRefuse, match="requires --target"):
        main(["--live", "--scope", str(scope)])


def test_live_refuses_expired_scope(tmp_path: Path) -> None:
    from shared.web_tls_live import LiveRefuse, run_live

    scope = _signed_scope(tmp_path, start="2020-01-01", end="2020-01-02")
    with pytest.raises(LiveRefuse, match="outside engagement window"):
        run_live(scope_path=scope, target="192.0.2.10", ports=[80])


def test_live_refuses_revoked_scope(tmp_path: Path) -> None:
    from shared.web_tls_live import LiveRefuse, run_live

    scope = _signed_scope(tmp_path, extra_eng="  status: revoked\n")
    with pytest.raises(LiveRefuse, match="revoked"):
        run_live(scope_path=scope, target="192.0.2.10", ports=[80])


def test_live_refuses_target_outside_scope(tmp_path: Path) -> None:
    from shared.web_tls_live import LiveRefuse, run_live

    scope = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 80\n")
    with pytest.raises(LiveRefuse, match="outside authorized SCOPE"):
        run_live(scope_path=scope, target="8.8.8.8", ports=[80])


def test_live_refuses_port_outside_scope(tmp_path: Path) -> None:
    from shared.web_tls_live import LiveRefuse, run_live

    scope = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 80\n")
    with pytest.raises(LiveRefuse, match="port"):
        run_live(scope_path=scope, target="192.0.2.10", ports=[22])


def test_live_mocked_snapshot_no_internet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from shared import web_tls_live as live

    scope = _signed_scope(tmp_path, extra_root="ports_allowed:\n  - 80\n  - 443\n")
    monkeypatch.setattr(live, "tcp_open", lambda host, port, timeout=2.0: port == 80)
    monkeypatch.setattr(
        live,
        "http_exchange",
        lambda url, **_k: {
            "status": 200,
            "headers": {"server": "nginx/1.18.0"},
            "body": "Welcome to nginx",
            "set_cookie": [],
            "allow": "GET",
        },
    )
    monkeypatch.setattr(live, "tls_probe", lambda host, port=443, timeout=5.0: {"open": False, "port": port})
    monkeypatch.setattr(live, "ssh_banner", lambda host, port=22, timeout=3.0: {})
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    (tmp_path / "out").mkdir()
    dest = tmp_path / "snap.json"
    payload = live.run_live(
        scope_path=scope,
        target="192.0.2.10",
        ports=[80, 443],
        dest=dest,
    )
    assert dest.is_file()
    assert payload["records"] >= 1
    sensors = {r["extra"]["sensor"] for r in payload["findings"]}
    assert "sense-cleartext-http" in sensors
    assert all("client" not in [str(x).lower() for x in (r.get("labels") or [])] for r in payload["findings"])


def test_make_ref_stable_key_scheme() -> None:
    assert make_ref("web-tls", "sense-tls-192-0-2-10-443") == "WEB-sense-tls-192-0-2-10-443"


def test_uncovered_emit_sites_from_fixture() -> None:
    recs = parse_file(SAMPLES / "probe-uncovered-emit.json")
    sensors = {str((r.get("extra") or {}).get("sensor")) for r in recs}
    assert "sense-tls" in sensors
    assert "sense-ssh-banner" in sensors
    assert "sense-cleartext-ftp" in sensors
    assert any("trust" in r["name"].lower() or r["extra"].get("variant") == "trust" for r in recs)
    assert any(r["extra"].get("variant") == "error" for r in recs)
    assert any(r["extra"]["sensor"] == "sense-ssh-banner" and r["severity"] == "low" for r in recs)
    assert any(r["extra"]["sensor"] == "sense-cleartext-ftp" for r in recs)


def test_tls_no_listener_and_ok_have_distinct_ids() -> None:
    closed = parse_snapshot(
        {
            "schema": "web_tls.probe.v1",
            "target": "192.0.2.10",
            "ports": [443],
            "open_ports": [],
            "tls": {"443": {"open": False, "port": 443}},
        }
    )
    ok = parse_snapshot(
        {
            "schema": "web_tls.probe.v1",
            "target": "192.0.2.10",
            "ports": [443],
            "open_ports": [443],
            "tls": {"443": {"open": True, "tls": True, "port": 443, "cert_present": True}},
        }
    )
    c = next(r for r in closed if r["extra"]["sensor"] == "sense-tls")
    o = next(r for r in ok if r["extra"]["sensor"] == "sense-tls")
    assert c["ref_id"] != o["ref_id"]
    assert c["extra"].get("variant") == "no-listener"
    assert o["extra"].get("variant") == "ok"


def test_info_tls_ok_is_off_poam_preview() -> None:
    recs = parse_file(SAMPLES / "probe-info-only.json")
    info = [r for r in recs if r["severity"] == "info"]
    assert info
    for rec in info:
        decision = poam_decision(rec)
        assert decision["include"] is False
        assert decision["reason"] in {"severity_info", "telemetry_info"}
