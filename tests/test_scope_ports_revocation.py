"""SCOPE ports_allowed + revocation. Backward compatible when fields are absent."""

from __future__ import annotations

import hashlib
from datetime import date, timedelta
from pathlib import Path

import pytest

from dropbox.scope import (
    GateError,
    load_scope,
    require_authorized_ports,
    require_live_probe,
    require_not_revoked,
)

ROOT = Path(__file__).resolve().parents[1]


def _consent(tmp_path: Path, text: str = "ok\n") -> tuple[Path, str]:
    att = tmp_path / "consent.md"
    att.write_text(text, encoding="utf-8")
    return att, hashlib.sha256(att.read_bytes()).hexdigest()


def _write_scope(
    tmp_path: Path,
    extra: str = "",
    *,
    start: str | None = None,
    end: str | None = None,
) -> Path:
    att, digest = _consent(tmp_path)
    today = date.today()
    start = start or (today - timedelta(days=1)).isoformat()
    end = end or (today + timedelta(days=30)).isoformat()
    body = (
        "client:\n  name: DEMO — not a client estate\nconsent:\n"
        f"  attestation_path: {att}\n  attestation_sha256: {digest}\n"
        f"engagement:\n  start: {start}\n  end: {end}\n{extra}"
        "internal:\n  cidrs:\n    - 10.20.30.0/23\n  hosts:\n    - 127.0.0.1\n"
        "    - 192.0.2.10\n"
        "external:\n  hosts:\n    - vpn.example.com\n  ips:\n    - 192.0.2.10\n"
        "allow_tools:\n  - curl\n"
    )
    path = tmp_path / "SCOPE.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_absent_ports_allowed_keeps_current_behavior(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path))
    assert scope.ports_allowed is None
    assert scope.allows_port(22)
    assert scope.allows_port(65535)
    assert not scope.allows_port(0)
    assert not scope.allows_port(-1)
    assert not scope.allows_port(65536)
    require_authorized_ports(scope, [22, 3389, 1])
    with pytest.raises(GateError, match="out of range"):
        require_authorized_ports(scope, [0])
    with pytest.raises(GateError, match="out of range"):
        require_authorized_ports(scope, [-1])
    with pytest.raises(GateError, match="out of range"):
        require_authorized_ports(scope, [65536])
    demo = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    assert demo.ports_allowed is None
    assert demo.allows_port(445)


def test_ports_allowed_allow_and_deny(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path, "ports_allowed:\n  - 80\n  - 443\n"))
    assert scope.ports_allowed == [80, 443]
    assert scope.allows_port(80)
    assert scope.allows_port(443)
    assert not scope.allows_port(22)
    require_authorized_ports(scope, [80, 443])
    with pytest.raises(GateError, match="port"):
        require_authorized_ports(scope, [22])
    with pytest.raises(GateError, match="port"):
        require_live_probe(scope, "192.0.2.10", [8080])
    require_live_probe(scope, "192.0.2.10", [443])


def test_empty_ports_allowed_denies_every_port(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path, "ports_allowed: []\n"))
    assert scope.ports_allowed == []
    assert not scope.allows_port(80)
    with pytest.raises(GateError, match="port"):
        require_authorized_ports(scope, [80])


def test_engagement_ports_allowed_alias(tmp_path: Path) -> None:
    att, digest = _consent(tmp_path)
    today = date.today()
    path = tmp_path / "SCOPE.yaml"
    path.write_text(
        "client:\n  name: DEMO — not a client estate\nconsent:\n"
        f"  attestation_path: {att}\n  attestation_sha256: {digest}\n"
        f"engagement:\n  start: {today.isoformat()}\n"
        f"  end: {(today + timedelta(days=2)).isoformat()}\n"
        "  ports_allowed:\n    - 22\n"
        "internal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n"
        "allow_tools:\n  - curl\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.ports_allowed == [22]
    assert scope.allows_port(22)
    assert not scope.allows_port(80)


def test_revoked_status_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  status: revoked\n"))


def test_revoked_flag_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  revoked: true\n"))


def test_revoked_on_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  revoked: on\n"))


def test_revoked_y_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  revoked: y\n"))


def test_status_terminated_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  status: terminated\n"))


def test_status_suspended_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  status: suspended\n"))


def test_toplevel_revoked_true_refuses_load(tmp_path: Path) -> None:
    att, digest = _consent(tmp_path)
    today = date.today()
    path = tmp_path / "SCOPE.yaml"
    path.write_text(
        "client:\n  name: DEMO — not a client estate\nconsent:\n"
        f"  attestation_path: {att}\n  attestation_sha256: {digest}\n"
        "revoked: true\n"
        f"engagement:\n  start: {today.isoformat()}\n"
        f"  end: {(today + timedelta(days=2)).isoformat()}\n"
        "internal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n"
        "allow_tools:\n  - curl\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="revoked"):
        load_scope(path)


def test_require_not_revoked_on_constructed_scope() -> None:
    from dropbox.scope import Scope

    demo = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    require_not_revoked(demo)
    revoked = Scope(
        path=demo.path,
        client_name=demo.client_name,
        consent_path=demo.consent_path,
        consent_sha256=demo.consent_sha256,
        window_start=demo.window_start,
        window_end=demo.window_end,
        internal_cidrs=list(demo.internal_cidrs),
        internal_hosts=list(demo.internal_hosts),
        external_hosts=list(demo.external_hosts),
        external_domains=list(demo.external_domains),
        external_ips=list(demo.external_ips),
        revoked=True,
    )
    with pytest.raises(GateError, match="revoked"):
        require_not_revoked(revoked)
    with pytest.raises(GateError, match="revoked"):
        require_live_probe(revoked, "127.0.0.1", [80])


def test_live_probe_refuses_target_outside_scope(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path, "ports_allowed:\n  - 80\n"))
    with pytest.raises(GateError, match="outside authorized SCOPE"):
        require_live_probe(scope, "8.8.8.8", [80])


def test_status_authorized_loads(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path, "  status: authorized\n"))
    require_not_revoked(scope)
    require_live_probe(scope, "127.0.0.1", [80])


def test_status_active_loads(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path, "  status: active\n"))
    require_not_revoked(scope)


def test_status_approved_loads(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path, "  status: approved\n"))
    require_not_revoked(scope)


def test_status_expired_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  status: expired\n"))


def test_status_on_hold_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  status: on-hold\n"))


def test_status_withdrawn_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  status: withdrawn\n"))


def test_status_revoked_by_client_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  status: revoked-by-client\n"))


def test_nested_status_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  status:\n    state: revoked\n"))


def test_toplevel_status_revoked_refuses_load(tmp_path: Path) -> None:
    att, digest = _consent(tmp_path)
    today = date.today()
    path = tmp_path / "SCOPE.yaml"
    path.write_text(
        "client:\n  name: DEMO — not a client estate\nconsent:\n"
        f"  attestation_path: {att}\n  attestation_sha256: {digest}\n"
        "status: revoked\n"
        f"engagement:\n  start: {today.isoformat()}\n"
        f"  end: {(today + timedelta(days=2)).isoformat()}\n"
        "internal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n"
        "allow_tools:\n  - curl\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="revoked"):
        load_scope(path)


def test_toplevel_REVOKED_true_refuses_load(tmp_path: Path) -> None:
    att, digest = _consent(tmp_path)
    today = date.today()
    path = tmp_path / "SCOPE.yaml"
    path.write_text(
        "client:\n  name: DEMO — not a client estate\nconsent:\n"
        f"  attestation_path: {att}\n  attestation_sha256: {digest}\n"
        "REVOKED: true\n"
        f"engagement:\n  start: {today.isoformat()}\n"
        f"  end: {(today + timedelta(days=2)).isoformat()}\n"
        "internal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n"
        "allow_tools:\n  - curl\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="revoked"):
        load_scope(path)


def test_engagement_Revoked_true_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  Revoked: true\n"))


def test_status_Revoked_refuses_load(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="revoked"):
        load_scope(_write_scope(tmp_path, "  Status: Revoked\n"))
