from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _estate_scope_text() -> str:
    return (ROOT / "dropbox" / "SCOPE.docker-estate.yaml").read_text(encoding="utf-8")


def test_estate_cidr_is_not_lan_10() -> None:
    text = (ROOT / "dropbox" / "SCOPE.docker-estate.yaml").read_text(encoding="utf-8")
    assert "192.168.10.0/24" not in text
    assert "172.28.90.0/24" in text
    assert "pve2" not in text.lower()
    assert "allow_live_exec: true" in text
    assert "Evergreen Docker Estate LLC" in text
    assert "https://127.0.0.1:18443/" in text
    assert "http://127.0.0.1:18081/" in text


def test_eval_24h_compose_is_isolated() -> None:
    text = (ROOT / "docker-compose.eval-24h.yml").read_text(encoding="utf-8")
    nets = [ln.strip() for ln in text.splitlines() if "subnet:" in ln and not ln.lstrip().startswith("#")]
    ips = [ln.strip() for ln in text.splitlines() if "ipv4_address:" in ln and not ln.lstrip().startswith("#")]
    assert any("172.28.120.0/24" in n for n in nets)
    assert not any("192.168.10.0/24" in n for n in nets)
    assert all(not ip.endswith("192.168.10.10") and "192.168.10." not in ip for ip in ips)
    assert all(ip.split(":")[-1].strip().startswith("172.28.120.") for ip in ips)
    assert "grc-estate-c11" not in text
    assert "127.0.0.1:18181:80" in text
    assert "0.0.0.0:18181" not in text
    assert 'GRC_LIVE_SCAN: "0"' in text


def test_estate_tls_sidecar_loopback_only() -> None:
    text = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "127.0.0.1:18443:443" in text
    assert "0.0.0.0:18443" not in text
    assert "estate-tls" in text
    conf = (ROOT / "estate" / "tls" / "default.conf").read_text(encoding="utf-8")
    assert "listen 443 ssl" in conf


def test_example_scope_still_not_live() -> None:
    text = (ROOT / "dropbox" / "SCOPE.example.yaml").read_text(encoding="utf-8")
    assert "allow_live_exec: true" not in text
    assert "allow_live_exec: false" in text
    assert "2026-09-05T09:00:00-07:00" in text


def test_office_lan_cidr_in_scope_is_plan_only(tmp_path, monkeypatch) -> None:
    """T03: adding 192.168.10.0/24 to SCOPE is refused. Do not scan. Plan only."""
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.plan import build_plan
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    poisoned = _estate_scope_text().replace(
        '- "172.28.90.0/24"',
        '- "172.28.90.0/24"\n    - "192.168.10.0/24"',
        1,
    )
    assert '- "192.168.10.0/24"' in poisoned
    path = tmp_path / "SCOPE.lan-poison.yaml"
    path.write_text(poisoned, encoding="utf-8")
    called: list[int] = []
    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)

    def _boom(*_a, **_k):
        called.append(1)
        raise AssertionError("nmap must not exec against office LAN")

    monkeypatch.setattr(nmap_byo.subprocess, "run", _boom)
    scope = load_scope(path)
    assert "192.168.10.0/24" in scope.internal_cidrs
    assert scope.refuse_live() == "forbidden_cidr"
    plan = build_plan(scope)
    assert plan["label"] == "plan-only"
    assert plan["brakes"]["refuse_live"] == "forbidden_cidr"
    dest = tmp_path / "out-lan"
    payload = run(path, "discover", dest=dest)
    assert payload.get("refused") == "forbidden_cidr"
    payload_all = run(path, "all", dest=dest / "all")
    assert payload_all.get("refused") == "forbidden_cidr"
    assert (payload_all.get("grc_export") or {}).get("client_facing_ready") is False
    assert called == []
    desc = nmap_byo.describe(scope, ["192.168.10.0/24"])
    assert desc["would_exec"] is False


def test_office_lan_in_comment_does_not_refuse(tmp_path) -> None:
    """Comments like 'Not 192.168.10.0/24' are not targets."""
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.comment.yaml"
    path.write_text("# Not 192.168.10.0/24\n" + _estate_scope_text(), encoding="utf-8")
    scope = load_scope(path)
    assert "192.168.10.0/24" not in scope.internal_cidrs
    assert scope.forbidden_cidr_reason() is None
    assert scope.refuse_live() is None


def test_office_lan_host_and_default_route_refused(tmp_path) -> None:
    from dropbox.orchestrator.scope import load_scope

    host_poison = _estate_scope_text().replace(
        '- "172.28.90.10"',
        '- "192.168.10.50"',
        1,
    )
    path = tmp_path / "SCOPE.host-poison.yaml"
    path.write_text(host_poison, encoding="utf-8")
    assert load_scope(path).refuse_live() == "forbidden_cidr"
    wide = _estate_scope_text().replace('- "172.28.90.0/24"', '- "0.0.0.0/0"', 1)
    path2 = tmp_path / "SCOPE.default-route.yaml"
    path2.write_text(wide, encoding="utf-8")
    assert load_scope(path2).refuse_live() == "forbidden_cidr"


def test_class_a_host_lan_exact_cidr_refused(tmp_path, monkeypatch) -> None:
    """24h bar: 10.0.0.0/8 is host LAN. Fixture 10.0.0.0/24 is not the whole class A."""
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.plan import build_plan
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    poisoned = _estate_scope_text().replace('- "172.28.90.0/24"', '- "10.0.0.0/8"', 1)
    path = tmp_path / "SCOPE.class-a.yaml"
    path.write_text(poisoned, encoding="utf-8")
    called: list[int] = []
    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)

    def _boom(*_a, **_k):
        called.append(1)
        raise AssertionError("nmap must not exec against 10.0.0.0/8")

    monkeypatch.setattr(nmap_byo.subprocess, "run", _boom)
    scope = load_scope(path)
    assert scope.refuse_live() == "forbidden_cidr"
    plan = build_plan(scope)
    assert plan["label"] == "plan-only"
    assert plan["brakes"]["refuse_live"] == "forbidden_cidr"
    payload = run(path, "discover", dest=tmp_path / "out-class-a")
    assert payload.get("refused") == "forbidden_cidr"
    assert called == []
    desc = nmap_byo.describe(scope, ["10.0.0.0/8"])
    assert desc["would_exec"] is False
    fixture = _estate_scope_text().replace('- "172.28.90.0/24"', '- "10.0.0.0/24"', 1)
    path24 = tmp_path / "SCOPE.class-a-24.yaml"
    path24.write_text(fixture, encoding="utf-8")
    assert load_scope(path24).forbidden_cidr_reason() is None


def test_xwait_compose_isolated_if_present() -> None:
    """T24-wait extra lab: 172.28.130.0/24 loopback 18281/18282/18243. Not office LAN. Not c11."""
    xwait = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.xwait.yml")
    if not xwait.is_file():
        return
    text = xwait.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.130.0/24" in live
    assert "grc-xwait-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:18281:80" in live
    assert "127.0.0.1:18282:80" in live
    assert "127.0.0.1:18243:443" in live
    assert "0.0.0.0:18281" not in live
    assert "0.0.0.0:18243" not in live
    assert "grc-estate-c11" not in live
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.130.0/24" not in main


def test_t06_cold_compose_isolated_if_present() -> None:
    """T06: cold copy uses 172.28.110.0/24 and loopback 19081/19082/19443. Not office LAN."""
    cold = Path(r"C:\GRC Collector\_24h\cold\docker-compose.estate.yml")
    if not cold.is_file():
        return
    text = cold.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.110.0/24" in live
    assert "grc-estate-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:19081:80" in live
    assert "127.0.0.1:19082:80" in live
    assert "127.0.0.1:19443:443" in live
    assert "0.0.0.0:19081" not in live
    assert "0.0.0.0:19443" not in live
    assert "grc-estate-c11" not in live
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.110.0/24" not in main


def test_push_scripts_still_wrap_dead() -> None:
    ps1 = (ROOT / "push_riskready.ps1").read_text(encoding="utf-8")
    assert "WRAP_DEAD" in ps1
    code = "\n".join(ln for ln in ps1.splitlines() if not ln.lstrip().startswith("#")).lower()
    assert "/api/risks" not in code
    sh = (ROOT / "push_riskready.sh").read_text(encoding="utf-8")
    assert "WRAP_DEAD" in sh
    sh_code = "\n".join(ln for ln in sh.splitlines() if not ln.lstrip().startswith("#")).lower()
    assert "/api/risks" not in sh_code
    ciso = (ROOT / "push_ciso.ps1").read_text(encoding="utf-8")
    assert "POST /api/risks" not in ciso
    assert "findings.csv" in ciso
    assert "HITL" in ciso or "clica" in ciso.lower()
