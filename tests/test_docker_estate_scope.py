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


def test_tls12_is_not_weak_tls() -> None:
    """TLSv1.2 must not map as Weak TLS/SSL. TLSv1.0 still does."""
    from dropbox.orchestrator.adapters import testssl_byo
    from dropbox.orchestrator.poam import map_finding

    weak = map_finding("TLSv1.0 offered", "127.0.0.1", "medium")
    assert weak["mapped"] is True
    assert weak["weakness"] == "Weak TLS/SSL"
    modern = map_finding("TLSv1.2 offered", "127.0.0.1", "medium")
    assert modern["mapped"] is False
    modern13 = map_finding("TLSv1.3 offered", "127.0.0.1", "medium")
    assert modern13["mapped"] is False
    rows = testssl_byo.parse_testssl_text(
        "Testing TLSv1.0  offered\nTesting TLSv1.2  offered\nProtocol  : TLSv1\n",
        "127.0.0.1",
    )
    names = {r["name"] for r in rows}
    assert "TLSv1.0 offered" in names
    assert "TLSv1.2 offered" not in names


def test_insecure_cookie_parser_and_map() -> None:
    """Observed on grc-cookie-24h HEAD / : Set-Cookie session=labonly; Path=/ without Secure/HttpOnly."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    blob = (
        "HTTP/1.1 200 OK\n"
        "Server: nginx/1.31.5\n"
        "Set-Cookie: session=labonly; Path=/\n"
        "\n"
    )
    names = {r["name"] for r in curl_byo.parse_curl_headers(blob, "http://127.0.0.1:19281/")}
    assert "Insecure session cookie" in names
    estate = (
        "HTTP/1.1 200 OK\n"
        "Server: nginx/1.31.5\n"
        "Content-Type: text/html\n"
        "\n"
    )
    estate_names = {r["name"] for r in curl_byo.parse_curl_headers(estate, "http://127.0.0.1:18081/")}
    assert "Insecure session cookie" not in estate_names
    safe = (
        "HTTP/1.1 200 OK\n"
        "Set-Cookie: session=labonly; Path=/; Secure; HttpOnly\n"
        "\n"
    )
    safe_names = {r["name"] for r in curl_byo.parse_curl_headers(safe, "https://127.0.0.1:18443/")}
    assert "Insecure session cookie" not in safe_names
    mapped = map_finding("Insecure session cookie", "127.0.0.1", "medium")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Insecure session cookie"


def test_cookie_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.210.0/24 loopback 19281 Set-Cookie. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.cookie.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.210.0/24" in live
    assert "grc-cookie-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:19281:80" in live
    assert "0.0.0.0:19281" not in live
    assert "grc-estate-c11" not in live
    conf = Path(r"C:\GRC Collector\product-lab\24h\cookie\default.conf").read_text(encoding="utf-8")
    assert "Set-Cookie" in conf
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.210.0/24" not in main


def test_git_metadata_parser_and_map() -> None:
    """Observed on grc-git-24h GET /.git/HEAD : ref: refs/heads/main."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = "ref: refs/heads/main\n"
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:19181/.git/HEAD")
    assert rows and rows[0]["name"] == "Git metadata exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:19181/") == []
    assert curl_byo.parse_curl_body("HTTP/1.1 200 OK\nContent-Type: application/octet-stream\n\n", "http://127.0.0.1:19181/.git/HEAD") == []
    mapped = map_finding("Git metadata exposed", "127.0.0.1", "medium")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Git metadata exposed"


def test_gitweb_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.200.0/24 loopback 19181 .git. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.gitweb.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.200.0/24" in live
    assert "grc-git-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:19181:80" in live
    assert "0.0.0.0:19181" not in live
    assert "grc-estate-c11" not in live
    head = Path(r"C:\GRC Collector\product-lab\24h\gitweb\.git\HEAD").read_text(encoding="utf-8")
    assert "ref: refs/heads/main" in head
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.200.0/24" not in main


def test_stub_status_parser_and_map() -> None:
    """Observed on grc-status-24h GET /nginx_status : Active connections + accepts handled."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = "Active connections: 1 \nserver accepts handled requests\n 2 2 2 \nReading: 0 Writing: 1 Waiting: 0 \n"
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:18981/nginx_status")
    assert rows and rows[0]["name"] == "Web server status page exposed"
    assert curl_byo.parse_curl_body("HTTP/1.1 200 OK\nContent-Type: text/plain\n\n", "http://127.0.0.1:18981/nginx_status") == []
    mapped = map_finding("Web server status page exposed", "127.0.0.1", "low")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Web server status page exposed"
    root = curl_byo.parse_curl_body("<html><body>lab web. not a client LAN.</body></html>", "http://127.0.0.1:18981/")
    assert root == []


def test_status_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.190.0/24 loopback 18981 stub_status. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.status.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.190.0/24" in live
    assert "grc-status-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:18981:80" in live
    assert "0.0.0.0:18981" not in live
    assert "grc-estate-c11" not in live
    conf = Path(r"C:\GRC Collector\product-lab\24h\status\default.conf").read_text(encoding="utf-8")
    assert "stub_status" in conf
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.190.0/24" not in main


def test_directory_listing_parser_and_map() -> None:
    """Observed on grc-dirlist-24h GET / : nginx autoindex Index of / . TRACE was 405."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        "<html>\n<head><title>Index of /</title></head>\n<body>\n"
        "<h1>Index of /</h1><hr><pre><a href=\"../\">../</a>\n"
        "<a href=\"readme.txt\">readme.txt</a>\n</pre><hr></body>\n</html>\n"
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:18881/")
    assert rows and rows[0]["name"] == "Directory listing enabled"
    assert curl_byo.parse_curl_body("HTTP/1.1 200 OK\nServer: nginx\n\n", "http://127.0.0.1:18881/") == []
    mapped = map_finding("Directory listing enabled", "127.0.0.1", "low")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Directory listing enabled"
    assert curl_byo.parse_curl_headers("HTTP/1.1 200 OK\nServer: nginx\n\n", "http://127.0.0.1:18881/")
    # HEAD must not invent a listing
    head_names = {r["name"] for r in curl_byo.parse_curl_headers("HTTP/1.1 200 OK\nServer: nginx\n\n", "http://127.0.0.1:18881/")}
    assert "Directory listing enabled" not in head_names


def test_dirlist_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.180.0/24 loopback 18881 autoindex. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.dirlist.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.180.0/24" in live
    assert "grc-dirlist-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:18881:80" in live
    assert "0.0.0.0:18881" not in live
    assert "grc-estate-c11" not in live
    conf = Path(r"C:\GRC Collector\product-lab\24h\dirlist\default.conf").read_text(encoding="utf-8")
    assert "autoindex on" in conf
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.180.0/24" not in main


def test_tls_hostname_mismatch_parser_and_map() -> None:
    """Observed on grc-mismatch-24h: alpine curl --cacert → SAN does not match IP."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    err = "curl: (60) SSL: no alternative certificate subject name matches target ipv4 address '172.28.170.12'\n"
    rows = curl_byo.parse_curl_tls(err, "https://172.28.170.12/")
    assert rows and rows[0]["name"] == "TLS hostname mismatch"
    mapped = map_finding("TLS hostname mismatch", "172.28.170.12", "medium")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "TLS hostname mismatch"
    assert curl_byo.parse_curl_tls(err, "http://127.0.0.1:18681/") == []
    untrusted = curl_byo.parse_curl_tls(
        "curl: (60) SSL certificate problem: self-signed certificate\n",
        "https://172.28.170.12/",
    )
    assert untrusted and untrusted[0]["name"] == "Untrusted TLS certificate"


def test_mismatch_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.170.0/24 loopback 18681/18643. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.mismatch.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.170.0/24" in live
    assert "grc-mismatch-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:18681:80" in live
    assert "127.0.0.1:18643:443" in live
    assert "0.0.0.0:18681" not in live
    assert "0.0.0.0:18643" not in live
    assert "grc-estate-c11" not in live
    assert "wrong.lab.example" in live
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.170.0/24" not in main


def test_expired_tls_parser_and_map() -> None:
    """Observed on grc-expired-24h: alpine curl --cacert → certificate has expired."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    err = "curl: (60) SSL certificate problem: certificate has expired\n"
    rows = curl_byo.parse_curl_tls(err, "https://127.0.0.1:18343/")
    assert rows and rows[0]["name"] == "Expired TLS certificate"
    assert curl_byo.parse_curl_tls(err, "http://127.0.0.1:18381/") == []
    mapped = map_finding("Expired TLS certificate", "127.0.0.1", "medium")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Expired TLS certificate"
    self_signed = curl_byo.parse_curl_tls(
        "curl: (60) SSL certificate problem: self-signed certificate\n",
        "https://127.0.0.1:18443/",
    )
    assert self_signed and self_signed[0]["name"] == "Untrusted TLS certificate"


def test_weak_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.160.0/24 loopback 18581/18543 TLS 1.0-only. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.weak.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.160.0/24" in live
    assert "grc-weak-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:18581:80" in live
    assert "127.0.0.1:18543:443" in live
    assert "0.0.0.0:18581" not in live
    assert "0.0.0.0:18543" not in live
    assert "grc-estate-c11" not in live
    conf = Path(r"C:\GRC Collector\product-lab\24h\weak\default.conf").read_text(encoding="utf-8")
    assert "ssl_protocols TLSv1;" in conf
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.160.0/24" not in main


def test_expired_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.140.0/24 loopback 18381/18343. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.expired.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.140.0/24" in live
    assert "grc-expired-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:18381:80" in live
    assert "127.0.0.1:18343:443" in live
    assert "0.0.0.0:18381" not in live
    assert "0.0.0.0:18343" not in live
    assert "grc-estate-c11" not in live
    assert "-not_after 20200102000000Z" in live
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.140.0/24" not in main


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
