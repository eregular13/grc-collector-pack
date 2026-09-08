from __future__ import annotations

import json
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


def test_kubeconfig_parser_and_map() -> None:
    """Observed on grc-kube-24h GET /kubeconfig : kind Config + clusters."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        "# lab-only dummy kubeconfig. not a client cluster.\n"
        "apiVersion: v1\n"
        "kind: Config\n"
        "clusters:\n- name: lab-only\n"
        "users:\n- name: lab-only\n"
        "  user:\n    token: lab-only-not-a-secret\n"
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:20481/kubeconfig")
    assert rows and rows[0]["name"] == "Kubernetes kubeconfig exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:20481/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n",
        "http://127.0.0.1:20481/kubeconfig",
    ) == []
    dot = curl_byo.parse_curl_body(body, "http://127.0.0.1:20481/.kube/config")
    assert dot and dot[0]["name"] == "Kubernetes kubeconfig exposed"
    mapped = map_finding("Kubernetes kubeconfig exposed", "127.0.0.1", "high")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Kubernetes kubeconfig exposed"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_kube_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.29.13.0/24 loopback 20481 /kubeconfig. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.kube.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.29.13.0/24" in live
    assert "grc-kube-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:20481:80" in live
    assert "0.0.0.0:20481" not in live
    assert "grc-estate-c11" not in live
    cfg = Path(r"C:\GRC Collector\product-lab\24h\kubeweb\kubeconfig").read_text(encoding="utf-8")
    assert "kind: Config" in cfg
    assert "lab-only-not-a-secret" in cfg
    assert "AWS_SECRET_ACCESS_KEY" not in cfg
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.29.13.0/24" not in main


def test_tfstate_parser_and_map() -> None:
    """Observed on grc-tfstate-24h GET /terraform.tfstate : terraform_version + resources."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        "{\n"
        '  "version": 4,\n'
        '  "terraform_version": "1.5.7",\n'
        '  "serial": 1,\n'
        '  "lineage": "lab-only-not-a-secret",\n'
        '  "resources": [{"type": "null_resource", "name": "lab_only"}]\n'
        "}\n"
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:20581/terraform.tfstate")
    assert rows and rows[0]["name"] == "Terraform state file exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:20581/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: application/json\n\n",
        "http://127.0.0.1:20581/terraform.tfstate",
    ) == []
    hidden = curl_byo.parse_curl_body(body, "http://127.0.0.1:20581/.terraform/terraform.tfstate")
    assert hidden and hidden[0]["name"] == "Terraform state file exposed"
    mapped = map_finding("Terraform state file exposed", "127.0.0.1", "high")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Terraform state file exposed"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_tfstate_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.29.14.0/24 loopback 20581 /terraform.tfstate. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.tfstate.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.29.14.0/24" in live
    assert "grc-tfstate-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:20581:80" in live
    assert "0.0.0.0:20581" not in live
    assert "grc-estate-c11" not in live
    state = Path(r"C:\GRC Collector\product-lab\24h\tfweb\terraform.tfstate").read_text(encoding="utf-8")
    assert "terraform_version" in state
    assert "lab-only-not-a-secret" in state
    assert "AWS_SECRET_ACCESS_KEY" not in state
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.29.14.0/24" not in main


def test_dockercfg_parser_and_map() -> None:
    """Observed on grc-dockercfg-24h GET /.docker/config.json : auths + auth."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        "{\n"
        '  "auths": {\n'
        '    "127.0.0.1:5000": {\n'
        '      "auth": "lab-only-not-a-secret"\n'
        "    }\n"
        "  }\n"
        "}\n"
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:20681/.docker/config.json")
    assert rows and rows[0]["name"] == "Docker config.json exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:20681/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: application/json\n\n",
        "http://127.0.0.1:20681/.docker/config.json",
    ) == []
    old = curl_byo.parse_curl_body(body, "http://127.0.0.1:20681/.dockercfg")
    assert old and old[0]["name"] == "Docker config.json exposed"
    mapped = map_finding("Docker config.json exposed", "127.0.0.1", "high")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Docker config.json exposed"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_dockercfg_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.29.15.0/24 loopback 20681 /.docker/config.json. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.dockercfg.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.29.15.0/24" in live
    assert "grc-dockercfg-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:20681:80" in live
    assert "0.0.0.0:20681" not in live
    assert "grc-estate-c11" not in live
    cfg = Path(r"C:\GRC Collector\product-lab\24h\dockercfgweb\config.json").read_text(encoding="utf-8")
    assert '"auths"' in cfg
    assert "lab-only-not-a-secret" in cfg
    assert "AWS_SECRET_ACCESS_KEY" not in cfg
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.29.15.0/24" not in main


def test_private_key_parser_and_map() -> None:
    """Observed on grc-key-24h GET /id_rsa : dummy BEGIN RSA PRIVATE KEY (not a real key)."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "LAB-ONLY-NOT-A-REAL-KEY\n"
        "lab-only-not-a-secret\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:20381/id_rsa")
    assert rows and rows[0]["name"] == "Private key file exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:20381/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n",
        "http://127.0.0.1:20381/id_rsa",
    ) == []
    cert = curl_byo.parse_curl_body(
        "-----BEGIN CERTIFICATE-----\nLAB-ONLY\n-----END CERTIFICATE-----\n",
        "http://127.0.0.1:20381/id_rsa",
    )
    assert cert == []
    mapped = map_finding("Private key file exposed", "127.0.0.1", "high")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Private key file exposed"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_key_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.29.12.0/24 loopback 20381 /id_rsa. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.key.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.29.12.0/24" in live
    assert "grc-key-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:20381:80" in live
    assert "0.0.0.0:20381" not in live
    assert "grc-estate-c11" not in live
    key = Path(r"C:\GRC Collector\product-lab\24h\keyweb\id_rsa").read_text(encoding="utf-8")
    assert "BEGIN RSA PRIVATE KEY" in key
    assert "LAB-ONLY-NOT-A-REAL-KEY" in key
    assert "AWS_SECRET_ACCESS_KEY" not in key
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.29.12.0/24" not in main


def test_graphql_introspection_parser_and_map() -> None:
    """Observed on grc-graphql-24h GET /graphql : __schema + types."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        '{\n  "data": {\n    "__schema": {\n'
        '      "queryType": {"name": "Query"},\n'
        '      "types": [{"name": "Query"}, {"name": "LabOnly"}]\n'
        "    }\n  }\n}\n"
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:20281/graphql")
    assert rows and rows[0]["name"] == "GraphQL introspection enabled"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:20281/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: application/json\n\n",
        "http://127.0.0.1:20281/graphql",
    ) == []
    empty = curl_byo.parse_curl_body('{"data":{"lab":"ok"}}', "http://127.0.0.1:20281/graphql")
    assert empty == []
    mapped = map_finding("GraphQL introspection enabled", "127.0.0.1", "medium")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "GraphQL introspection enabled"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_graphql_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.29.11.0/24 loopback 20281 /graphql. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.graphql.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.29.11.0/24" in live
    assert "grc-graphql-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:20281:80" in live
    assert "0.0.0.0:20281" not in live
    assert "grc-estate-c11" not in live
    spec = Path(r"C:\GRC Collector\product-lab\24h\graphqlweb\graphql.json").read_text(encoding="utf-8")
    assert '"__schema"' in spec
    assert "lab-only-not-a-secret" in spec
    assert "AWS_SECRET_ACCESS_KEY" not in spec
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.29.11.0/24" not in main


def test_actuator_parser_and_map() -> None:
    """Observed on grc-actuator-24h GET /actuator : _links health/info."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        '{\n  "_links": {\n'
        '    "self": {"href": "http://127.0.0.1:20181/actuator"},\n'
        '    "health": {"href": "http://127.0.0.1:20181/actuator/health"}\n'
        "  }\n}\n"
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:20181/actuator")
    assert rows and rows[0]["name"] == "Spring Actuator endpoint exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:20181/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: application/json\n\n",
        "http://127.0.0.1:20181/actuator",
    ) == []
    health = curl_byo.parse_curl_body(
        '{"status":"UP","components":{"ping":{"status":"UP"}}}',
        "http://127.0.0.1:20181/actuator/health",
    )
    assert health and health[0]["name"] == "Spring Actuator endpoint exposed"
    assert curl_byo.parse_curl_body(
        '{"status":"UP","components":{"ping":{"status":"UP"}}}',
        "http://127.0.0.1:20181/health",
    ) == []
    mapped = map_finding("Spring Actuator endpoint exposed", "127.0.0.1", "medium")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Spring Actuator endpoint exposed"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_actuator_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.29.10.0/24 loopback 20181 /actuator. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.actuator.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.29.10.0/24" in live
    assert "grc-actuator-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:20181:80" in live
    assert "0.0.0.0:20181" not in live
    assert "grc-estate-c11" not in live
    idx = Path(r"C:\GRC Collector\product-lab\24h\actuatorweb\actuator.json").read_text(encoding="utf-8")
    assert '"_links"' in idx
    assert "health" in idx
    health = Path(r"C:\GRC Collector\product-lab\24h\actuatorweb\health.json").read_text(encoding="utf-8")
    assert "lab-only-not-a-secret" in health
    assert "AWS_SECRET_ACCESS_KEY" not in health
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.29.10.0/24" not in main


def test_sourcemap_parser_and_map() -> None:
    """Observed on grc-sourcemap-24h GET /app.js.map : version + sources."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        '{\n  "version": 3,\n  "file": "app.js",\n  "sources": ["lab-only.ts"],\n'
        '  "sourcesContent": ["// lab-only dummy source map.\\n"],\n'
        '  "mappings": "AAAA"\n}\n'
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:20081/app.js.map")
    assert rows and rows[0]["name"] == "JavaScript source map exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:20081/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: application/json\n\n",
        "http://127.0.0.1:20081/app.js.map",
    ) == []
    js = curl_byo.parse_curl_body(
        '// lab-only dummy bundle.\n//# sourceMappingURL=app.js.map\n',
        "http://127.0.0.1:20081/app.js",
    )
    assert js == []
    mapped = map_finding("JavaScript source map exposed", "127.0.0.1", "low")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "JavaScript source map exposed"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_sourcemap_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.254.0/24 loopback 20081 app.js.map. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.sourcemap.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.254.0/24" in live
    assert "grc-sourcemap-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:20081:80" in live
    assert "0.0.0.0:20081" not in live
    assert "grc-estate-c11" not in live
    smap = Path(r"C:\GRC Collector\product-lab\24h\mapweb\app.js.map").read_text(encoding="utf-8")
    assert '"version"' in smap
    assert '"sources"' in smap
    assert "lab-only-not-a-secret" in smap
    assert "AWS_SECRET_ACCESS_KEY" not in smap
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.254.0/24" not in main


def test_openapi_parser_and_map() -> None:
    """Observed on grc-openapi-24h GET /openapi.json : openapi 3.0.3."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        '{\n  "openapi": "3.0.3",\n  "info": {"title": "lab-only dummy API", "version": "0.0.0-lab"},\n'
        '  "paths": {"/lab": {"get": {"summary": "lab-only-not-a-secret"}}}\n}\n'
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:19881/openapi.json")
    assert rows and rows[0]["name"] == "OpenAPI specification exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:19881/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: application/json\n\n",
        "http://127.0.0.1:19881/openapi.json",
    ) == []
    swagger = curl_byo.parse_curl_body('{"swagger": "2.0", "info": {"title": "lab"}}', "http://127.0.0.1:19881/swagger.json")
    assert swagger and swagger[0]["name"] == "OpenAPI specification exposed"
    mapped = map_finding("OpenAPI specification exposed", "127.0.0.1", "low")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "OpenAPI specification exposed"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_openapi_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.252.0/24 loopback 19881 /openapi.json. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.openapi.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.252.0/24" in live
    assert "grc-openapi-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:19881:80" in live
    assert "0.0.0.0:19881" not in live
    assert "grc-estate-c11" not in live
    spec = Path(r"C:\GRC Collector\product-lab\24h\openapiweb\openapi.json").read_text(encoding="utf-8")
    assert '"openapi"' in spec
    assert "lab-only-not-a-secret" in spec
    assert "AWS_SECRET_ACCESS_KEY" not in spec
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.252.0/24" not in main


def test_basic_auth_without_tls_parser_and_map() -> None:
    """Observed on grc-basic-24h HEAD / : WWW-Authenticate Basic on http://."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    blob = (
        "HTTP/1.1 401 Unauthorized\n"
        "Server: nginx/1.31.5\n"
        'WWW-Authenticate: Basic realm="lab-only"\n'
        "\n"
    )
    names = {r["name"] for r in curl_byo.parse_curl_headers(blob, "http://127.0.0.1:19981/")}
    assert "HTTP Basic auth without TLS" in names
    assert "Cleartext HTTP" in names
    https_names = {r["name"] for r in curl_byo.parse_curl_headers(blob, "https://127.0.0.1:18443/")}
    assert "HTTP Basic auth without TLS" not in https_names
    estate = (
        "HTTP/1.1 200 OK\n"
        "Server: nginx/1.31.5\n"
        "Content-Type: text/html\n"
        "\n"
    )
    estate_names = {r["name"] for r in curl_byo.parse_curl_headers(estate, "http://127.0.0.1:18081/")}
    assert "HTTP Basic auth without TLS" not in estate_names
    digest = (
        "HTTP/1.1 401 Unauthorized\n"
        'WWW-Authenticate: Digest realm="lab-only"\n'
        "\n"
    )
    digest_names = {r["name"] for r in curl_byo.parse_curl_headers(digest, "http://127.0.0.1:19981/")}
    assert "HTTP Basic auth without TLS" not in digest_names
    mapped = map_finding("HTTP Basic auth without TLS", "127.0.0.1", "high")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "HTTP Basic auth without TLS"
    assert "UNMAPPED" not in mapped["control_refs"]
    clear = map_finding("Cleartext HTTP", "127.0.0.1", "medium")
    assert clear["weakness"] == "Cleartext HTTP"


def test_basic_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.253.0/24 loopback 19981 Basic on HTTP. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.basic.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.253.0/24" in live
    assert "grc-basic-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:19981:80" in live
    assert "0.0.0.0:19981" not in live
    assert "grc-estate-c11" not in live
    conf = Path(r"C:\GRC Collector\product-lab\24h\basicweb\default.conf").read_text(encoding="utf-8")
    assert "WWW-Authenticate" in conf
    assert 'Basic realm="lab-only"' in conf
    assert "AWS_SECRET_ACCESS_KEY" not in conf
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.253.0/24" not in main


def test_prometheus_metrics_parser_and_map() -> None:
    """Observed on grc-metrics-24h GET /metrics : # HELP + # TYPE."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        "# HELP lab_only_info Lab-only dummy metric. not a client estate.\n"
        "# TYPE lab_only_info gauge\n"
        'lab_only_info{note="lab-only-not-a-secret"} 1\n'
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:19781/metrics")
    assert rows and rows[0]["name"] == "Prometheus metrics exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:19781/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n",
        "http://127.0.0.1:19781/metrics",
    ) == []
    actuator = curl_byo.parse_curl_body(body, "http://127.0.0.1:19781/actuator/prometheus")
    assert actuator and actuator[0]["name"] == "Prometheus metrics exposed"
    mapped = map_finding("Prometheus metrics exposed", "127.0.0.1", "low")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Prometheus metrics exposed"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_metrics_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.251.0/24 loopback 19781 /metrics. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.metrics.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.251.0/24" in live
    assert "grc-metrics-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:19781:80" in live
    assert "0.0.0.0:19781" not in live
    assert "grc-estate-c11" not in live
    page = Path(r"C:\GRC Collector\product-lab\24h\metricsweb\metrics").read_text(encoding="utf-8")
    assert "# HELP" in page
    assert "# TYPE" in page
    assert "lab-only-not-a-secret" in page
    assert "AWS_SECRET_ACCESS_KEY" not in page
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.251.0/24" not in main


def test_phpinfo_parser_and_map() -> None:
    """Observed on grc-phpinfo-24h GET /phpinfo.php : phpinfo() + PHP Version."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        "<!DOCTYPE html>\n<html>\n<head><title>phpinfo()</title></head>\n<body>\n"
        "<h1>PHP Version 8.3.0-lab-only</h1>\n"
        "<table>\n<tr><td>System</td><td>Linux lab-only</td></tr>\n"
        "<tr><td>SERVER_API</td><td>lab-only-not-a-secret</td></tr>\n"
        "</table>\n</body>\n</html>\n"
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:19681/phpinfo.php")
    assert rows and rows[0]["name"] == "phpinfo page exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:19681/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n",
        "http://127.0.0.1:19681/phpinfo.php",
    ) == []
    info = curl_byo.parse_curl_body(body, "http://127.0.0.1:19681/info.php")
    assert info and info[0]["name"] == "phpinfo page exposed"
    assert curl_byo.parse_curl_body("<?php echo 'hi';", "http://127.0.0.1:19681/index.php") == []
    mapped = map_finding("phpinfo page exposed", "127.0.0.1", "medium")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "phpinfo page exposed"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_phpinfo_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.250.0/24 loopback 19681 phpinfo.php. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.phpinfo.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.250.0/24" in live
    assert "grc-phpinfo-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:19681:80" in live
    assert "0.0.0.0:19681" not in live
    assert "grc-estate-c11" not in live
    page = Path(r"C:\GRC Collector\product-lab\24h\phpinfo\phpinfo.php").read_text(encoding="utf-8")
    assert "phpinfo()" in page
    assert "PHP Version" in page
    assert "lab-only-not-a-secret" in page
    assert "AWS_SECRET_ACCESS_KEY" not in page
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.250.0/24" not in main


def test_backup_file_parser_and_map() -> None:
    """Observed on grc-bak-24h GET /dump.sql : CREATE TABLE lab_only."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = (
        "-- lab-only dummy dump. not a client database.\n"
        "-- MySQL dump\n"
        "CREATE TABLE lab_only (\n"
        "  id INT PRIMARY KEY,\n"
        "  note VARCHAR(64)\n"
        ");\n"
        "INSERT INTO lab_only VALUES (1, 'lab-only-not-a-secret');\n"
    )
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:19581/dump.sql")
    assert rows and rows[0]["name"] == "Backup file exposed"
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:19581/") == []
    assert curl_byo.parse_curl_body(
        "HTTP/1.1 200 OK\nContent-Type: application/octet-stream\n\n",
        "http://127.0.0.1:19581/dump.sql",
    ) == []
    php_bak = curl_byo.parse_curl_body("<?php // lab-only dummy backup\n", "http://127.0.0.1:19581/config.php.bak")
    assert php_bak and php_bak[0]["name"] == "Backup file exposed"
    assert curl_byo.parse_curl_body("<?php echo 'hi';", "http://127.0.0.1:19581/index.php") == []
    mapped = map_finding("Backup file exposed", "127.0.0.1", "high")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Backup file exposed"
    assert "UNMAPPED" not in mapped["control_refs"]


def test_bak_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.240.0/24 loopback 19581 dump.sql. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.bak.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.240.0/24" in live
    assert "grc-bak-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:19581:80" in live
    assert "0.0.0.0:19581" not in live
    assert "grc-estate-c11" not in live
    dump = Path(r"C:\GRC Collector\product-lab\24h\bakweb\dump.sql").read_text(encoding="utf-8")
    assert "CREATE TABLE lab_only" in dump
    assert "lab-only-not-a-secret" in dump
    assert "AWS_SECRET_ACCESS_KEY" not in dump
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.240.0/24" not in main


def test_env_file_parser_and_map() -> None:
    """Observed on grc-env-24h GET /.env : LAB_TOKEN=lab-only-not-a-secret."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    body = "# lab-only dummy. not a client secret.\nLAB_DB_URL=postgres://lab:lab@127.0.0.1:5432/lab\nLAB_TOKEN=lab-only-not-a-secret\n"
    rows = curl_byo.parse_curl_body(body, "http://127.0.0.1:19481/.env")
    assert rows and rows[0]["name"] == "Environment file exposed"
    assert "lab-only-not-a-secret" not in json.dumps(rows)
    assert curl_byo.parse_curl_body(body, "http://127.0.0.1:19481/") == []
    assert curl_byo.parse_curl_body("HTTP/1.1 200 OK\nContent-Type: application/octet-stream\n\n", "http://127.0.0.1:19481/.env") == []
    mapped = map_finding("Environment file exposed", "127.0.0.1", "high")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Environment file exposed"
    redacted = curl_byo.parse_curl_body("LAB_TOKEN=[REDACTED]\nLAB_DB_URL=[REDACTED]\n", "http://127.0.0.1:18081/.env")
    assert redacted and redacted[0]["name"] == "Environment file exposed"


def test_estate_web_env_static_folded() -> None:
    """R08: dummy /.env on main estate-web with [REDACTED] values, not a second 172.28.230 farm."""
    env = (ROOT / "estate" / "web" / "env-meta" / "lab.env").read_text(encoding="utf-8")
    assert "LAB_TOKEN=[REDACTED]" in env
    assert "LAB_DB_URL=[REDACTED]" in env
    assert "lab-only-not-a-secret" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    conf = (ROOT / "estate" / "nginx-web.conf").read_text(encoding="utf-8")
    assert "location = /.env" in conf
    assert "env-meta" in conf
    compose = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    live = "\n".join(ln for ln in compose.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.90.0/24" in live
    assert "172.28.230.0/24" not in live
    assert "192.168.10.0/24" not in live


def test_env_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.230.0/24 loopback 19481 .env. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.env.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.230.0/24" in live
    assert "grc-env-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:19481:80" in live
    assert "0.0.0.0:19481" not in live
    assert "grc-estate-c11" not in live
    env = Path(r"C:\GRC Collector\product-lab\24h\envweb\.env").read_text(encoding="utf-8")
    assert "LAB_TOKEN=lab-only-not-a-secret" in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.230.0/24" not in main


def test_permissive_cors_parser_and_map() -> None:
    """Observed on grc-cors-24h HEAD / : Access-Control-Allow-Origin: *."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    blob = (
        "HTTP/1.1 200 OK\n"
        "Server: nginx/1.31.5\n"
        "Access-Control-Allow-Origin: *\n"
        "\n"
    )
    names = {r["name"] for r in curl_byo.parse_curl_headers(blob, "http://127.0.0.1:19381/")}
    assert "Permissive CORS policy" in names
    estate = (
        "HTTP/1.1 200 OK\n"
        "Server: nginx/1.31.5\n"
        "Content-Type: text/html\n"
        "\n"
    )
    estate_names = {r["name"] for r in curl_byo.parse_curl_headers(estate, "http://127.0.0.1:18081/")}
    assert "Permissive CORS policy" not in estate_names
    tight = (
        "HTTP/1.1 200 OK\n"
        "Access-Control-Allow-Origin: https://app.example.invalid\n"
        "\n"
    )
    tight_names = {r["name"] for r in curl_byo.parse_curl_headers(tight, "http://127.0.0.1:19381/")}
    assert "Permissive CORS policy" not in tight_names
    mapped = map_finding("Permissive CORS policy", "127.0.0.1", "low")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Permissive CORS policy"


def test_estate_web_cors_stub_folded() -> None:
    """R07: ACAO * on /cors of main estate-web, not a second 172.28.220 farm."""
    conf = (ROOT / "estate" / "nginx-web.conf").read_text(encoding="utf-8")
    assert "location = /cors" in conf
    assert "Access-Control-Allow-Origin *" in conf
    compose = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    live = "\n".join(ln for ln in compose.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.90.0/24" in live
    assert "172.28.220.0/24" not in live
    assert "192.168.10.0/24" not in live


def test_cors_compose_isolated_if_present() -> None:
    """T24-wait extra: 172.28.220.0/24 loopback 19381 ACAO *. Not office LAN. Not c11."""
    path = Path(r"C:\GRC Collector\product-lab\24h\docker-compose.cors.yml")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8-sig")
    live = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.220.0/24" in live
    assert "grc-cors-24h" in live
    assert "192.168.10.0/24" not in live
    assert "127.0.0.1:19381:80" in live
    assert "0.0.0.0:19381" not in live
    assert "grc-estate-c11" not in live
    conf = Path(r"C:\GRC Collector\product-lab\24h\cors\default.conf").read_text(encoding="utf-8")
    assert "Access-Control-Allow-Origin *" in conf
    main = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    assert "172.28.90.0/24" in main
    assert "172.28.220.0/24" not in main


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


def test_estate_web_cookie_stub_folded() -> None:
    """R06: insecure Set-Cookie on /cookie of main estate-web, not a second 172.28.210 farm."""
    conf = (ROOT / "estate" / "nginx-web.conf").read_text(encoding="utf-8")
    assert "location = /cookie" in conf
    assert "Set-Cookie" in conf
    assert "session=labonly" in conf
    assert "HttpOnly" not in conf
    compose = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    live = "\n".join(ln for ln in compose.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.90.0/24" in live
    assert "172.28.210.0/24" not in live
    assert "192.168.10.0/24" not in live


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


def test_estate_web_git_static_folded() -> None:
    """R04: dummy .git on main estate-web, not a second 172.28.200 farm."""
    head = (ROOT / "estate" / "web" / "git-meta" / "HEAD").read_text(encoding="utf-8")
    assert "ref: refs/heads/main" in head
    cfg = (ROOT / "estate" / "web" / "git-meta" / "config").read_text(encoding="utf-8")
    assert "repositoryformatversion" in cfg
    assert "lab.invalid" in cfg
    conf = (ROOT / "estate" / "nginx-web.conf").read_text(encoding="utf-8")
    assert "location /.git/" in conf
    assert "git-meta" in conf
    compose = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    live = "\n".join(ln for ln in compose.splitlines() if not ln.lstrip().startswith("#"))
    assert "estate/nginx-web.conf" in live
    assert "172.28.90.0/24" in live
    assert "172.28.200.0/24" not in live
    assert "192.168.10.0/24" not in live


def test_curl_leak_get_urls_git_root_only() -> None:
    from dropbox.orchestrator.adapters import curl_byo

    assert curl_byo.leak_get_urls("http://127.0.0.1:18081/") == [
        "http://127.0.0.1:18081/.git/HEAD",
        "http://127.0.0.1:18081/listing/",
        "http://127.0.0.1:18081/.env",
    ]
    assert curl_byo.leak_get_urls("http://127.0.0.1:18081") == [
        "http://127.0.0.1:18081/.git/HEAD",
        "http://127.0.0.1:18081/listing/",
        "http://127.0.0.1:18081/.env",
    ]
    assert curl_byo.leak_get_urls("https://127.0.0.1:18443/") == [
        "https://127.0.0.1:18443/.git/HEAD",
        "https://127.0.0.1:18443/listing/",
        "https://127.0.0.1:18443/.env",
    ]
    assert curl_byo.leak_get_urls("http://127.0.0.1:18081/.git/HEAD") == []
    assert curl_byo.leak_get_urls("http://127.0.0.1:18081/listing/") == []
    assert curl_byo.leak_get_urls("http://127.0.0.1:18081/.env") == []
    assert curl_byo.leak_get_urls("http://127.0.0.1:18081/index.html") == []
    assert curl_byo.leak_get_urls("http://192.168.10.1/") == []
    assert curl_byo.leak_get_urls("file:///etc/passwd") == []


def test_curl_leak_head_urls_cookie_root_only() -> None:
    from dropbox.orchestrator.adapters import curl_byo

    assert curl_byo.leak_head_urls("http://127.0.0.1:18081/") == [
        "http://127.0.0.1:18081/cookie",
        "http://127.0.0.1:18081/cors",
    ]
    assert curl_byo.leak_head_urls("http://127.0.0.1:18081") == [
        "http://127.0.0.1:18081/cookie",
        "http://127.0.0.1:18081/cors",
    ]
    assert curl_byo.leak_head_urls("https://127.0.0.1:18443/") == [
        "https://127.0.0.1:18443/cookie",
        "https://127.0.0.1:18443/cors",
    ]
    assert curl_byo.leak_head_urls("http://127.0.0.1:18081/cookie") == []
    assert curl_byo.leak_head_urls("http://127.0.0.1:18081/cors") == []
    assert curl_byo.leak_head_urls("http://192.168.10.1/") == []
    assert curl_byo.leak_head_urls("file:///etc/passwd") == []


def test_curl_execute_gets_git_head_from_root(monkeypatch) -> None:
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.scope import load_scope

    cmds: list[list[str]] = []

    class _Proc:
        def __init__(self, stdout: str, stderr: str = "", returncode: int = 0) -> None:
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    def fake_run(cmd, **kwargs):
        assert kwargs.get("shell") is False
        cmds.append(list(cmd))
        if "-I" in cmd:
            if any(str(a).rstrip("/").endswith("/cookie") for a in cmd):
                return _Proc("HTTP/1.1 200 OK\nSet-Cookie: session=labonly; Path=/\n\n")
            if any(str(a).rstrip("/").endswith("/cors") for a in cmd):
                return _Proc("HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\n\n")
            return _Proc("HTTP/1.1 200 OK\nServer: nginx/1.31.5\n\n")
        if any(str(a).endswith("/.git/HEAD") for a in cmd):
            return _Proc("ref: refs/heads/main\n")
        if any(str(a).endswith("/listing/") for a in cmd):
            return _Proc("<html><head><title>Index of /listing/</title></head><body><h1>Index of /listing/</h1></body></html>\n")
        if any(str(a).endswith("/.env") for a in cmd):
            return _Proc("LAB_TOKEN=[REDACTED]\nLAB_DB_URL=[REDACTED]\n")
        return _Proc("")

    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(curl_byo, "on_path", lambda: True)
    monkeypatch.setattr(curl_byo.subprocess, "run", fake_run)
    scope = load_scope(ROOT / "dropbox" / "SCOPE.docker-estate.yaml")
    rec = curl_byo.execute(scope, ["http://127.0.0.1:18081/"])
    names = {r["name"] for r in rec["findings"]}
    assert "Git metadata exposed" in names
    assert "Directory listing enabled" in names
    assert "Insecure session cookie" in names
    assert "Permissive CORS policy" in names
    assert "Environment file exposed" in names
    assert "Cleartext HTTP" in names
    dumped = json.dumps(rec["findings"])
    assert "lab-only-not-a-secret" not in dumped
    assert "postgres://lab" not in dumped
    assert any("-I" in c for c in cmds)
    git_gets = [c for c in cmds if any(str(a).endswith("/.git/HEAD") for a in c)]
    assert git_gets and all("-I" not in c and "-sS" in c for c in git_gets)
    list_gets = [c for c in cmds if any(str(a).endswith("/listing/") for a in c)]
    assert list_gets and all("-I" not in c and "-sS" in c for c in list_gets)
    env_gets = [c for c in cmds if any(str(a).endswith("/.env") for a in c)]
    assert env_gets and all("-I" not in c and "-sS" in c for c in env_gets)
    cookie_heads = [c for c in cmds if "-I" in c and any(str(a).rstrip("/").endswith("/cookie") for a in c)]
    assert cookie_heads
    cors_heads = [c for c in cmds if "-I" in c and any(str(a).rstrip("/").endswith("/cors") for a in c)]
    assert cors_heads
    assert not any("192.168.10" in str(c) for c in cmds)


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


def test_estate_web_dirlist_static_folded() -> None:
    """R05: autoindex on /listing/ of main estate-web, not a second 172.28.180 farm."""
    readme = (ROOT / "estate" / "web" / "listing" / "readme.txt").read_text(encoding="utf-8")
    assert "lab listing" in readme.lower()
    assert not (ROOT / "estate" / "web" / "listing" / "index.html").is_file()
    conf = (ROOT / "estate" / "nginx-web.conf").read_text(encoding="utf-8")
    assert "location /listing/" in conf
    assert "autoindex on" in conf
    compose = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    live = "\n".join(ln for ln in compose.splitlines() if not ln.lstrip().startswith("#"))
    assert "172.28.90.0/24" in live
    assert "172.28.180.0/24" not in live
    assert "192.168.10.0/24" not in live


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


def test_r10_unmapped_audit_folded_classes() -> None:
    """R10: every folded/live estate class has CPG+CSF. Unknown stays UNMAPPED with a reason. No SMBv1 from HTTP."""
    from dropbox.orchestrator.poam import map_finding

    classes = (
        "Cleartext HTTP",
        "Missing HSTS",
        "Missing X-Frame-Options",
        "Missing CSP",
        "Server banner disclosure",
        "Git metadata exposed",
        "Directory listing enabled",
        "Insecure session cookie",
        "Permissive CORS policy",
        "Environment file exposed",
        "Untrusted TLS certificate",
    )
    for name in classes:
        rec = map_finding(name, "127.0.0.1", "medium")
        assert rec["mapped"] is True, name
        assert rec["cpg"], name
        assert rec["csf"], name
        assert "UNMAPPED" not in rec["control_refs"], name
        assert rec.get("unmapped_reason") is None
        assert "smb" not in rec["weakness"].lower(), name
        assert "445" not in rec["recommended_action"], name
        assert "eternalblue" not in rec["recommended_action"].lower(), name
    unknown = map_finding("Lab-only HTTP widget (not a catalog class)", "127.0.0.1", "low")
    assert unknown["mapped"] is False
    assert unknown["control_refs"] == ["UNMAPPED"]
    assert unknown.get("unmapped_reason") == "no stub rule for this finding text"
    assert unknown["cpg"] == []
    assert unknown["csf"] == []
    poam = ROOT / "engagements" / "docker-estate-product" / "out" / "poam" / "poam.csv"
    live = ROOT / "out-estate" / "poam" / "poam.csv"
    for path in (poam, live):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert "UNMAPPED" not in text
        assert "SMBv1" not in text
        assert "Git metadata exposed" in text
        assert "Directory listing enabled" in text
        assert "Environment file exposed" in text


def test_r09_skip_expired_mismatch_on_main_18443() -> None:
    """R09 skip: one :18443 cert. Host schannel reports UNTRUSTED_ROOT before expiry/CN mismatch.
    24h labs needed alpine curl --cacert on a second project. Not invented from UNTRUSTED_ROOT."""
    from dropbox.orchestrator.adapters import curl_byo

    compose = (ROOT / "docker-compose.estate.yml").read_text(encoding="utf-8")
    live = "\n".join(ln for ln in compose.splitlines() if not ln.lstrip().startswith("#"))
    assert "127.0.0.1:18443:443" in live
    assert "0.0.0.0:18443" not in live
    assert "/CN=localhost" in compose
    assert "-days 2" in compose
    assert "172.28.140.0/24" not in live
    assert "172.28.170.0/24" not in live
    assert "192.168.10.0/24" not in live
    win = (
        "curl: (60) schannel: SEC_E_UNTRUSTED_ROOT (0x80090325) - "
        "The certificate chain was issued by an authority that is not trusted.\n"
    )
    names = {r["name"] for r in curl_byo.parse_curl_tls(win, "https://127.0.0.1:18443/")}
    assert names == {"Untrusted TLS certificate"}
    assert "Expired TLS certificate" not in names
    assert "TLS hostname mismatch" not in names


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
