from client_env_eval.engagement import lab_engagement, require_authz
from client_env_eval.sensors import collect
import pytest


def test_lab_ready():
    eng = lab_engagement()
    ok, _ = eng.is_live_ready()
    assert ok


def test_oos_blocked():
    eng = lab_engagement()
    with pytest.raises(PermissionError):
        require_authz(eng, "8.8.8.8", [80])


def test_collect_shape():
    # offline-ish: collect localhost may vary; just ensure structure if target fails soft
    data = collect("127.0.0.1", ports=[9], http_urls=[])  # discard port unlikely open
    assert "findings" in data
    assert data["schema"].startswith("evergreen.client_env_eval")


def test_new_sensors_callable():
    from client_env_eval.sensors import (
        sense_cookie_flags,
        sense_cors,
        sense_ssh_banner,
        sense_cleartext_admin,
    )
    assert sense_cookie_flags("http://127.0.0.1:9/") == [] or isinstance(sense_cookie_flags("http://127.0.0.1:9/"), list)
    assert isinstance(sense_cors("http://127.0.0.1:9/"), list)
    assert isinstance(sense_ssh_banner("127.0.0.1", 9), list)
    assert isinstance(sense_cleartext_admin("h", [80]), list)
    assert any(f.get("sensor") == "sense-cleartext-http" for f in sense_cleartext_admin("h", [80]))


def test_scan_mode_real():
    data = collect("127.0.0.1", ports=[9], http_urls=[])
    assert data["scan_mode"] == "real"


def test_extra_sensors_importable():
    from client_env_eval.sensors import (
        sense_http_methods,
        sense_tech_disclosure,
        sense_dir_listing,
        sense_service_ports,
    )
    assert sense_service_ports("127.0.0.1", [9]) == [] or isinstance(sense_service_ports("127.0.0.1", [9]), list)
    assert isinstance(sense_http_methods("http://127.0.0.1:9/"), list)


def test_surface_empty_when_no_ports_open(monkeypatch):
    from client_env_eval import sensors as s
    monkeypatch.setattr(s, "_tcp_open", lambda host, port, timeout=2.0: False)
    assert s.sense_surface("192.0.2.1", [22, 80]) == []


def test_service_ports_flags_redis_when_open(monkeypatch):
    from client_env_eval import sensors as s
    monkeypatch.setattr(s, "_tcp_open", lambda host, port, timeout=2.0: port == 6379)
    f = s.sense_service_ports("192.0.2.1", [6379, 80])
    assert any(x.get("sensor") == "sense-service-exposure" for x in f)
    assert any("Redis" in (x.get("title") or "") for x in f)


def test_cleartext_http_when_80_only(monkeypatch):
    from client_env_eval import sensors as s
    f = s.sense_cleartext_admin("192.0.2.1", [80])
    assert any(x.get("sensor") == "sense-cleartext-http" for x in f)


def test_https_redirect_sensor_skips_without_both_ports():
    from client_env_eval.sensors import sense_http_to_https_redirect
    assert sense_http_to_https_redirect("example.com", [80]) == []
    assert sense_http_to_https_redirect("example.com", [443]) == []
