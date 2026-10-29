"""Fail-before/pass-after: classify_name folds loopback + single-label distro suffix."""
from __future__ import annotations

from shared.asset_ids import classify_name


def test_classify_name_loopback_folds_to_loopback_ip():
    got = classify_name("localhost")
    ips = got.get("ip") or []
    if isinstance(ips, str):
        ips = [ips]
    assert "127.0.0.1" in [str(x) for x in ips], got
    # must not keep bare NETBIOS-only localhost identity as the fold target
    assert got.get("netbios") != "LOCALHOST" or "127.0.0.1" in [str(x) for x in ips]


def test_classify_name_distro_suffix_single_label_host():
    got = classify_name("host1.debian")
    # fold host1.debian → host1 hostname, not fqdn host1.debian
    assert got.get("hostname") == "host1", got
    assert got.get("fqdn") != "host1.debian", got


def test_classify_name_multi_label_local_fqdn_preserved():
    got = classify_name("web.corp.local")
    assert got.get("fqdn") == "web.corp.local", got
