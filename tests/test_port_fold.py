"""Port-only nmap rows fold into a specific finding on the same host+port."""

from __future__ import annotations

import csv
import re
from pathlib import Path

import pytest

from collectors.grc_loader import load
from shared.ciso_shape import EXCLUDED_HEADER, assert_count_consistency
from shared.control_map import POAM_EXCLUDE_REASONS, iter_poam_decisions, poam_breakdown
from shared.io_util import out_dir, write_canonical
from shared.poam_ledger import assign_poam_id, fp_v1
from shared.port_fold import (
    SUPERSEDED_REASON,
    _strip_host,
    _url_has_explicit_port,
    _valid_port,
    egp_id_for,
    finding_hosts,
    finding_port,
    fold_port_only_into_specific,
    is_port_only_finding,
    is_specific_port_finding,
    pick_superseder,
    port_only_superseders,
)
from shared.schema import make_record


def _port_only(**kwargs):
    extra = dict(kwargs.pop("extra", {}) or {})
    extra.setdefault("port", "443")
    extra.setdefault("service", "https")
    extra.setdefault("ip", "10.0.0.30")
    extra.setdefault("protocol", "tcp")
    defaults = dict(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-web-443",
        name="HTTPS/TLS exposed",
        description="web-01.corp.local has open TCP/443 (https).",
        severity="medium",
        category="exposure",
        assets=["web-01.corp.local"],
        labels=["nmap", "inventory", "port-443"],
        extra=extra,
    )
    defaults.update(kwargs)
    return make_record(**defaults)


def _specific(**kwargs):
    extra = dict(kwargs.pop("extra", {}) or {})
    extra.setdefault("port", "443")
    extra.setdefault("protocol", "tcp")
    extra.setdefault("template_id", "cve-2014-0160")
    extra.setdefault("cve", "CVE-2014-0160")
    extra.setdefault("tool", "nuclei")
    extra.setdefault("ip", "10.0.0.30")
    defaults = dict(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-heartbleed-web",
        name="Heartbleed on TLS",
        description="OpenSSL heartbeat on 10.0.0.30:443",
        severity="high",
        category="vulnerability",
        assets=["https://web-01.corp.local"],
        labels=["vuln", "nuclei"],
        extra=extra,
    )
    defaults.update(kwargs)
    return make_record(**defaults)


def test_classifies_port_only_vs_specific() -> None:
    port = _port_only()
    spec = _specific()
    assert is_port_only_finding(port)
    assert not is_specific_port_finding(port)
    assert is_specific_port_finding(spec)
    assert not is_port_only_finding(spec)


def test_port_only_alone_is_not_superseded() -> None:
    port = _port_only()
    assert port_only_superseders([port]) == {}
    decisions = iter_poam_decisions([port], lighter=False)
    rec, decision = decisions[0]
    assert rec is port
    assert decision["include"] is True
    assert decision["reason"] != SUPERSEDED_REASON


def test_fold_same_host_port_excludes_port_only_and_keeps_source() -> None:
    port = _port_only()
    spec = _specific()
    mapping = fold_port_only_into_specific([port, spec])
    assert mapping[port["ref_id"]] is spec
    extra = spec["extra"]
    assert "inventory-nmap" in (extra.get("sources") or [])
    assert "nmap" in (spec.get("labels") or [])
    assert "nmap" in (extra.get("tools") or [])
    assert any(p.get("ref_id") == port["ref_id"] for p in (extra.get("provenance") or []))
    assert port["ref_id"] in (extra.get("folded_port_only") or [])
    decisions = {r["ref_id"]: d for r, d in iter_poam_decisions([port, spec], lighter=False)}
    assert decisions[spec["ref_id"]]["include"] is True
    assert decisions[port["ref_id"]]["include"] is False
    assert decisions[port["ref_id"]]["reason"] == SUPERSEDED_REASON
    assert decisions[port["ref_id"]]["superseded_by"] == egp_id_for(spec)
    assert SUPERSEDED_REASON in POAM_EXCLUDE_REASONS
    breakdown = poam_breakdown([port, spec], lighter=False)
    assert breakdown["weaknesses_total"] == 2
    assert breakdown["poam_included"] == 1
    assert breakdown["excluded_by_reason"] == {SUPERSEDED_REASON: 1}


def test_finding_port_from_http_url_when_extra_port_absent() -> None:
    rec = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-url",
        name="Exposed admin panel",
        description="Unauthenticated admin UI",
        severity="medium",
        category="vulnerability",
        assets=["http://10.0.0.20/admin"],
        labels=["nuclei"],
        extra={"template_id": "exposed-panel"},
    )
    assert finding_port(rec) == "80"


def test_host_ip_and_url_normalize_to_same_key() -> None:
    port = _port_only(assets=["web-01.corp.local"], extra={"port": "80", "ip": "10.0.0.20"})
    spec = _specific(
        assets=["http://10.0.0.20/admin"],
        extra={
            "template_id": "exposed-panel",
            "cve": "",
            "tool": "nuclei",
            "port": "80",
        },
    )
    spec["name"] = "Exposed admin panel"
    spec["description"] = "Unauthenticated admin UI"
    spec["severity"] = "medium"
    spec["ref_id"] = "VULN-panel-20"
    assert port_only_superseders([port, spec])[port["ref_id"]] is spec


def test_protocol_mismatch_does_not_fold() -> None:
    port = _port_only(extra={"port": "53", "protocol": "udp", "service": "domain"})
    spec = _specific(
        extra={
            "port": "53",
            "protocol": "tcp",
            "plugin_id": "999",
            "tool": "nessus",
            "template_id": "",
            "cve": "",
        }
    )
    spec["ref_id"] = "VULN-dns-tcp"
    spec["labels"] = ["vuln", "nessus"]
    spec["name"] = "DNS TCP zone transfer"
    assert port_only_superseders([port, spec]) == {}


def test_missing_protocol_still_matches() -> None:
    port = _port_only(extra={"port": "445", "ip": "10.0.0.50", "service": "microsoft-ds"})
    port["extra"].pop("protocol", None)
    spec = _specific(
        assets=["filesrv.corp.local"],
        extra={
            "port": "445",
            "protocol": "tcp",
            "plugin_id": "42411",
            "id": "42411",
            "tool": "nessus",
            "template_id": "",
            "cve": "",
            "ip": "10.0.0.50",
        },
    )
    spec["ref_id"] = "VULN-nessus-42411"
    spec["labels"] = ["vuln", "nessus"]
    spec["name"] = "SMB shares unprivileged access"
    assert port_only_superseders([port, spec])[port["ref_id"]] is spec


def test_multiple_specifics_pick_highest_severity_then_lowest_egp() -> None:
    port = _port_only()
    high_a = _specific(ref_id="VULN-aaa", extra={"template_id": "tpl-a", "cve": "CVE-2020-0001"})
    high_b = _specific(ref_id="VULN-bbb", extra={"template_id": "tpl-b", "cve": "CVE-2020-0002"})
    med = _specific(
        ref_id="VULN-med",
        severity="medium",
        extra={"template_id": "tpl-med", "cve": "CVE-2020-0003"},
    )
    winner = pick_superseder([high_a, high_b, med])
    expected = min(
        [high_a, high_b],
        key=lambda rec: (assign_poam_id(fp_v1(rec), {}), rec["ref_id"]),
    )
    assert winner is expected
    mapping = port_only_superseders([port, high_a, high_b, med])
    assert mapping[port["ref_id"]] is expected


def test_loader_writes_excluded_egp_and_keeps_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    def _asset(name: str, ref: str) -> dict:
        return make_record(
            kind="asset",
            source="inventory-nmap",
            ref_id=ref,
            name=name,
            description=f"Host {name}",
            category="host",
            assets=[name],
            labels=["nmap"],
            extra={"asset_type": "PR"},
        )

    port = _port_only()
    spec = _specific()
    lone = _port_only(
        ref_id="NMAP-jump-22",
        name="SSH exposed",
        description="jump.corp.local has open TCP/22 (ssh).",
        severity="low",
        assets=["jump.corp.local"],
        labels=["nmap", "inventory", "port-22"],
        extra={"port": "22", "service": "ssh", "ip": "10.0.0.40", "protocol": "tcp"},
    )
    write_canonical(
        "inventory-nmap",
        [
            _asset("web-01.corp.local", "NMAP-asset-web"),
            _asset("jump.corp.local", "NMAP-asset-jump"),
            port,
            lone,
        ],
    )
    write_canonical("vuln-scan", [_asset("https://web-01.corp.local", "VULN-asset-web"), spec])
    summary = load()
    shape = assert_count_consistency(tmp_path, summary)
    assert summary["weaknesses_total"] == summary["poam_included"] + summary["excluded"]
    assert summary["excluded_by_reason"].get(SUPERSEDED_REASON) == 1
    assert shape["poam"] == summary["poam"]
    excluded_path = out_dir() / "poam" / "excluded.csv"
    first = excluded_path.read_text(encoding="utf-8").splitlines()[0]
    assert first == EXCLUDED_HEADER
    with excluded_path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    folded = next(row for row in rows if row["finding_ref_id"] == port["ref_id"])
    assert folded["excluded_reason"] == SUPERSEDED_REASON
    assert folded["superseded_by"] == egp_id_for(spec)
    assert folded["superseded_by"].startswith("EGP-")
    with (out_dir() / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        poam = list(csv.DictReader(fh))
    refs = {row["finding_ref_id"] for row in poam}
    assert spec["ref_id"] in refs
    assert lone["ref_id"] in refs
    assert port["ref_id"] not in refs
    det = " ".join(
        row.get("detector_source") or ""
        for row in poam
        if row["finding_ref_id"] == spec["ref_id"]
    )
    assert "nmap" in det


V6 = "2001:4860:4860::8888"


def test_strip_host_malformed_brackets_do_not_raise() -> None:
    """#207: extra.host / matched_at garbage must not abort the load."""
    host, port, scheme = _strip_host("https://[notanip]:6379")
    assert host == "notanip"
    assert port == "6379"
    assert scheme == "https"
    host, port, scheme = _strip_host("https://[2001:4860:4860::8888")
    assert host == ""
    assert port == ""
    assert scheme == "https"
    rec = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-bad-bracket",
        name="Redis without auth",
        description="Malformed host tokens must not crash fold.",
        severity="high",
        category="vulnerability",
        assets=["https://[notanip]:6379"],
        labels=["nuclei"],
        extra={
            "host": "https://[notanip]:6379",
            "matched_at": "https://[2001:4860:4860::8888",
            "template_id": "exposed-redis",
        },
    )
    assert "notanip" in finding_hosts(rec)
    assert finding_port(rec) == "6379"
    rec["extra"]["host"] = "https://[2001:4860:4860::8888"
    rec["extra"]["port"] = ""
    rec["assets"] = ["https://[2001:4860:4860::8888"]
    assert finding_hosts(rec) == set()
    assert finding_port(rec) == ""


def test_strip_host_valid_bracketed_ipv6_with_and_without_port() -> None:
    host, port, scheme = _strip_host(f"https://[{V6}]/")
    assert host == V6
    assert port == ""
    assert scheme == "https"
    host, port, scheme = _strip_host(f"https://[{V6}]:443/")
    assert host == V6
    assert port == "443"
    host, port, scheme = _strip_host(f"[{V6}]")
    assert host == V6
    assert port == ""
    host, port, scheme = _strip_host(f"[{V6}]:6379")
    assert host == V6
    assert port == "6379"


def test_ipv6_url_and_bare_address_fold_on_same_host_port() -> None:
    port = _port_only(
        assets=[V6],
        extra={"port": "443", "ip": V6, "protocol": "tcp", "service": "https"},
    )
    spec = _specific(
        assets=[f"https://[{V6}]:443/"],
        extra={
            "template_id": "cve-2014-0160",
            "cve": "CVE-2014-0160",
            "tool": "nuclei",
            "host": f"https://[{V6}]:443/",
            "matched_at": f"https://[{V6}]:443/",
            "port": "443",
            "protocol": "tcp",
        },
    )
    assert port_only_superseders([port, spec])[port["ref_id"]] is spec


def test_malformed_host_does_not_abort_fold_or_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = _specific(
        ref_id="VULN-bad-bracket",
        extra={
            "host": "https://[notanip]:6379",
            "matched_at": "https://[2001:4860:4860::8888",
            "port": "6379",
            "template_id": "exposed-redis",
            "cve": "",
        },
    )
    port = _port_only()
    spec = _specific()
    mapping = fold_port_only_into_specific([bad, port, spec])
    assert mapping[port["ref_id"]] is spec
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    write_canonical("vuln-scan", [bad, spec])
    write_canonical("inventory-nmap", [port])
    summary = load()
    assert summary["poam"] >= 1
    assert (tmp_path / "poam" / "poam.csv").is_file()


def test_strip_host_invalid_explicit_port_does_not_raise_or_invent() -> None:
    assert _strip_host("http://h:99999") == ("h", "", "http")
    assert _strip_host("http://h:abc") == ("h", "", "http")
    assert _strip_host("http://h:0") == ("h", "", "http")
    assert _strip_host("http://u@[x") == ("", "", "http")
    assert _strip_host("h:8443") == ("h", "8443", "")
    rec = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-bad-port",
        name="Exposed panel",
        description="Invalid port must not become 80.",
        severity="medium",
        category="vulnerability",
        assets=["http://foo:99999/admin"],
        labels=["nuclei"],
        extra={"template_id": "exposed-panel"},
    )
    assert finding_port(rec) == ""
    port80 = _port_only(
        assets=["foo"],
        extra={"port": "80", "ip": "foo", "protocol": "tcp", "service": "http"},
    )
    spec = _specific(
        assets=["http://foo:99999/admin"],
        extra={
            "template_id": "exposed-panel",
            "cve": "",
            "tool": "nuclei",
            "port": "",
        },
    )
    spec["extra"].pop("port", None)
    assert port_only_superseders([port80, spec]) == {}


def test_notanip_url_also_folds_with_bare_notanip_port() -> None:
    port = _port_only(
        assets=["notanip"],
        extra={"port": "6379", "ip": "notanip", "protocol": "tcp", "service": "redis"},
    )
    spec = _specific(
        assets=["https://[notanip]:6379"],
        extra={
            "template_id": "exposed-redis",
            "cve": "",
            "tool": "nuclei",
            "host": "https://[notanip]:6379",
            "port": "6379",
            "protocol": "tcp",
        },
    )
    assert port_only_superseders([port, spec])[port["ref_id"]] is spec


def test_poam_md_escapes_scanner_hostnames(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    evil = "evil](http://evil.invalid)<img src=x onerror=alert(3)>|x|"
    spec = _specific(
        assets=[evil],
        extra={
            "template_id": "cve-2014-0160",
            "cve": "CVE-2014-0160",
            "tool": "nuclei",
            "port": "443",
            "ip": "10.0.0.30",
        },
    )
    write_canonical("vuln-scan", [spec])
    load()
    md = (tmp_path / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "<img" not in md
    assert "|x|" not in md
    assert "&lt;" in md or "\\|" in md


def test_valid_port_rejects_unicode_digits_and_bounds() -> None:
    assert _valid_port("443") == "443"
    assert _valid_port("65535") == "65535"
    assert _valid_port("1") == "1"
    assert _valid_port("0") == ""
    assert _valid_port("65536") == ""
    assert _valid_port("0443") == "0443"
    assert _valid_port("²") == ""
    assert _valid_port("³¹") == ""
    assert _valid_port("٤٤٣") == ""
    assert _valid_port("443 ") == "443"
    assert _valid_port("abc") == ""
    assert _valid_port("") == ""


def test_strip_host_unicode_digits_do_not_raise() -> None:
    assert _strip_host("10.0.0.1:³¹") == ("10.0.0.1", "", "")
    assert _strip_host("h:²")[1] == ""
    assert _strip_host("[::1]:²") == ("::1", "", "")
    assert _strip_host("https://[notanip]:²/")[1] == ""
    assert _strip_host("ptr.invalid:³¹") == ("ptr.invalid", "", "")
    assert finding_port(
        make_record(
            kind="finding",
            source="inventory-nmap",
            ref_id="NMAP-sup",
            name="Open port",
            description="superscript port",
            severity="low",
            category="exposure",
            assets=["10.0.0.1:³¹"],
            labels=["nmap"],
            extra={"host": "h:²"},
        )
    ) == ""


def test_unicode_digit_ports_load_without_abort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    rows = []
    for i, asset in enumerate(
        ("10.0.0.1:³¹", "h:²", "[::1]:²", "https://[notanip]:²/", "ptr.invalid:³¹")
    ):
        rows.append(
            _specific(
                ref_id=f"VULN-sup-{i}",
                assets=[asset],
                extra={
                    "template_id": "exposed-panel",
                    "cve": "",
                    "tool": "nuclei",
                    "host": asset,
                    "port": "",
                },
            )
        )
        rows[-1]["extra"].pop("port", None)
    write_canonical("vuln-scan", rows)
    summary = load()
    assert summary["poam"] >= 1
    assert (tmp_path / "poam" / "poam.csv").is_file()
    for rec in rows:
        assert finding_port(rec) == ""


def test_url_has_explicit_port_branches() -> None:
    assert _url_has_explicit_port("http://h:443/") is True
    assert _url_has_explicit_port("http://u:p@h:443/") is True
    assert _url_has_explicit_port("https://[::1]:443/") is True
    assert _url_has_explicit_port("//h:8080/x") is True
    assert _url_has_explicit_port("http://h/") is False
    assert _url_has_explicit_port("http://h:/") is False
    assert _url_has_explicit_port("https://[::1]/") is False
    assert _url_has_explicit_port("https://[bad") is False
    assert _url_has_explicit_port("") is False
    assert _url_has_explicit_port("http://h:99999/") is True


def test_finding_port_continues_past_invalid_explicit() -> None:
    rec = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-later-good",
        name="Exposed panel",
        description="later valid candidate wins",
        severity="medium",
        category="vulnerability",
        assets=["http://foo:99999/admin", "https://foo:443/ok"],
        labels=["nuclei"],
        extra={"template_id": "exposed-panel"},
    )
    rec["extra"].pop("port", None)
    assert finding_port(rec) == "443"
    empty_default = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-empty-colon",
        name="HTTP",
        description="RFC default",
        severity="low",
        category="exposure",
        assets=["http://h:/"],
        labels=["nuclei"],
        extra={"template_id": "http-default"},
    )
    empty_default["extra"].pop("port", None)
    assert finding_port(empty_default) == "80"
    spaced = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-space-port",
        name="TLS",
        description="space after port",
        severity="low",
        category="exposure",
        assets=["https://h:443 /x"],
        labels=["nuclei"],
        extra={"template_id": "tls"},
    )
    spaced["extra"].pop("port", None)
    assert finding_port(spaced) == "443"
