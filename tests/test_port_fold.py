"""Port-only nmap rows fold into a specific finding on the same host+port."""

from __future__ import annotations

import csv
from pathlib import Path

from collectors.grc_loader import load
from shared.ciso_shape import EXCLUDED_HEADER, assert_count_consistency
from shared.control_map import POAM_EXCLUDE_REASONS, iter_poam_decisions, poam_breakdown
from shared.io_util import out_dir, write_canonical
from shared.poam_ledger import assign_poam_id, fp_v1
from shared.port_fold import (
    SUPERSEDED_REASON,
    egp_id_for,
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
