"""Metis §13.4 P6/P7: protocol-aware nmap port risk. UDP is never labelled TCP."""

from __future__ import annotations

from pathlib import Path

from collectors import inventory_nmap
from shared.control_map import poam_decision
from shared.schema import canon_severity

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
DEMO = ROOT / "fixtures" / "demo"


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r["kind"] == "finding"]


def test_udp_445_open_filtered_not_high_smb() -> None:
    recs = inventory_nmap.parse_file(SAMPLES / "nmap-udp-proto.xml")
    findings = _findings(recs)
    udp445 = [
        r
        for r in findings
        if (r.get("extra") or {}).get("port") == "445"
        and (r.get("extra") or {}).get("protocol") == "udp"
    ]
    assert udp445
    for rec in udp445:
        assert rec["severity"] == canon_severity("info")
        assert rec["name"] != "SMB 445 exposed"
        assert "SMB" not in rec["name"]
        assert "Administrative share" not in rec["name"]
        assert "TCP" not in rec["description"]
        assert "UDP/445" in rec["description"]
        assert rec["extra"].get("state") == "open|filtered"
        assert rec["extra"].get("not_a_weakness") is True
        assert poam_decision(rec)["include"] is False
        assert poam_decision(rec)["reason"] == "not_a_weakness"
        assert rec["ref_id"].endswith("-445-udp")


def test_snmp_161_udp_open_is_medium() -> None:
    recs = inventory_nmap.parse_file(SAMPLES / "nmap-udp-proto.xml")
    findings = _findings(recs)
    snmp = [
        r
        for r in findings
        if (r.get("extra") or {}).get("port") == "161"
        and (r.get("extra") or {}).get("protocol") == "udp"
    ]
    assert len(snmp) == 1
    rec = snmp[0]
    assert rec["severity"] == canon_severity("medium")
    assert "SNMP" in rec["name"]
    assert rec["assets"] == ["10.11.1.22"]
    assert "TCP" not in rec["description"]
    assert "UDP/161" in rec["description"]
    assert rec["extra"].get("state") in {None, "open"}
    assert poam_decision(rec)["include"] is True
    assert rec["ref_id"].endswith("-161-udp")
    assert rec["ref_id"].startswith("NMAP-")


def test_tcp_risky_unchanged() -> None:
    recs = inventory_nmap.parse_file(DEMO / "nmap" / "scan.xml")
    findings = _findings(recs)
    by_port = {
        str((r.get("extra") or {}).get("port")): r
        for r in findings
        if (r.get("extra") or {}).get("protocol") == "tcp"
    }
    assert by_port["445"]["name"] == "SMB 445 exposed"
    assert by_port["445"]["severity"] == canon_severity("high")
    assert "TCP/445" in by_port["445"]["description"]
    assert by_port["445"]["ref_id"].endswith("-445-tcp")
    assert by_port["23"]["name"] == "Telnet exposed"
    assert by_port["23"]["severity"] == canon_severity("critical")
    assert by_port["3389"]["name"] == "RDP exposed"
    assert by_port["3389"]["severity"] == canon_severity("medium")
    assert by_port["22"]["name"] == "SSH exposed"
    assert by_port["22"]["severity"] == canon_severity("low")
    assert inventory_nmap.RISKY[("445", "tcp")][0] == "high"
    assert inventory_nmap.RISKY[("161", "udp")][0] == "medium"
    assert inventory_nmap.RISKY[("69", "udp")][0] == "high"
    assert ("445", "udp") not in inventory_nmap.RISKY
