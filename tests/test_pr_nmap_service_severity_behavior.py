"""Fail-before/pass-after: dangerous nmap ports/services raise severity (synthetic 10.0.0.x)."""
from __future__ import annotations

from pathlib import Path

from collectors.inventory_nmap import parse_file

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _xml(tmp_path: Path) -> Path:
    body = [
        '<?xml version="1.0"?>',
        "<nmaprun>",
        '<host><address addr="10.0.0.9" addrtype="ipv4"/>',
        "<ports>",
        (
            '<port protocol="tcp" portid="1524">'
            '<state state="open"/>'
            '<service name="bindshell" method="probed" conf="10"/>'
            "</port>"
        ),
        (
            '<port protocol="tcp" portid="2323">'
            '<state state="open"/>'
            '<service name="telnet" method="probed" conf="10"/>'
            "</port>"
        ),
        (
            '<port protocol="tcp" portid="21">'
            '<state state="open"/>'
            '<service name="ftp" product="vsftpd" version="2.3.4" method="probed" conf="10"/>'
            "</port>"
        ),
        "</ports></host></nmaprun>",
    ]
    p = tmp_path / "nmap-sev-fbpa.xml"
    p.write_text("\n".join(body), encoding="utf-8")
    return p


def test_bind_shell_and_offtable_telnet_raised(tmp_path: Path) -> None:
    recs = parse_file(_xml(tmp_path))
    by = {}
    for r in recs:
        if r.get("kind") != "finding":
            continue
        ex = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        port = str(ex.get("port") or "")
        if port:
            by[port] = r
    assert "1524" in by, sorted(by)
    sev1524 = str(by["1524"].get("severity") or "info").lower()
    assert RANK.get(sev1524, 0) >= RANK["critical"], (
        f"bind shell 1524 must be critical, got {sev1524} name={by['1524'].get('name')}"
    )
    name1524 = str(by["1524"].get("name") or "")
    assert "1524" in name1524 or "bind" in name1524.lower(), name1524

    assert "2323" in by, sorted(by)
    sev2323 = str(by["2323"].get("severity") or "info").lower()
    assert RANK.get(sev2323, 0) >= RANK["critical"], (
        f"telnet on 2323 must be critical, got {sev2323} name={by['2323'].get('name')}"
    )
    name2323 = str(by["2323"].get("name") or "").lower()
    assert "telnet" in name2323, name2323

    assert "21" in by
    sev21 = str(by["21"].get("severity") or "info").lower()
    assert RANK.get(sev21, 0) >= RANK["critical"], f"vsftpd 2.3.4 must be critical, got {sev21}"


def test_check_id_stable_for_bind_shell(tmp_path: Path) -> None:
    recs = parse_file(_xml(tmp_path))
    for r in recs:
        ex = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        if str(ex.get("port")) == "1524":
            assert ex.get("check_id") == "nmap-port-1524/tcp"
            return
    raise AssertionError("missing 1524 finding")
