"""prior-unit: dangerous nmap service ports + product (synthetic 10.0.0.x only)."""
from __future__ import annotations
from pathlib import Path
from collectors.inventory_nmap import parse_file

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _xml(tmp_path: Path) -> Path:
    ports = [
        (1524, "bindshell", "", ""),
        (512, "exec", "", ""),
        (5900, "vnc", "", ""),
        (3306, "mysql", "", ""),
        (5432, "postgresql", "", ""),
        (3632, "distccd", "", ""),
        (1099, "rmiregistry", "", ""),
        (6667, "irc", "UnrealIRCd", "3.2.8.1"),
        (2323, "telnet", "Linux telnetd", ""),
        (21, "ftp", "vsftpd", "2.3.4"),
    ]
    body = [
        '<?xml version="1.0"?>',
        "<!DOCTYPE nmaprun>",
        '<nmaprun scanner="nmap" start="1700000000" version="7.90" xmloutputversion="1.05">',
        "<host><status state=\"up\"/>",
        '<address addr="10.0.0.60" addrtype="ipv4"/>',
        "<ports>",
    ]
    for port, svc, prod, ver in ports:
        body.append(
            f'<port protocol="tcp" portid="{port}"><state state="open"/>'
            f'<service name="{svc}" product="{prod}" version="{ver}" method="probed" conf="10"/>'
            f"</port>"
        )
    body += ["</ports>", "</host>", "</nmaprun>"]
    p = tmp_path / "nmap-sev.xml"
    p.write_text("\n".join(body), encoding="utf-8")
    return p


def test_dangerous_ports_raised(tmp_path: Path) -> None:
    recs = parse_file(_xml(tmp_path))
    by = {}
    for r in recs:
        if r.get("kind") != "finding":
            continue
        ex = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        port = str(ex.get("port") or "")
        if port:
            by[port] = r
    expect = {
        "1524": "critical",
        "512": "high",
        "5900": "high",
        "3306": "medium",
        "5432": "medium",
        "3632": "high",
        "1099": "high",
        "6667": "high",
        "2323": "critical",
        "21": "critical",
    }
    for port, want in expect.items():
        assert port in by, f"missing {port}"
        got = str(by[port].get("severity") or "info").lower()
        assert RANK.get(got, 0) >= RANK[want], f"{port} {got} < {want}"
        name = str(by[port].get("name") or "")
        assert not (got == "low" and name.lower().startswith("open port")), name


def test_check_id_stable(tmp_path: Path) -> None:
    recs = parse_file(_xml(tmp_path))
    for r in recs:
        ex = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        if str(ex.get("port")) == "1524":
            assert ex.get("check_id") == "nmap-port-1524/tcp"
