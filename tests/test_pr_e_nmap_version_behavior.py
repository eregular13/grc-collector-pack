"""prior-unit behavior: nmap version severity bump via existing inventory_nmap entrypoint.

Does not import shared.nmap_version_sev (new on pr-e). Exercises tip-existing
collectors.inventory_nmap.parse_file end-to-end with synthetic XML only.
"""
from __future__ import annotations

from pathlib import Path

from collectors import inventory_nmap


def _nmap_xml(*, product: str, version: str, port: str = "22", service: str = "ssh") -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" start="1700000000" startstr="Wed Nov 15 00:00:00 2023" version="7.90" xmloutputversion="1.05">
<host><status state="up"/>
<address addr="10.0.0.9" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="{port}">
  <state state="open"/>
  <service name="{service}" product="{product}" version="{version}" method="probed" conf="10"/>
</port>
</ports>
</host>
</nmaprun>
"""


def test_openssh_old_version_raises_severity_via_inventory_nmap(tmp_path: Path) -> None:
    dest = tmp_path / "nmap-old-ssh.xml"
    dest.write_text(
        _nmap_xml(product="OpenSSH", version="5.9p1 Debian 4", port="22", service="ssh"),
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    finds = [r for r in recs if r.get("kind") == "finding"]
    assert finds, "expected at least one finding from synthetic nmap xml"
    ssh = next(r for r in finds if (r.get("extra") or {}).get("port") == "22")
    # pr-e bumps outdated OpenSSH open-port from low → medium and keeps version text
    assert ssh.get("severity") == "medium", (
        f"expected medium severity for OpenSSH 5.9p1 open port, got {ssh.get('severity')!r}"
    )
    blob = f"{ssh.get('name')} {ssh.get('description')}"
    assert "OpenSSH" in blob
    assert "5.9p1" in blob
