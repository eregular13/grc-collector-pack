"""Fail-before/pass-after: every nmap CVE is accounted for in poam.csv.

Two ports on one host each get a lower-severity vulners rollup. Both rollups
share check_id "vulners-rollup" and the host asset, so _dedupe used to fold
the port-80 rollup into the port-22 one as DUPLICATE_INSTANCE. The excluded
row carried no CVE ids and the ledger dropped them. A confirmed http-vuln-*
NSE script (State: VULNERABLE) was never parsed at all.
Synthetic data only (203.0.113.30, CVE-2099-*).
"""
from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_VULNERS = (
    '<script id="vulners" output="cpe&#xa;&#x9;{c}&#x9;5.0&#x9;https://example.test/{c}">'
    '<table key="cpe:/a:example:app:1.0"><table><elem key="is_exploit">false</elem>'
    '<elem key="cvss">5.0</elem><elem key="type">cve</elem><elem key="id">{c}</elem>'
    "</table></table></script>"
)

XML = f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1790000000" version="7.94">
<host><status state="up"/><address addr="203.0.113.30" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="ExampleSSH" version="1.0"/>
{_VULNERS.format(c="CVE-2099-2201")}</port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="ExampleHTTPD" version="1.0"/>
{_VULNERS.format(c="CVE-2099-8001")}
<script id="http-vuln-cve2099-8002" output="&#xa;  VULNERABLE:&#xa;  Example app pre-auth issue&#xa;    State: VULNERABLE (Exploitable)&#xa;    IDs:  CVE:CVE-2099-8002&#xa;"/>
</port>
</ports></host>
<runstats><finished time="1790000100"/></runstats>
</nmaprun>
"""


def test_every_nmap_cve_reaches_poam(tmp_path: Path) -> None:
    work = tmp_path / "w"
    (work / "in" / "nmap").mkdir(parents=True)
    (work / "in" / "LAB.txt").write_text("LAB/DEMO -- not a client estate. Synthetic.\n", encoding="utf-8")
    (work / "in" / "nmap" / "scan.xml").write_text(XML, encoding="utf-8")
    env = dict(os.environ, PYTHON=sys.executable, SOURCE_DATE_EPOCH="1790007200", PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts" / "lab_drop_to_sor.sh"), "--work", str(work)],
        cwd=str(ROOT), env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]
    poam = (work / "out" / "poam" / "poam.csv").read_text(encoding="utf-8")
    for cve in ("CVE-2099-2201", "CVE-2099-8001", "CVE-2099-8002"):
        assert cve in poam, cve
    with (work / "out" / "poam" / "excluded.csv").open(encoding="utf-8", newline="") as fh:
        dup = [
            r for r in csv.DictReader(fh)
            if "vulners-rollup" in str(r.get("finding_ref_id") or r.get("id") or "")
            and "DUPLICATE" in str(r)
        ]
    assert not dup, dup
