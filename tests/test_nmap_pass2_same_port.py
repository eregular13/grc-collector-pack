"""Nmap second pass on the same port, synthetic data.

Full lab_drop_to_sor.sh flow with --prior-out across four runs:
  r1 port-only, r2 port + vulners (same port), r3 repeat r2, r4 port-only again.
The pass-1 port item must stay explicit (superseded_by_specific) on r2, and
the pass-2 CVE items must be carried from the prior ledger on r4, not lost.
Data: 203.0.113.0/24, *.example.test, CVE-2099-*.
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lab_drop_to_sor.sh"

_HOST = (
    '<host starttime="{t}" endtime="{t}"><status state="up" reason="syn-ack"/>'
    '<address addr="203.0.113.20" addrtype="ipv4"/>'
    '<hostnames><hostname name="host-a.example.test" type="PTR"/></hostnames>'
    '<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>'
    '<service name="ssh" product="OpenSSH" version="6.0p1" extrainfo="protocol 2.0" '
    'method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:6.0p1</cpe></service>'
    "{script}</port></ports></host>"
)
_VULNERS = (
    '<script id="vulners" output="cpe:/a:openbsd:openssh:6.0p1: CVE-2099-0001 7.5 '
    'CVE-2099-0002 5.0"><table key="cpe:/a:openbsd:openssh:6.0p1">'
    '<table><elem key="cvss">7.5</elem><elem key="id">CVE-2099-0001</elem>'
    '<elem key="is_exploit">false</elem><elem key="type">cve</elem></table>'
    '<table><elem key="cvss">5.0</elem><elem key="id">CVE-2099-0002</elem>'
    '<elem key="is_exploit">false</elem><elem key="type">cve</elem></table>'
    "</table></script>"
)


def _xml(start: int, vuln: bool) -> str:
    args = "nmap -sV -p22 --script vuln 203.0.113.20" if vuln else "nmap -sV -p22 203.0.113.20"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<nmaprun scanner="nmap" args="{args}" start="{start}" version="7.94" '
        'xmloutputversion="1.05">\n'
        + _HOST.format(t=start, script=_VULNERS if vuln else "")
        + f'\n<runstats><finished time="{start}"/></runstats></nmaprun>\n'
    )


PASS1 = ("nmap-pass1.xml", 1790000000, False)
PASS2 = ("nmap-pass2-vuln.xml", 1790003600, True)


def _run(tmp: Path, name: str, files, sde: int, prior: Path | None) -> Path:
    work = tmp / name
    inv = work / "in" / "inventory"
    inv.mkdir(parents=True)
    for fname, start, vuln in files:
        (inv / fname).write_text(_xml(start, vuln), encoding="utf-8", newline="\n")
    env = dict(os.environ)
    env.update(
        PYTHON=sys.executable,
        SOURCE_DATE_EPOCH=str(sde),
        PYTHONDONTWRITEBYTECODE="1",
    )
    cmd = ["bash", str(SCRIPT), "--work", str(work)]
    if prior is not None:
        cmd += ["--prior-out", str(prior)]
    proc = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True, text=True)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]
    return work / "out"


def _poam(out: Path) -> dict[str, dict[str, str]]:
    with (out / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        return {r["poam_id"]: r for r in csv.DictReader(fh)}


def _excluded(out: Path) -> list[dict[str, str]]:
    with (out / "poam" / "excluded.csv").open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _ledger(out: Path) -> dict:
    return json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))


def _by_pid(ledger: dict) -> dict[str, dict]:
    return {str(v.get("poam_id")): v for v in ledger["items"].values()}


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("pass2")
    r1 = _run(tmp, "r1", [PASS1], 1790007200, None)
    r2 = _run(tmp, "r2", [PASS1, PASS2], 1790010800, r1)
    r3 = _run(tmp, "r3", [PASS1, PASS2], 1790014400, r2)
    r4 = _run(tmp, "r4", [PASS1], 1790018000, r3)
    return r1, r2, r3, r4


def test_pass1_port_item_is_explicit_on_pass2(runs) -> None:
    r1, r2, _r3, _r4 = runs
    p1 = _poam(r1)
    assert len(p1) == 1
    (port_id,) = p1
    assert p1[port_id]["weakness"].startswith("SSH exposed")
    p2 = _poam(r2)
    cve = [pid for pid, r in p2.items() if r["weakness"] == "CVE-2099-0001"]
    assert len(cve) == 1 and p2[cve[0]]["severity"] == "high"
    assert port_id not in p2
    led = _by_pid(_ledger(r2))
    assert led[port_id]["status"] == "open"
    assert led[port_id]["excluded_reason"] == "superseded_by_specific"
    ex = [r for r in _excluded(r2) if r["weakness"].startswith("SSH exposed")]
    assert len(ex) == 1
    assert ex[0]["excluded_reason"] == "superseded_by_specific"
    assert ex[0]["superseded_by"] == cve[0]
    s2 = json.loads((r2 / "summary.json").read_text(encoding="utf-8"))
    assert not s2.get("ledger_dropped_poam_ids")


def test_pass2_ids_and_dates_stable_on_repeat(runs) -> None:
    _r1, r2, r3, _r4 = runs
    p2, p3 = _poam(r2), _poam(r3)
    assert set(p2) == set(p3)
    for pid in p2:
        assert p2[pid]["original_detection_date"] == p3[pid]["original_detection_date"]


def test_prior_ledger_is_read_on_inventory_drop(runs) -> None:
    """Fail-before: KEEP-min inventory staged under out/in, so in/poam ledger was ignored."""
    _r1, r2, r3, _r4 = runs
    l3 = _ledger(r3)
    assert l3["prev_sha256"]
    kinds = {e["kind"] for e in l3["events_this_run"]}
    assert "created" not in kinds
    assert "reobserved" in kinds


def test_pass2_cve_items_not_lost_when_port_only_rescan(runs) -> None:
    _r1, _r2, r3, r4 = runs
    cve_ids = {pid for pid, r in _poam(r3).items() if not r["weakness"].startswith("SSH exposed")}
    assert len(cve_ids) == 2
    l4 = _ledger(r4)
    live = _by_pid(l4)
    closed = {str(c.get("poam_id")) for c in l4["closed"]}
    for pid in cve_ids:
        assert pid in live or pid in closed, f"{pid} silently dropped"
        if pid in live:
            assert live[pid]["status"] in {"open", "pending_verification"}
