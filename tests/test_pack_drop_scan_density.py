"""Brick 5: SAMPLE/DEMO pack_drop looks like a dual-net nmap-ish scan leaf.

Fixture + assertion depth only. Not a new operator entrypoint.
SAMPLE/DEMO != client. Farm path stays exposure (vulnerabilities == 0).
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from collectors import inventory_nmap
from scripts.prove_ciso import prove_ciso
from shared.ciso_shape import assert_flood_guard, assert_risk_register_and_poam
from shared.control_map import map_finding
from shared.farm_ship import assert_farm_ship_sor

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "fixtures" / "pack_drop"
NMAP = PACK / "nmap"

# Brick 4 farm_drop SoR ballpark (thin one-host nmap leaf): 85 findings / 23 poam / 0 vulns.
# Brick 5 floors are the denser dual-net SAMPLE leaf, still below inventing client KEEP.
# Full POA&M plan (default) puts Lows + non-key Mediums on the plan. Measured
# farm_drop after port-only fold (unchanged vs 174/106): pack_drop has no
# specific-on-port peer so no superseded_by_specific. After (weakness, EGA-
# asset) merge, unique included POA&M rows measure 85 (21 duplicate pairs
# collapsed; not a thinner unique estate). Findings and excluded floors stay
# 110 / 20 — those MIN_ gates are not loosened. MIN_FARM_POAM restamped to
# the unique included count (was 100 against the duplicate-inflated 106).
BEFORE_FARM_FINDINGS = 85
BEFORE_FARM_POAM = 23
MIN_NMAP_HOSTS = 14
MIN_NMAP_PORTS = 30
MIN_NMAP_FINDINGS = 30
MIN_FARM_FINDINGS = 110
MIN_FARM_POAM = 85
MIN_FARM_EXCLUDED = 20
CORP_PREFIX = "10.0.0."
LAB_PREFIX = "172.16.10."
HOST_CLASSES = (
    "dc.corp.local",
    "filesrv.corp.local",
    "web-01.corp.local",
    "jump.corp.local",
    "telnet-legacy.corp.local",
    "legacy-ftp.corp.local",
    "mail.corp.local",
    "ws-finance.corp.local",
    "printer.corp.local",
    "lab-gw.lab.local",
    "lab-web.lab.local",
    "lab-db.lab.local",
    "lab-win.lab.local",
    "lab-iot.lab.local",
)


def _jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        row = json.loads(text)
        assert isinstance(row, dict)
        rows.append(row)
    return rows


def _nested_ports(row: dict) -> list[dict]:
    raw = row.get("ports") or []
    assert isinstance(raw, list)
    return [item for item in raw if isinstance(item, dict)]


def test_nmap_pack_drop_is_dual_net_scan_leaf() -> None:
    assets = _jsonl(NMAP / "assets.jsonl")
    findings = _jsonl(NMAP / "findings.jsonl")
    assert findings[0]["id"] == "nmap-50-smb-445"
    assert findings[0]["assets"] == ["filesrv.corp.local"]
    hosts = [row for row in assets if row.get("kind") == "asset"]
    assert len(hosts) >= MIN_NMAP_HOSTS
    names = {row.get("name") for row in hosts}
    for host in HOST_CLASSES:
        assert host in names, host
    ips = {str(row.get("ip") or "") for row in hosts}
    corp = {ip for ip in ips if ip.startswith(CORP_PREFIX)}
    lab = {ip for ip in ips if ip.startswith(LAB_PREFIX)}
    assert len(corp) >= 8, corp
    assert len(lab) >= 6, lab
    ports: list[dict] = []
    products = 0
    for row in hosts:
        for item in _nested_ports(row):
            ports.append(item)
            if str(item.get("product") or "").strip():
                products += 1
    assert len(ports) >= MIN_NMAP_PORTS
    assert products >= 8
    port_ids = {str(item.get("port")) for item in ports}
    assert {"21", "22", "23", "80", "445", "3389", "3306"} <= port_ids
    assert all(row.get("kind") != "service" for row in assets)
    assert len(findings) >= MIN_NMAP_FINDINGS
    blob = json.dumps(assets + findings)
    assert "CVE-" not in blob
    assert "SAMPLE" in blob and "DEMO" in blob
    assert "not a client" in blob.lower()
    meta = json.loads((NMAP / "meta.json").read_text(encoding="utf-8"))
    assert meta["demo"] is True
    assert "sample" in meta["note"].lower() or "demo" in meta["note"].lower()
    assert "client" in meta["note"].lower()
    sample = (NMAP / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in sample
    assert "10.0.0.0/24" in sample
    assert "172.16.10.0/24" in sample
    assert "not cve" in sample.lower() or "exposure" in sample.lower()


def test_nmap_scan_leaf_emit_host_and_poam_density() -> None:
    recs = inventory_nmap.parse_file(NMAP / "assets.jsonl")
    assets = [row for row in recs if row["kind"] == "asset"]
    findings = [row for row in recs if row["kind"] == "finding"]
    names = {row["name"] for row in assets}
    assert "filesrv.corp.local" in names
    assert "dc.corp.local" in names
    assert "lab-db.lab.local" in names
    ports = {str((row.get("extra") or {}).get("port") or "") for row in findings}
    assert {"21", "22", "23", "80", "445", "3389"} <= ports
    smb = next(row for row in findings if (row.get("extra") or {}).get("port") == "445")
    mapped = map_finding(smb)
    assert mapped["include_poam"] is True
    assert "CVE-" not in mapped["recommended_fix"]
    poamable = [row for row in findings if map_finding(row).get("include_poam")]
    assert len(poamable) >= 10
    lifted = inventory_nmap.parse_file(NMAP / "findings.jsonl")
    lift_findings = [row for row in lifted if row["kind"] == "finding"]
    assert lift_findings[0]["source"] == "inventory-nmap"
    assert "filesrv.corp.local" in (lift_findings[0].get("assets") or [])
    assert any("telnet" in row["name"].lower() for row in lift_findings)
    assert any("ftp" in row["name"].lower() for row in lift_findings)
    assert any((row.get("extra") or {}).get("product") for row in lift_findings)


def test_port_scan_twins_share_dual_net_without_cve() -> None:
    rust = inventory_nmap.parse_file(PACK / "rustscan" / "assets.jsonl")
    naabu = inventory_nmap.parse_file(PACK / "naabu" / "assets.jsonl")
    fping = inventory_nmap.parse_file(PACK / "fping" / "assets.jsonl")
    rust_names = {row["name"] for row in rust if row["kind"] == "asset"}
    naabu_names = {row["name"] for row in naabu if row["kind"] == "asset"}
    fping_names = {row["name"] for row in fping if row["kind"] == "asset"}
    assert {"10.9.8.7", "10.0.0.30", "172.16.10.20"} <= rust_names
    assert {"10.9.8.30", "10.0.0.40", "172.16.10.30"} <= naabu_names
    assert {"10.9.8.10", "10.0.0.10", "172.16.10.10"} <= fping_names
    assert all(row["kind"] != "finding" for row in fping)
    rust_findings = [row for row in rust if row["kind"] == "finding"]
    assert any((row.get("extra") or {}).get("port") == "8080" for row in rust_findings)
    for path in (
        PACK / "rustscan" / "findings.jsonl",
        PACK / "naabu" / "findings.jsonl",
        PACK / "fping" / "findings.jsonl",
    ):
        blob = path.read_text(encoding="utf-8")
        assert "CVE-" not in blob
        assert "SAMPLE/DEMO" in blob or "not a client" in blob.lower()


def test_farm_drop_prove_register_is_denser_and_exposure_only(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    stamp = prove_ciso(root=ROOT, dest=dest)
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["sample"] is True
    assert stamp["demo"] is True
    assert stamp["client"] is False
    assert stamp["client_keep"] is False
    assert stamp["paying_day"] == "FAIL"
    assert stamp["posted"] is False
    shape = assert_risk_register_and_poam(Path(stamp["out_dir"]))
    assert shape["findings"] >= MIN_FARM_FINDINGS
    assert shape["findings"] > BEFORE_FARM_FINDINGS
    assert shape["risk_scenarios"] >= shape["findings"]
    assert shape["poam_rows"] >= MIN_FARM_POAM
    assert shape["poam_rows"] > BEFORE_FARM_POAM
    excluded_path = Path(stamp["out_dir"]) / "poam" / "excluded.csv"
    assert excluded_path.is_file()
    with excluded_path.open(encoding="utf-8", newline="") as fh:
        excluded = list(csv.DictReader(fh))
    assert len(excluded) >= MIN_FARM_EXCLUDED
    reasons = {str(row.get("excluded_reason") or "") for row in excluded}
    assert "severity_info" in reasons
    assert "honeypot" in reasons
    summary = json.loads((Path(stamp["out_dir"]) / "summary.json").read_text(encoding="utf-8"))
    assert summary["poam_plan"] == "full"
    assert_flood_guard(summary)
    assert int(summary["excluded"]) == len(excluded)
    assert shape["vulnerabilities"] == 0
    assert shape["vulns_cve_class_only"] is True
    assert stamp["counts"]["findings"] == shape["findings"]
    assert stamp["counts"]["poam"] == shape["poam_rows"]
    assets_csv = (Path(stamp["out_dir"]) / "ciso-assistant" / "assets.csv").read_text(
        encoding="utf-8"
    )
    findings_csv = (Path(stamp["out_dir"]) / "ciso-assistant" / "findings.csv").read_text(
        encoding="utf-8"
    )
    assert "filesrv.corp.local" in assets_csv
    assert "dc.corp.local" in assets_csv
    assert "lab-db.lab.local" in assets_csv
    assert "172.16.10." in assets_csv
    assert "SMB" in findings_csv
    assert "Telnet" in findings_csv or "telnet" in findings_csv.lower()
    ship = assert_farm_ship_sor(dest)
    assert ship["ok"] is True
    assert ship["paying_day"] == "FAIL"
    assert ship["vulnerabilities"] in (0, None)
