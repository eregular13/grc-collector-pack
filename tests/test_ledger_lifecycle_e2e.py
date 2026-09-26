"""Full-pipeline multi-run ledger proof on client-facing exports.

Timeline (Nessus HOST_START calendar days; family = vuln-scan). Coverage is
per source_family + EGA- host, so COVER on cover-host makes FLAP a *covered*
miss. The ledger's rule is two covered misses → pending_verification (still
open, same EGP- ID). pending-then-seen keeps that ID (test_3_5_10). -R1 is
close-then-reappear (test_3_5_9). Run 4 documents the operator close so both
client-facing statuses appear in one coherent scenario.

  Run 1 (2026-09-01)
    STABLE  plugin 156032 on dhcp-web.lab.internal
            (IEEE UAA MAC 00:1A:2B:3C:4D:5E, IP 10.0.10.10)
    COVER   plugin 20007  on cover-host.lab.internal (10.0.10.20)
    FLAP    plugin 42411  on cover-host:445

  Run 2 (2026-09-08)
    STABLE  same MAC, DHCP IP 10.0.10.99 — EGA- and EGP- IDs must hold
    COVER   still present (so FLAP is a covered miss)
    FLAP    absent (missed_covered_runs = 1, still open)
    NEW     plugin 51192 on cover-host:8443 — minted once

  Run 3 (2026-09-15)
    STABLE, COVER, NEW unchanged
    FLAP    absent a second covered run → pending_verification

  Between 3 and 4
    Operator closes the pending FLAP on the carried poam-ledger.json.

  Run 4 (2026-09-22)
    FLAP returns → EGP-…-R1 (new detection date; prior ID on Closed)
    NEW is not reminted; STABLE/COVER keep their EGP- IDs and earliest dates

Each run is the operator lab path: ten collectors + grc_loader (same as
`make lab`). Ledgers copy out/ → next in/. LAB dest_in, never SAMPLE/client KEEP.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from shared.ciso_shape import csv_rows
from shared.poam_fedramp import FEDRAMP_CLOSED_CSV_NAME, FEDRAMP_CSV_NAME
from shared.poam_ledger import payload_sha256

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "lab-lifecycle"

MAC = "00:1A:2B:3C:4D:5E"
STABLE_NAME = "TLS Version 1.0 Protocol Detection"
COVER_NAME = "SSL Version 2 and 3 Protocol Detection"
FLAP_NAME = "Microsoft Windows SMB Shares Unprivileged Access"
NEW_NAME = "SSL Certificate Cannot Be Trusted"

COLLECTORS = (
    "cloud_prowler",
    "inventory_nmap",
    "vuln_scan",
    "host_wazuh",
    "identity_ad",
    "easm",
    "k8s_kubescape",
    "code_secrets",
    "saas_idp",
    "dns_email",
)

HOST_START = {
    1: "Tue Sep  1 12:00:00 2026",
    2: "Tue Sep  8 12:00:00 2026",
    3: "Tue Sep 15 12:00:00 2026",
    4: "Tue Sep 22 12:00:00 2026",
}


def _host(
    name: str,
    ip: str,
    host_start: str,
    items: list[tuple[str, str, str, str]],
    *,
    fqdn: str = "",
    mac: str = "",
) -> str:
    props = [
        f'<tag name="host-ip">{ip}</tag>',
        f'<tag name="HOST_START">{host_start}</tag>',
    ]
    if fqdn:
        props.append(f'<tag name="host-fqdn">{fqdn}</tag>')
    if mac:
        props.append(f'<tag name="mac-address">{mac}</tag>')
    rows = []
    for port, proto, plugin, title in items:
        rows.append(
            f'<ReportItem port="{port}" svc_name="www" protocol="{proto}" '
            f'severity="3" pluginID="{plugin}" pluginName="{title}">'
            f"<risk_factor>High</risk_factor>"
            f"<description>{title} on LAB host {name}.</description>"
            f"</ReportItem>"
        )
    return (
        f'<ReportHost name="{name}">'
        f"<HostProperties>{''.join(props)}</HostProperties>"
        f"{''.join(rows)}"
        f"</ReportHost>"
    )


def _nessus(run: int) -> str:
    start = HOST_START[run]
    stable_ip = "10.0.10.10" if run == 1 else "10.0.10.99"
    cover_items: list[tuple[str, str, str, str]] = [
        ("443", "tcp", "20007", COVER_NAME),
    ]
    if run == 1 or run == 4:
        cover_items.append(("445", "tcp", "42411", FLAP_NAME))
    if run >= 2:
        cover_items.append(("8443", "tcp", "51192", NEW_NAME))
    body = _host(
        "dhcp-web.lab.internal",
        stable_ip,
        start,
        [("443", "tcp", "156032", STABLE_NAME)],
        fqdn="dhcp-web.lab.internal",
        mac=MAC,
    ) + _host(
        "cover-host.lab.internal",
        "10.0.10.20",
        start,
        cover_items,
        fqdn="cover-host.lab.internal",
    )
    return (
        '<?xml version="1.0" ?><NessusClientData_v2>'
        f'<Report name="lab-lifecycle-run{run}">{body}</Report>'
        "</NessusClientData_v2>\n"
    )


def _stage_run(work: Path, run: int) -> Path:
    dest_in = work / "in"
    if dest_in.exists():
        shutil.rmtree(dest_in)
    dest_in.mkdir(parents=True)
    (dest_in / "LAB.txt").write_text((FIX / "LAB.txt").read_text(encoding="utf-8"), encoding="utf-8")
    src = FIX / f"run{run}" / "vuln" / "lifecycle.nessus"
    (dest_in / "vuln").mkdir()
    (dest_in / "vuln" / "lifecycle.nessus").write_text(
        src.read_text(encoding="utf-8") if src.is_file() else _nessus(run),
        encoding="utf-8",
    )
    return dest_in


def _carry_ledgers(work: Path) -> None:
    dest_in = work / "in"
    out = work / "out"
    for rel in (Path("poam") / "poam-ledger.json", Path("assets") / "asset-ledger.json"):
        src = out / rel
        if not src.is_file():
            continue
        dest = dest_in / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")


def _close_pending_flap(work: Path) -> str:
    """Operator closes the pending FLAP on the carried ledger (not a remint)."""
    src = work / "out" / "poam" / "poam-ledger.json"
    doc = json.loads(src.read_text(encoding="utf-8"))
    closed_id = ""
    for item in (doc.get("items") or {}).values():
        if str(item.get("weakness_key") or "").endswith(":42411") or FLAP_NAME in str(
            item.get("name") or ""
        ):
            assert item.get("status") == "pending_verification", item.get("status")
            closed_id = str(item.get("poam_id") or "")
            item["status"] = "closed"
            item["closed_date"] = "2026-09-16"
            item["closure_evidence"] = ["operator: pending after 2 covered misses"]
    assert closed_id.startswith("EGP-")
    doc["sha256"] = payload_sha256(doc)
    dest = work / "in" / "poam" / "poam-ledger.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return closed_id


def _run_full_pipeline(work: Path) -> None:
    """Ten collectors + grc_loader. LAB dest_in; empty sensors do not demo-fill."""
    dest_in = work / "in"
    dest_out = work / "out"
    if dest_out.exists():
        shutil.rmtree(dest_out)
    dest_out.mkdir(parents=True)
    env = os.environ.copy()
    env.update(
        {
            "IN_DIR": str(dest_in),
            "OUT_DIR": str(dest_out),
            "PYTHONPATH": str(ROOT),
            "DRY_RUN": "1",
            "GRC_LIVE_SCAN": "0",
            "CISO_PUSH": "0",
            "RISKREADY_PUSH": "0",
            "DROPBOX_DEMO": "0",
            "DROPBOX_LIVE": "0",
            "GRC_ESTATE_LABEL": "LAB",
        }
    )
    for name in COLLECTORS:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "collectors" / f"{name}.py")],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"{name} exit {proc.returncode}: {(proc.stderr or proc.stdout)[-400:]}"
    loader = subprocess.run(
        [sys.executable, str(ROOT / "collectors" / "grc_loader.py")],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert loader.returncode == 0, f"grc_loader exit {loader.returncode}: {(loader.stderr or loader.stdout)[-400:]}"


def _by_weakness(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    return {r.get("weakness") or r.get("Weakness Name") or "": r for r in rows}


def _exec_delta(text: str) -> dict[str, int]:
    line = next(ln for ln in text.splitlines() if ln.startswith("Changed since last run:"))
    out: dict[str, int] = {}
    for part in line.split(":", 1)[1].replace(".", "").split():
        if "=" in part:
            key, val = part.split("=", 1)
            out[key] = int(val)
    if "pending verification=" in line:
        out["pending"] = int(line.split("pending verification=", 1)[1].split()[0].rstrip("."))
    return out


def _mac_asset(doc: dict) -> dict:
    hits = [
        a
        for a in (doc.get("assets") or {}).values()
        if any(
            str(al.get("type")) == "mac"
            and str(al.get("value") or "").lower().replace("-", ":") == MAC.lower()
            for al in (a.get("aliases") or [])
        )
    ]
    assert len(hits) == 1, hits
    return hits[0]


def test_lab_lifecycle_client_facing_outputs(tmp_path: Path) -> None:
    work = tmp_path / "lifecycle"
    ids: dict[str, str] = {}
    dates: dict[str, str] = {}

    def run(n: int) -> dict[str, Path]:
        _stage_run(work, n)
        if n > 1:
            _carry_ledgers(work)
        if n == 4:
            ids["flap_closed"] = _close_pending_flap(work)
        _run_full_pipeline(work)
        out = work / "out"
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        assert "LAB" in str(summary.get("estate") or "")
        assert summary.get("client") is False
        assert summary.get("estate_kind") == "LAB"
        return {
            "poam": out / "poam" / "poam.csv",
            "fed": out / "poam" / FEDRAMP_CSV_NAME,
            "fed_closed": out / "poam" / FEDRAMP_CLOSED_CSV_NAME,
            "exec": out / "EXECUTIVE_SUMMARY.md",
            "ledger": out / "poam" / "poam-ledger.json",
            "assets": out / "assets" / "asset-ledger.json",
            "summary": out / "summary.json",
        }

    # --- run 1 ---
    p1 = run(1)
    poam1 = _by_weakness(csv_rows(p1["poam"]))
    fed1 = _by_weakness(csv_rows(p1["fed"]))
    assert {STABLE_NAME, COVER_NAME, FLAP_NAME} <= set(poam1)
    assert NEW_NAME not in poam1
    for name in (STABLE_NAME, COVER_NAME, FLAP_NAME):
        assert poam1[name]["poam_id"].startswith("EGP-")
        assert poam1[name]["status"] == "open"
        assert poam1[name]["original_detection_date"] == "2026-09-01"
        assert fed1[name]["POAM ID"] == poam1[name]["poam_id"]
        assert fed1[name]["Original Detection Date"] == "2026-09-01"
        ids[name] = poam1[name]["poam_id"]
        dates[name] = poam1[name]["original_detection_date"]
    exec1 = _exec_delta(p1["exec"].read_text(encoding="utf-8"))
    assert exec1["open"] == 3 and exec1["new"] == 3
    assert exec1.get("pending", 0) == 0 and exec1.get("reopened", 0) == 0
    ega1 = str(_mac_asset(json.loads(p1["assets"].read_text(encoding="utf-8"))).get("asset_uid") or "")
    assert ega1.startswith("EGA-")

    # --- run 2 ---
    p2 = run(2)
    poam2 = _by_weakness(csv_rows(p2["poam"]))
    fed2 = _by_weakness(csv_rows(p2["fed"]))
    assert poam2[STABLE_NAME]["poam_id"] == ids[STABLE_NAME]
    assert poam2[COVER_NAME]["poam_id"] == ids[COVER_NAME]
    assert poam2[STABLE_NAME]["original_detection_date"] == dates[STABLE_NAME]
    assert "10.0.10.99" in poam2[STABLE_NAME]["asset"] or "dhcp-web" in poam2[STABLE_NAME]["asset"]
    assert NEW_NAME in poam2
    assert poam2[NEW_NAME]["poam_id"].startswith("EGP-")
    assert poam2[NEW_NAME]["poam_id"] not in ids.values()
    ids[NEW_NAME] = poam2[NEW_NAME]["poam_id"]
    dates[NEW_NAME] = poam2[NEW_NAME]["original_detection_date"]
    assert poam2[FLAP_NAME]["poam_id"] == ids[FLAP_NAME]
    assert poam2[FLAP_NAME]["status"] == "open"
    assert poam2[FLAP_NAME]["original_detection_date"] == "2026-09-01"
    assert fed2[NEW_NAME]["POAM ID"] == ids[NEW_NAME]
    assert fed2[STABLE_NAME]["POAM ID"] == ids[STABLE_NAME]
    exec2 = _exec_delta(p2["exec"].read_text(encoding="utf-8"))
    assert exec2["new"] == 1
    assert exec2["open"] == 4
    assert exec2.get("pending", 0) == 0
    ega2 = str(_mac_asset(json.loads(p2["assets"].read_text(encoding="utf-8"))).get("asset_uid") or "")
    assert ega2 == ega1

    # --- run 3 ---
    p3 = run(3)
    poam3 = _by_weakness(csv_rows(p3["poam"]))
    fed3 = _by_weakness(csv_rows(p3["fed"]))
    assert poam3[FLAP_NAME]["status"] == "pending_verification"
    assert poam3[FLAP_NAME]["poam_id"] == ids[FLAP_NAME]
    assert poam3[NEW_NAME]["poam_id"] == ids[NEW_NAME]
    assert poam3[STABLE_NAME]["poam_id"] == ids[STABLE_NAME]
    assert "pending_verification" in (fed3[FLAP_NAME].get("Comments") or "").lower()
    assert fed3[FLAP_NAME]["POAM ID"] == ids[FLAP_NAME]
    assert fed3[FLAP_NAME]["Original Detection Date"] == "2026-09-01"
    exec3 = _exec_delta(p3["exec"].read_text(encoding="utf-8"))
    assert exec3.get("pending", 0) == 1
    assert exec3["new"] == 0
    assert exec3["open"] == 4

    # --- run 4 ---
    p4 = run(4)
    poam4 = _by_weakness(csv_rows(p4["poam"]))
    fed4 = _by_weakness(csv_rows(p4["fed"]))
    closed4 = csv_rows(p4["fed_closed"])
    flap4 = poam4[FLAP_NAME]
    assert flap4["poam_id"] == f"{ids[FLAP_NAME]}-R1"
    assert flap4["status"] == "reopened"
    assert flap4["original_detection_date"] == "2026-09-22"
    assert fed4[FLAP_NAME]["POAM ID"] == flap4["poam_id"]
    assert ids[FLAP_NAME] in (fed4[FLAP_NAME].get("Comments") or "")
    assert any(r.get("POAM ID") == ids[FLAP_NAME] for r in closed4)
    assert poam4[NEW_NAME]["poam_id"] == ids[NEW_NAME]
    assert poam4[STABLE_NAME]["poam_id"] == ids[STABLE_NAME]
    assert poam4[COVER_NAME]["poam_id"] == ids[COVER_NAME]
    assert poam4[STABLE_NAME]["original_detection_date"] == "2026-09-01"
    assert poam4[NEW_NAME]["original_detection_date"] == dates[NEW_NAME]
    exec4 = _exec_delta(p4["exec"].read_text(encoding="utf-8"))
    assert exec4.get("reopened", 0) == 1
    assert exec4["new"] == 0
    assert exec4.get("pending", 0) == 0
    assert exec4["open"] == 4

    assets = json.loads(p4["assets"].read_text(encoding="utf-8"))
    mac_hit = _mac_asset(assets)
    assert str(mac_hit.get("asset_uid") or "") == ega1
