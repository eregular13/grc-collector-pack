"""One POA&M decision set across register, FedRAMP, console, and exec."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from shared.ciso_shape import (
    assert_flood_guard,
    assert_poam_fedramp_identity,
    assert_unique_weakness_asset,
    csv_rows,
)
from shared.control_map import map_finding, weakness_name_for
from shared.estate_pages import rank_exec_findings
from shared.finding_types import dedupe_key, dedupe_weaknesses, finding_type
from shared.schema import canon_severity, make_record, map_severity


ROOT = Path(__file__).resolve().parents[1]


def _asset(name: str, uid: str, **extra: object) -> dict:
    payload = {
        "asset_type": "PR",
        "asset_uid": uid,
        "ip": extra.pop("ip", "10.0.0.7"),
    }
    payload.update(extra)
    return make_record(
        kind="asset",
        source="host-wazuh",
        ref_id=f"WAZ-{name}",
        name=name,
        assets=[name],
        extra=payload,
    )


def _finding(**kwargs) -> dict:
    defaults = dict(
        kind="finding",
        source="host-wazuh",
        ref_id="WAZ-a",
        name="Disk encryption disabled on fleet-laptop-07",
        description="export lists disk encryption as not enabled",
        severity="high",
        category="host-posture",
        assets=["fleet-laptop-07"],
        extra={"check_id": "disk_encryption", "asset_uid": "EGA-LAPTOP007"},
    )
    defaults.update(kwargs)
    extra = dict(defaults.get("extra") or {})
    extra.setdefault("asset_uid", "EGA-LAPTOP007")
    defaults["extra"] = extra
    return make_record(**defaults)


def _load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, records: list[dict]) -> Path:
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    with (out / "canonical" / "x.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    (tmp_path / "in").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    return out


def test_same_weakness_same_ega_asset_merges_sources() -> None:
    intune = _finding(
        ref_id="WAZ-diskenc-intune-fleet-laptop-07",
        extra={
            "check_id": "disk_encryption",
            "provider": "intune",
            "asset_uid": "EGA-LAPTOP007",
        },
        labels=["intune", "mdm"],
    )
    jamf = _finding(
        ref_id="WAZ-diskenc-jamf-fleet-laptop-07",
        source="host-wazuh",
        name="Disk encryption disabled on fleet-laptop-07",
        extra={
            "check_id": "disk_encryption",
            "provider": "jamf",
            "asset_uid": "EGA-LAPTOP007",
        },
        labels=["jamf", "mdm"],
    )
    assert finding_type(intune) == finding_type(jamf) == "disk_encryption"
    assert dedupe_key(intune) == dedupe_key(jamf)
    merged = [r for r in dedupe_weaknesses([intune, jamf]) if r.get("kind") == "finding"]
    assert len(merged) == 1
    extra = merged[0]["extra"]
    assert "WAZ-diskenc-jamf-fleet-laptop-07" in (extra.get("also_ids") or [])
    assert {"intune", "jamf"} <= set(extra.get("sources") or extra.get("tools") or []) or {
        "intune",
        "jamf",
    } <= set(merged[0].get("labels") or [])


def test_poam_and_fedramp_row_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _load(
        tmp_path,
        monkeypatch,
        [
            _asset("fleet-laptop-07", "EGA-LAPTOP007"),
            _finding(),
        ],
    )
    poam = csv_rows(out / "poam" / "poam.csv")
    fed = csv_rows(out / "poam" / "poam_fedramp.csv")
    assert_unique_weakness_asset(poam)
    identity = assert_poam_fedramp_identity(out)
    assert identity["ok"] is True
    assert len(poam) == len(fed) == 1
    assert poam[0]["poam_id"] == fed[0]["POAM ID"]
    assert poam[0]["poam_id"].startswith("EGP-")
    assert poam[0]["controls"] == fed[0]["Controls"]
    assert poam[0]["weakness"] == fed[0]["Weakness Name"]
    assert poam[0]["controls"]


def test_failure_title_on_register_fedramp_and_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = make_record(
        kind="finding",
        source="cloud-prowler",
        ref_id="CLD-root-mfa",
        name="Root account MFA enabled",
        description="root MFA is not enabled",
        severity="high",
        category="cloud-misconfiguration",
        assets=["account"],
        extra={"check_id": "iam_root_mfa_enabled", "asset_uid": "EGA-ACCOUNT01"},
    )
    out = _load(
        tmp_path,
        monkeypatch,
        [
            _asset("account", "EGA-ACCOUNT01", ip="10.0.0.8"),
            rec,
        ],
    )
    title = "Root account has no MFA"
    findings = csv_rows(out / "ciso-assistant" / "findings.csv")
    poam = csv_rows(out / "poam" / "poam.csv")
    fed = csv_rows(out / "poam" / "poam_fedramp.csv")
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    assert findings[0]["name"] == title
    assert poam[0]["weakness"] == title
    assert fed[0]["Weakness Name"] == title
    assert title in exec_text
    assert "Root account MFA enabled" not in findings[0]["name"]
    assert "enabled" not in poam[0]["weakness"].lower() or "not" in poam[0]["weakness"].lower()


def test_evergreen_critical_sla_15_fedramp_labelled_30(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-CVE-2021-44228",
        name="Log4j remote code execution",
        description="Log4Shell CVE-2021-44228",
        severity="critical",
        category="vulnerability",
        assets=["app-1"],
        extra={
            "cve": "CVE-2021-44228",
            "asset_uid": "EGA-APP000001",
            "scan_time": "2026-09-01T12:00:00Z",
        },
        collected_at="2026-09-01T12:00:00Z",
    )
    out = _load(
        tmp_path,
        monkeypatch,
        [_asset("app-1", "EGA-APP000001", ip="10.0.0.9"), rec],
    )
    poam = csv_rows(out / "poam" / "poam.csv")[0]
    assert poam["scheduled_completion_date"] == "2026-09-16"
    md = (out / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "Critical 15" in md
    assert "FedRAMP" in md and "+30" in md
    assert "Evergreen default schedule (poam.csv / KEV note): Critical 15 days" in md
    fed = csv_rows(out / "poam" / "poam_fedramp.csv")[0]
    assert fed["Scheduled Completion Date"] == ""


def test_console_severity_from_poam(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from product.server import estate

    out = tmp_path / "out"
    out.mkdir()
    (out / "summary.json").write_text(
        json.dumps({"demo": True, "client": False, "assets": 2, "findings": 1, "poam": 2}),
        encoding="utf-8",
    )
    ciso = out / "ciso-assistant"
    ciso.mkdir()
    (ciso / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n"
        "F1,only findings strip,x,high,identified,demo\n",
        encoding="utf-8",
    )
    (ciso / "vulnerabilities.csv").write_text(
        "ref_id,name,description,status,severity,assets,applied_controls\n"
        "CVE-2021-44228,Log4j,x,Exploitable,Critical,app,\n",
        encoding="utf-8",
    )
    (ciso / "risk_scenarios.csv").write_text(
        "ref_id;assets;threats;name;description;existing_controls;current_impact;"
        "current_proba;current_risk;additional_controls;residual_impact;"
        "residual_proba;residual_risk;treatment\n",
        encoding="utf-8",
    )
    (out / "poam").mkdir()
    (out / "poam" / "poam.csv").write_text(
        "weakness,asset,severity,framework_refs,recommended_fix,owner,due,status\n"
        "Log4j remote code execution,app,critical,csf_RS,Patch,, ,open\n"
        "High leftover,host,high,csf_PR,Fix,,,open\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["severity"]["critical"] == 1
    assert data["severity"]["high"] == 1
    assert data["severity"] == data["poam"]["severity"]
    assert data["severity"]["critical"] != 0


def test_exec_top5_severity_kev_criticality_no_dupes_no_inflation() -> None:
    log4j = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-log4j",
        name="Log4j remote code execution",
        severity="critical",
        category="vulnerability",
        assets=["app"],
        extra={"cve": "CVE-2021-44228"},
    )
    xz = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-xz",
        name="xz backdoor CVE-2024-3094",
        severity="critical",
        category="vulnerability",
        assets=["build"],
        extra={"cve": "CVE-2024-3094"},
    )
    dcsync = make_record(
        kind="finding",
        source="identity-ad",
        ref_id="ID-dcsync",
        name="BloodHound DCSync",
        severity="critical",
        category="identity-gap",
        assets=["SVC-SQL"],
        extra={"edge": "DCSync"},
    )
    telnet_a = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-telnet-a",
        name="Telnet exposed",
        severity="critical",
        category="exposure",
        assets=["legacy"],
        extra={"port": "23", "service": "telnet"},
    )
    telnet_b = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-telnet-b",
        name="Telnet exposed",
        severity="critical",
        category="exposure",
        assets=["iot"],
        extra={"port": "23", "service": "telnet"},
    )
    smb = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-smb",
        name="SMB file sharing is exposed",
        severity="high",
        category="exposure",
        assets=["fs"],
        extra={"port": "445", "service": "microsoft-ds"},
    )
    inflated = make_record(
        kind="finding",
        source="code-secrets",
        ref_id="CODE-purple",
        name="unknown band",
        severity="purple",
        extra={"rule": "x"},
    )
    assert inflated["extra"].get("severity_unmapped") is True
    assert canon_severity("purple") != "high"
    sev, unmapped = map_severity("")
    assert sev != "high" and unmapped is True
    ranked = rank_exec_findings(
        [telnet_a, telnet_b, inflated, dcsync, xz, log4j, smb],
        {
            r["ref_id"]: map_finding(r)
            for r in (log4j, xz, dcsync, telnet_a, telnet_b, inflated, smb)
        },
        titles={
            "VULN-log4j": "Log4j remote code execution",
            "VULN-xz": "xz backdoor CVE-2024-3094",
            "ID-dcsync": "Non-DC principal has DCSync / replication rights",
            "NMAP-telnet-a": "Telnet is exposed",
            "NMAP-telnet-b": "Telnet is exposed",
            "NMAP-smb": "SMB file sharing is exposed",
            "CODE-purple": "unknown band",
        },
    )
    names = [r["ref_id"] for r in ranked]
    assert names[:3] == ["VULN-log4j", "VULN-xz", "ID-dcsync"] or (
        "VULN-log4j" in names and "VULN-xz" in names and "ID-dcsync" in names
    )
    assert names.count("NMAP-telnet-a") + names.count("NMAP-telnet-b") <= 1
    from shared.estate_pages import _sev

    assert _sev(inflated) not in {"high", "critical"}
    assert "CODE-purple" not in names


def test_redis_remediation_is_specific() -> None:
    unauth = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-exposed-redis-a",
        name="Redis without auth",
        description="Unauthenticated Redis",
        severity="high",
        category="vulnerability",
        assets=["https://redis-a.lab.internal"],
        extra={"template_id": "exposed-redis", "template-id": "exposed-redis"},
    )
    bind = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-redis-bind",
        name="Redis bound on all interfaces",
        description="Redis protected-mode is off and bind is 0.0.0.0",
        severity="high",
        extra={"check_id": "redis_bind"},
    )
    cmds = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-redis-cmd",
        name="Redis dangerous commands enabled",
        description="CONFIG MODULE and DEBUG are not renamed",
        severity="high",
        extra={"check_id": "redis_dangerous_cmd"},
    )
    mapped = {r["ref_id"]: map_finding(r) for r in (unauth, bind, cmds)}
    assert finding_type(unauth) == "redis_unauth"
    fix = mapped["VULN-exposed-redis-a"]["recommended_fix"].lower()
    assert "requirepass" in fix or "acl" in fix
    assert "bind" in fix or "protected-mode" in fix
    assert "rename" in fix or "disable" in fix
    assert "generic fallback" not in fix
    assert "review and remediate per control" not in fix
    bind_fix = mapped["NMAP-redis-bind"]["recommended_fix"].lower()
    assert "protected-mode" in bind_fix and "bind" in bind_fix
    cmd_fix = mapped["NMAP-redis-cmd"]["recommended_fix"].lower()
    assert "rename" in cmd_fix or "disable" in cmd_fix
    assert "config" in cmd_fix
    assert weakness_name_for(unauth, mapped["VULN-exposed-redis-a"])
    assert "pass" not in weakness_name_for(unauth, mapped["VULN-exposed-redis-a"]).lower() or "unauth" in weakness_name_for(unauth, mapped["VULN-exposed-redis-a"]).lower()


def test_no_pentera_in_console_or_refresh_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Drift lock: refresh + console must not write the Pentera vendor line."""
    import zipfile
    from io import BytesIO

    from product.server import build_drop_zip
    import scripts.refresh_product_lab_drop_sinks as refresh

    needle = "Pentera"
    for rel in (
        "product/static/index.html",
        "product/static/app.js",
        "product/static/app.css",
        "product/server.py",
        "scripts/refresh_product_lab_drop_sinks.py",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert needle not in text, rel

    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setenv("OUT_DIR", str(out))
    blob = build_drop_zip()
    with zipfile.ZipFile(BytesIO(blob)) as zf:
        for name in zf.namelist():
            if name.startswith("product-lab/drop"):
                continue
            data = zf.read(name)
            assert needle.encode("utf-8") not in data, name

    dest = tmp_path / "refresh-drop"
    dest.mkdir()
    monkeypatch.setattr(refresh, "DROP", dest)
    hashes = {
        "ciso/applied_controls.csv": "a" * 64,
        "ciso/assets.csv": "b" * 64,
        "ciso/evidences.csv": "c" * 64,
        "ciso/findings.csv": "d" * 64,
        "ciso/risk_scenarios.csv": "e" * 64,
        "ciso/vulnerabilities.csv": "f" * 64,
        "poam/poam.csv": "1" * 64,
        "poam/poam.md": "2" * 64,
        "opengrc/risks.csv": "3" * 64,
        "opengrc/assets.csv": "4" * 64,
        "opengrc/implementations.csv": "5" * 64,
        "import_preview/probo.json": "6" * 64,
    }
    counts = {rel: 1 for rel in hashes}
    refresh._write_manifest(counts, hashes)
    refresh._write_readme(counts)
    written = list(dest.rglob("*"))
    assert written, "refresh writers produced nothing"
    for path in written:
        if path.is_file():
            assert needle not in path.read_text(encoding="utf-8"), path.name
    assert (ROOT / "product-lab" / "drop" / "README.md").is_file()


def test_fedramp_open_excludes_info_honeypot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FedRAMP Open rows are the poam.csv decision set — not every ledger item."""
    keep = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-smb",
        name="SMB file sharing is exposed",
        description="box has open TCP/445 (microsoft-ds).",
        severity="high",
        category="exposure",
        assets=["filesrv"],
        extra={"port": "445", "service": "microsoft-ds", "asset_uid": "EGA-FILESRV01"},
    )
    info = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-info",
        name="Host discovered",
        description="banner only",
        severity="info",
        category="exposure",
        assets=["filesrv"],
        extra={"port": "80", "asset_uid": "EGA-FILESRV01"},
    )
    honeypot = make_record(
        kind="finding",
        source="honeypot",
        ref_id="HPOT-1",
        name="Deception-sensor stage-1 hit",
        description="deception-sensor evidence / an agent-behavior signal.",
        severity="high",
        category="deception-sensor",
        assets=["honeypot-1"],
        extra={"honesty": "deception-sensor", "asset_uid": "EGA-HPOT00001"},
    )
    out = _load(
        tmp_path,
        monkeypatch,
        [
            _asset("filesrv", "EGA-FILESRV01", ip="10.0.0.10"),
            _asset("honeypot-1", "EGA-HPOT00001", ip="10.0.0.11"),
            keep,
            info,
            honeypot,
        ],
    )
    poam = csv_rows(out / "poam" / "poam.csv")
    fed = csv_rows(out / "poam" / "poam_fedramp.csv")
    excluded = csv_rows(out / "poam" / "excluded.csv")
    assert_poam_fedramp_identity(out)
    assert [row["finding_ref_id"] for row in poam] == ["NMAP-smb"]
    assert [row["POAM ID"] for row in fed] == [poam[0]["poam_id"]]
    assert poam[0]["weakness"] == fed[0]["Weakness Name"]
    reasons = {row["finding_ref_id"]: row["excluded_reason"] for row in excluded}
    assert reasons["NMAP-info"] == "severity_info"
    assert reasons["HPOT-1"] == "honeypot"
    fed_names = {row["Weakness Name"] for row in fed}
    assert "Host discovered" not in fed_names
    assert "Deception-sensor stage-1 hit" not in fed_names
    assert "NMAP-info" not in {row.get("Weakness Source Identifier") for row in fed}


def test_duplicate_instance_and_flood_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Merged-away rows reach excluded.csv; flood_guard is the pre-dedupe identity."""
    intune = _finding(
        ref_id="WAZ-diskenc-intune-fleet-laptop-07",
        extra={
            "check_id": "disk_encryption",
            "provider": "intune",
            "asset_uid": "EGA-LAPTOP007",
        },
        labels=["intune", "mdm"],
    )
    jamf = _finding(
        ref_id="WAZ-diskenc-jamf-fleet-laptop-07",
        source="host-wazuh",
        name="Disk encryption disabled on fleet-laptop-07",
        extra={
            "check_id": "disk_encryption",
            "provider": "jamf",
            "asset_uid": "EGA-LAPTOP007",
        },
        labels=["jamf", "mdm"],
    )
    out = _load(
        tmp_path,
        monkeypatch,
        [_asset("fleet-laptop-07", "EGA-LAPTOP007"), intune, jamf],
    )
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert_flood_guard(summary)
    assert summary["duplicates_merged"] == 1
    assert summary["flood_guard"]["findings_in"] == 2
    assert summary["flood_guard"]["poam_rows"] == 1
    assert summary["flood_guard"]["excluded_rows"] == 1
    poam = csv_rows(out / "poam" / "poam.csv")
    excluded = csv_rows(out / "poam" / "excluded.csv")
    assert len(poam) == 1
    assert poam[0]["poam_id"].startswith("EGP-")
    assert len(excluded) == 1
    assert excluded[0]["excluded_reason"] == "DUPLICATE_INSTANCE"
    assert excluded[0]["finding_ref_id"] == "WAZ-diskenc-jamf-fleet-laptop-07"
    assert excluded[0]["superseded_by"] == poam[0]["poam_id"]
    fed = csv_rows(out / "poam" / "poam_fedramp.csv")
    assert [row["POAM ID"] for row in fed] == [poam[0]["poam_id"]]


def test_write_fedramp_without_decisions_does_not_dump_ledger(tmp_path: Path) -> None:
    """Fail-closed: a fat ledger is not an Open export when decisions are omitted."""
    from shared.poam_fedramp import FEDRAMP_CSV_NAME, write_fedramp_poam

    ledger = {
        "items": {
            "EGP-INFO": {
                "poam_id": "EGP-INFO",
                "status": "open",
                "name": "Host discovered",
                "weakness_name": "Host discovered",
            },
            "EGP-KEEP": {
                "poam_id": "EGP-KEEP",
                "status": "open",
                "name": "SMB file sharing is exposed",
                "weakness_name": "SMB file sharing is exposed",
            },
        }
    }
    write_fedramp_poam(tmp_path, ledger)
    assert csv_rows(tmp_path / FEDRAMP_CSV_NAME) == []
    write_fedramp_poam(
        tmp_path,
        ledger,
        decisions=[
            {
                "item": ledger["items"]["EGP-KEEP"],
                "weakness": "SMB file sharing is exposed",
                "fields": {"poam_id": "EGP-KEEP"},
                "mapped": {},
                "rec": {},
                "assets_s": "filesrv",
            }
        ],
    )
    rows = csv_rows(tmp_path / FEDRAMP_CSV_NAME)
    assert [row["POAM ID"] for row in rows] == ["EGP-KEEP"]
