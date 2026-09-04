"""Farm slot catalog + callable adapter stubs. Zero binaries. Plan-only default."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from dropbox.scope import FORBIDDEN_TOOLS, GateError
from farm.adapters.catalog import (
    FILE_DROP_ONLY,
    LAYER_C_SENSORS,
    LICENSE_CLASSES,
    REQUIRED_FIELDS,
    audit_output_globs,
    catalog_summary,
    farm_slot_status,
    ingest_map,
    invoke_slots,
    load_slots,
    parse_output_glob,
    render_slots_md,
    wired_slots,
)
from farm.adapters.stubs import NEVER_SUBPROCESS, argv_for, run_slot

ROOT = Path(__file__).resolve().parents[1]
FARM = ROOT / "farm"


def _stub(bin_dir: Path, name: str, marker: Path, payload: str) -> Path:
    script = bin_dir / name
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "{name}" >> "{marker}"\n'
        f"cat <<'EOF'\n{payload}\nEOF\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def test_catalog_has_forty_plus_slots_and_required_fields() -> None:
    slots = load_slots()
    assert len(slots) >= 95
    categories = {v.get("category") or v.get("stage") for v in slots.values()}
    for needed in (
        "discover",
        "deepen",
        "external",
        "endpoint",
        "identity",
        "cloud",
        "k8s",
        "secrets",
        "wifi",
        "ot",
    ):
        assert needed in categories
    for name, slot in slots.items():
        for field in REQUIRED_FIELDS:
            assert slot.get(field) not in (None, ""), f"{name} missing {field}"
        assert slot.get("id") == name
        assert slot.get("vendored") is False
        assert slot.get("license_class") in LICENSE_CLASSES
        assert str(slot.get("output_glob") or "").startswith("in/")
        assert slot.get("scope_key") in {"allow_tools", "file_drop"}
        assert int(slot.get("default_batch") or 0) >= 1
    wired = wired_slots()
    assert len(wired) >= 21
    invoke = invoke_slots()
    assert len(invoke) >= 21
    counts = catalog_summary()
    assert counts["total"] == len(slots)
    assert counts["wired"] == len(wired)
    assert counts["invoke"] == len(invoke)
    assert "openssl" in invoke and "nslookup" in invoke
    assert len(invoke) >= 28
    assert "ping" in invoke and "traceroute" in invoke
    assert "hostname" in invoke
    assert len(invoke) >= 30
    assert "journal-export" in invoke and "kubectl" in invoke
    assert "snmpwalk" in invoke
    assert audit_output_globs() == []
    for name in FILE_DROP_ONLY:
        assert name in slots
        assert slots[name].get("invoke") is False
        assert slots[name].get("scope_key") == "file_drop"
    md = (FARM / "SLOTS.md").read_text(encoding="utf-8")
    assert f"Total: {counts['total']}" in md
    assert "By category" in md
    assert "Ingest map (Layer C)" in md
    assert "Nmap file-drop" in md
    assert "in/nmap/" in md
    assert "never subprocesses" in md or "parse-only" in md
    assert "masscan" in md
    assert "use_dont_ship" in md
    assert "masscan.xml" in md
    assert "rustscan" in md
    assert "naabu" in md
    assert "naabu.jsonl" in md
    assert "arp-scan" in md
    assert "arp-scan.txt" in md
    assert slots["arp-scan"].get("scope_key") == "file_drop"
    assert slots["arp-scan"].get("wired") is False
    assert slots["arp-scan"].get("invoke") is False
    assert "fping" in md
    assert "fping.txt" in md
    assert slots["fping"].get("scope_key") == "file_drop"
    assert slots["fping"].get("wired") is False
    assert slots["fping"].get("invoke") is False
    assert "netdiscover" in md
    assert "netdiscover.txt" in md
    assert slots["netdiscover"].get("scope_key") == "file_drop"
    assert slots["netdiscover"].get("wired") is False
    assert slots["netdiscover"].get("invoke") is False
    assert "nbtscan" in md
    assert "nbtscan.txt" in md
    assert slots["nbtscan"].get("scope_key") == "file_drop"
    assert slots["nbtscan"].get("wired") is False
    assert slots["nbtscan"].get("invoke") is False
    assert "smbmap" in md
    assert "smbmap.txt" in md
    assert slots["smbmap"].get("scope_key") == "file_drop"
    assert slots["smbmap"].get("wired") is False
    assert slots["smbmap"].get("invoke") is False
    assert slots["smbmap"].get("sensor") == "nmap"
    assert "enum4linux-ng" in md
    assert "enum4linux-ng.txt" in md
    assert slots["enum4linux-ng"].get("scope_key") == "file_drop"
    assert slots["enum4linux-ng"].get("wired") is False
    assert slots["enum4linux-ng"].get("invoke") is False
    assert slots["enum4linux-ng"].get("sensor") == "identity"
    assert "zmap" in md
    assert "zmap.txt" in md
    assert slots["zmap"].get("scope_key") == "file_drop"
    assert slots["zmap"].get("wired") is False
    assert slots["zmap"].get("invoke") is False
    assert "unicornscan" in md
    assert "unicornscan.txt" in md
    assert slots["unicornscan"].get("scope_key") == "file_drop"
    assert slots["unicornscan"].get("invoke") is False
    assert "Kubernetes file-drop" in md
    assert "kube-bench" in md
    assert "Kubescape" in md
    assert "KEEP-chain file-drop" in md
    assert "testssl" in md
    assert "sslscan.xml" in md
    assert "ssltest" in md
    assert "Maester" in md
    assert "BloodHound CE file-drop" in md
    assert "SharpHound" in md
    assert "ObjectIdentifier" in md
    assert "Endpoint file-drop" in md
    assert "HardeningKitty" in md
    assert "Lynis" in md
    assert "Fleet" in md
    assert "CIS-CAT" in md
    assert "osquery" in md
    assert "in/identity/" in md
    assert "Cloud file-drop" in md
    assert "in/cloud/" in md
    assert "ScoutSuite" in md
    assert "ASFF" in md
    assert "EASM file-drop" in md
    assert "httpx" in md
    assert "Amass" in md
    assert "ffuf" in md
    assert "gobuster" in md
    assert "WhatWeb" in md
    assert "whatweb.json" in md
    assert "(Status:" in md or "Status:" in md
    assert "Nuclei JSON file-drop" in md
    assert "template_id" in md
    assert "Nikto file-drop" in md
    assert "niktoscan" in md
    assert "Nessus file-drop" in md
    assert "ReportHost" in md
    assert "demo.nessus" in md
    assert "SaaS file-drop" in md
    assert "ScubaGear" in md
    assert "scuba-wrap.json" in md
    assert "Secrets / IaC file-drop" in md
    assert "failed_checks" in md
    assert "SARIF file-drop" in md
    assert "in/vuln/*.sarif" in md
    for sensor in LAYER_C_SENSORS:
        assert f"| in/{sensor}/ |" in md
    assert "nikto" in md and "checkov" in md
    assert render_slots_md() == md
    for required in (
        "nmap",
        "nessus",
        "nessuscli",
        "curl",
        "testssl",
        "lynis",
        "ss",
        "ip",
        "prowler",
        "hardeningkitty-export",
        "maester",
        "trivy",
        "rustscan",
        "naabu",
        "httpx",
        "dig",
        "whois",
        "sslscan",
        "kube-bench",
        "gitleaks",
    ):
        assert required in wired
    assert "kube-bench" not in invoke and "gitleaks" not in invoke
    assert invoke["rustscan"].get("invoke") is True


def test_forbidden_slots_are_file_drop_not_wired() -> None:
    slots = load_slots()
    for name, slot in slots.items():
        binary = str(slot.get("binary") or name).lower()
        if name in FORBIDDEN_TOOLS or binary in FORBIDDEN_TOOLS:
            assert slot.get("wired") is not True, name
            assert slot.get("scope_key") == "file_drop", name


def test_wired_slots_invoke_path_stubs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    invoke = invoke_slots()
    for name, slot in invoke.items():
        _stub(bin_dir, str(slot["binary"]), marker, f"DEMO {name} stub\n")
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + "/usr/bin")
    allow = [str(s["binary"]) for s in invoke.values()]
    dest_root = tmp_path / "out"
    for name, slot in invoke.items():
        dest = dest_root / f"{name}.out"
        named_only = {
            "ping",
            "traceroute",
            "tracepath",
            "host",
            "getent",
            "snmpwalk",
            "httpx",
            "dig",
            "whois",
            "sslscan",
            "openssl",
            "nslookup",
        }
        target = "vpn.example.com" if slot["stage"] == "external" else "10.20.30.0/24"
        if name in named_only:
            target = "vpn.example.com"
        if name in {"nmap", "rustscan", "naabu"}:
            target = "10.20.30.0/24"
        result = run_slot(name, dest, allow, target=target, timeout=8, live=True)
        assert result["ran"] is True, result
        assert result["mode"] == "live"
        assert dest.is_file()
    text = marker.read_text(encoding="utf-8")
    for slot in invoke.values():
        assert str(slot["binary"]) in text


def test_missing_binary_stays_plan_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    dest = tmp_path / "nmap.out"
    result = run_slot("nmap", dest, ["nmap"], target="10.20.30.0/24", live=True)
    assert result["ran"] is False
    assert result["mode"] == "plan"
    assert "PATH" in result["skip_reason"]
    assert not dest.exists()


def test_non_allowlisted_and_file_drop_never_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    _stub(bin_dir, "nmap", marker, "SHOULD-NOT-RUN\n")
    _stub(bin_dir, "nuclei", marker, "SHOULD-NOT-RUN\n")
    monkeypatch.setenv("PATH", str(bin_dir))
    dest = tmp_path / "x.out"
    result = run_slot("nmap", dest, ["lynis"], target="10.20.30.0/24", live=True)
    assert result["ran"] is False
    assert not marker.exists() or "nmap" not in marker.read_text(encoding="utf-8")
    with pytest.raises(GateError, match="LICENSE-LOCK"):
        run_slot("nuclei", dest, ["nuclei"], live=True)
    with pytest.raises(GateError, match="LICENSE-LOCK"):
        argv_for("nuclei", "/stub/nuclei", ".", 8)


def test_plan_only_when_live_false(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    _stub(bin_dir, "lynis", marker, "lynis stub\n")
    monkeypatch.setenv("PATH", str(bin_dir))
    dest = tmp_path / "lynis.out"
    result = run_slot("lynis", dest, ["lynis"], live=False)
    assert result["mode"] == "plan"
    assert result["tool_ready"] is True
    assert result["ran"] is False
    assert not marker.exists()


def test_file_drop_stubs_and_license_lock_never_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    for name in ("kube-bench", "gitleaks", "nuclei", "openvas", "pingcastle"):
        _stub(bin_dir, name, marker, "SHOULD-NOT-RUN\n")
    monkeypatch.setenv("PATH", str(bin_dir))
    dest = tmp_path / "x.out"
    for name in ("kube-bench", "gitleaks"):
        result = run_slot(name, dest, [name], live=True)
        assert result["mode"] == "file_drop"
        assert result["ran"] is False
        assert result["subprocess"] is False
    for name in NEVER_SUBPROCESS & {"nuclei", "openvas", "pingcastle"}:
        with pytest.raises(GateError, match="LICENSE-LOCK"):
            run_slot(name, dest, [name], live=True)
        with pytest.raises(GateError, match="LICENSE-LOCK"):
            argv_for(name, f"/stub/{name}", ".", 8)
    assert not marker.exists()


def test_named_host_slots_refuse_cidr() -> None:
    for name in ("ping", "traceroute", "tracepath", "host", "getent", "snmpwalk"):
        with pytest.raises(GateError, match="wildcard/CIDR"):
            argv_for(name, f"/stub/{name}", "10.20.30.0/24", 8)
        argv = argv_for(name, f"/stub/{name}", "vpn.example.com", 8)
        assert argv[0] == f"/stub/{name}"
        assert "10.20.30.0/24" not in argv


def test_file_drop_only_never_gets_argv(tmp_path: Path) -> None:
    dest = tmp_path / "x.out"
    for name in FILE_DROP_ONLY:
        with pytest.raises(GateError, match="file_drop only"):
            argv_for(name, f"/stub/{name}", "vpn.example.com", 8)
        result = run_slot(name, dest, [name], target="vpn.example.com", live=True)
        assert result["ran"] is False
        assert result["subprocess"] is False
        assert result["mode"] == "file_drop"


def test_farm_slot_status_filters_category() -> None:
    rows = farm_slot_status(["nmap", "ss"], category="discover")
    assert rows
    assert all(row["category"] == "discover" for row in rows)
    names = {row["slot"] for row in rows}
    assert "nmap" in names
    assert "ping" in names
    assert "prowler" not in names


def test_layer_c_sensor_dirs_exist() -> None:
    for sensor in LAYER_C_SENSORS:
        path = ROOT / "in" / sensor
        assert path.is_dir(), path
    mapped = ingest_map()
    assert set(mapped) == set(LAYER_C_SENSORS)
    assert sum(b["total"] for b in mapped.values()) == len(load_slots())
    assert audit_output_globs() == []
    assert parse_output_glob("in/easm/*.jsonl") == ("easm", "*.jsonl")
    assert parse_output_glob("in/not-a-sensor/*.txt") is None
    assert parse_output_glob("easm/*.json") is None
