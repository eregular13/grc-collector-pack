"""Farm ↔ orchestrator slot selection. No catalog inflation. No LICENSE-LOCK live."""

from __future__ import annotations

from pathlib import Path

import pytest

from dropbox.orchestrator.farm import Farm
from dropbox.orchestrator.pipeline import (
    EXTERNAL_PLAN_REASON,
    deepen_stage,
    discover_stage,
    external_stage,
    ingest_stage,
    orchestrate,
)
from dropbox.scope import FORBIDDEN_TOOLS, GateError, load_scope
from farm.adapters.catalog import (
    FILE_DROP_ONLY,
    LICENSE_LOCK_LIVE,
    dropped_file_inventory,
    load_slots,
    refuse_live_slot,
    select_stage_slots,
)
from farm.adapters.stubs import argv_for, run_slot

ROOT = Path(__file__).resolve().parents[1]


def test_plan_lists_slots_per_stage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setattr("dropbox.orchestrator.pipeline._which", lambda name: None)
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    summary = orchestrate(scope, live=False)
    slots = summary["slots"]
    assert set(slots) == {"discover", "deepen", "external"}
    disc = slots["discover"]["selected"]
    names = {row["slot"] for row in disc}
    assert "nmap" in names
    assert "nuclei" not in names
    assert "nessus" not in names
    nmap = next(row for row in disc if row["slot"] == "nmap")
    assert nmap["will_run"] is False
    assert "PATH" in nmap["reason"]
    deep = {row["slot"] for row in slots["deepen"]["selected"]}
    assert "nessus" in deep
    assert "openvas" not in deep
    ext_rows = slots["external"]["selected"]
    ext = {row["slot"] for row in ext_rows}
    assert "curl" in ext
    assert all(row["will_run"] is False for row in ext_rows)
    assert all("plan-only" in row["reason"] or "file_drop" in row["reason"] for row in ext_rows)
    assert slots["external"]["ready"] == []
    assert slots["external"]["primary"] == ""
    assert summary["external"]["mode"] == "plan"
    assert summary["external"]["live"] is False
    assert "external (plan-only)" in summary["stage_graph"]
    assert summary["discover"]["slots"]["stage"] == "discover"
    assert summary["deepen"]["slots"]["stage"] == "deepen"


def test_select_refuses_nuclei_openvas_even_if_named() -> None:
    plan = select_stage_slots("deepen", ["nessus", "nuclei", "openvas"], which=lambda n: f"/stub/{n}")
    selected = {row["slot"] for row in plan["selected"]}
    skipped = {row["slot"]: row for row in plan["skipped"]}
    assert "nessus" in selected
    assert "nuclei" not in selected
    assert "openvas" not in selected
    assert "LICENSE-LOCK" in skipped["nuclei"]["reason"]
    assert "LICENSE-LOCK" in skipped["openvas"]["reason"]
    assert refuse_live_slot("nuclei") 
    assert refuse_live_slot("openvas")
    for name in FILE_DROP_ONLY:
        assert refuse_live_slot(name)
    for name in ("nuclei", "openvas"):
        with pytest.raises(GateError, match="LICENSE-LOCK"):
            argv_for(name, f"/stub/{name}", "10.20.30.0/24", 8)


def test_license_lock_and_file_drop_never_will_run() -> None:
    """Even if every slot is allowlisted and on PATH, locked names stay dark."""
    slots = load_slots()
    allow = sorted({str(slot.get("binary") or name) for name, slot in slots.items()} | set(slots))
    locked = (
        set(LICENSE_LOCK_LIVE)
        | set(FILE_DROP_ONLY)
        | set(FORBIDDEN_TOOLS)
        | {
            "bloodhound",
            "azurehound",
            "sharphound",
            "pingcastle",
            "purpleknight",
            "nuclei",
            "openvas",
            "gvm",
            "enum4linux-ng",
            "smbmap",
            "zmap",
            "unicornscan",
            "hexstrike",
        }
    )
    ready: set[str] = set()
    will_run_true: set[str] = set()
    for stage in ("discover", "deepen", "external"):
        plan = select_stage_slots(stage, allow, which=lambda n: f"/stub/{n}")
        ready.update(plan["ready"])
        for row in plan["selected"]:
            if row.get("will_run"):
                will_run_true.add(row["slot"])
        for row in plan["skipped"]:
            assert row.get("will_run") is False
    overlap = (ready | will_run_true) & locked
    assert not overlap, f"LICENSE-LOCK/file_drop appeared in will_run: {sorted(overlap)}"
    refuse = set(LICENSE_LOCK_LIVE) | set(FILE_DROP_ONLY) | set(FORBIDDEN_TOOLS)
    for name in locked:
        if name not in slots:
            continue
        assert slots[name].get("invoke") is not True
        if name in refuse:
            assert refuse_live_slot(name, str(slots[name].get("binary") or name))


def test_live_discover_uses_path_invoke_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    for name in ("nmap", "nuclei", "openvas", "nikto"):
        script = bin_dir / name
        script.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "{name}" >> "{marker}"\n'
            "printf 'Host: 10.20.30.5 (app-01.demo.internal) Status: Up\\n'\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm(max_workers=scope.max_workers)
    plan = discover_stage(scope, farm, live=True)
    assert plan["mode"] == "live"
    assert plan["tool"] == "nmap"
    assert plan["slots"]["primary"] == "nmap"
    assert all(row["slot"] != "nuclei" for row in plan["slots"]["selected"])
    invoked = marker.read_text(encoding="utf-8")
    assert "nmap" in invoked
    assert "nuclei" not in invoked
    assert "openvas" not in invoked
    assert "nikto" not in invoked


def test_live_deepen_only_deepen_invoke_on_named_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    for name in ("nessus", "nuclei", "openvas"):
        script = bin_dir / name
        script.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "{name}" >> "{marker}"\n'
            "printf 'DEMO nessus stub\\n'\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm(max_workers=scope.max_workers)
    plan = deepen_stage(scope, farm, live_hosts=["app-01.demo.internal"], live=True)
    assert plan["host_source"] == "discover"
    assert plan["hosts"] == ["app-01.demo.internal"]
    assert plan["tool"] == "nessus"
    skipped = {row["slot"] for row in plan["slots"]["skipped"]}
    assert "nuclei" in skipped and "openvas" in skipped
    invoked = marker.read_text(encoding="utf-8")
    assert "nessus" in invoked
    assert "nuclei" not in invoked
    assert "openvas" not in invoked
    dest = tmp_path / "x.out"
    for name in ("nuclei", "openvas"):
        with pytest.raises(GateError, match="LICENSE-LOCK"):
            run_slot(name, dest, [name], live=True)


def test_missing_discover_slot_has_explicit_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setattr("dropbox.orchestrator.pipeline._which", lambda name: None)
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm(max_workers=1)
    plan = discover_stage(scope, farm, live=True)
    assert plan["mode"] == "plan"
    assert plan["tool_ready"] is False
    nmap = next(row for row in plan["slots"]["selected"] if row["slot"] == "nmap")
    assert nmap["will_run"] is False
    assert "PATH" in nmap["reason"]
    assert "PATH" in plan["skip_reason"]
    rust = next(row for row in plan["slots"]["skipped"] if row["slot"] == "rustscan")
    assert rust["state"] == "not-allowlisted"
    assert LICENSE_LOCK_LIVE


def test_external_stage_never_live_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.txt"
    for name in ("curl", "testssl"):
        script = bin_dir / name
        script.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "{name}" >> "{marker}"\n',
            encoding="utf-8",
        )
        script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    plan = external_stage(scope, dest_in=tmp_path / "in", live=True)
    assert plan["mode"] == "plan"
    assert plan["live"] is False
    assert plan["plan_only"] is True
    assert plan["workers"] == []
    assert EXTERNAL_PLAN_REASON in plan["skip_reason"]
    curl = next(row for row in plan["slots"]["selected"] if row["slot"] == "curl")
    assert curl["will_run"] is False
    assert "in/easm" in curl["reason"]
    assert not marker.exists()


def test_dropbox_external_script_is_demo_fixture_writer() -> None:
    script = (ROOT / "scripts" / "dropbox-external.sh").read_text(encoding="utf-8")
    assert "--live" not in script
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    block = makefile.split("dropbox-external:")[1].split("dropbox-orchestrate:")[0]
    assert "--live" not in block
    assert "run --profile external" in block


def test_ingest_inventories_dropped_external_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    dest = tmp_path / "in"
    easm = dest / "easm"
    easm.mkdir(parents=True)
    (easm / ".gitkeep").write_text("", encoding="utf-8")
    (easm / "plan.json").write_text("{}\n", encoding="utf-8")
    (easm / "amass.json").write_text('{"name":"vpn.example.com"}\n', encoding="utf-8")
    (easm / "httpx.jsonl").write_text('{"host":"vpn.example.com"}\n', encoding="utf-8")
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    marker = ingest_stage(scope, dest_in=dest)
    dropped = marker["dropped_external"]
    assert marker["live"] is False
    assert marker["probed"] is False
    assert dropped["live"] is False
    assert dropped["will_run"] is False
    assert dropped["probed"] is False
    assert dropped["file_count"] == 2
    assert "easm/amass.json" in dropped["files"]
    assert "easm/httpx.jsonl" in dropped["files"]
    assert "easm/.gitkeep" not in dropped["files"]
    assert "easm/plan.json" not in dropped["files"]
    assert dropped["sensors"]["easm"] == ["amass.json", "httpx.jsonl"]


def test_ingest_empty_in_has_zero_dropped_external(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    dest = tmp_path / "in"
    dest.mkdir()
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    marker = ingest_stage(scope, dest_in=dest)
    dropped = marker["dropped_external"]
    assert dropped["file_count"] == 0
    assert dropped["files"] == []
    assert dropped["live"] is False
    assert dropped["will_run"] is False


def test_ingest_skips_external_plan_json_and_does_not_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    orch = tmp_path / "orch"
    (orch / "external").mkdir(parents=True)
    (orch / "external" / "plan.json").write_text("{}\n", encoding="utf-8")
    (orch / "external" / "headers.jsonl").write_text(
        '{"url":"https://vpn.example.com"}\n', encoding="utf-8"
    )
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(orch))
    dest = tmp_path / "in"
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    marker = ingest_stage(scope, dest_in=dest)
    assert not (dest / "easm" / "dropbox-external-plan.json").exists()
    copied = dest / "easm" / "dropbox-external-headers.jsonl"
    assert copied.is_file()
    assert str(copied) in marker["copied"]
    dropped = marker["dropped_external"]
    assert "easm/dropbox-external-headers.jsonl" in dropped["files"]
    assert dropped["live"] is False
    assert dropped["probed"] is False
    inv = dropped_file_inventory(dest, category="external")
    assert inv["file_count"] == 1
    assert inv["live"] is False
