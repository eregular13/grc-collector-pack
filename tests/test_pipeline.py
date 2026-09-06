from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SENSORS = ("cloud", "nmap", "vuln", "wazuh", "identity", "easm", "k8s", "code", "saas")


def _run_collectors() -> None:
    from collectors import (
        cloud_prowler,
        code_secrets,
        easm,
        host_wazuh,
        identity_ad,
        inventory_nmap,
        k8s_kubescape,
        saas_idp,
        vuln_scan,
    )

    cloud_prowler.main()
    inventory_nmap.main()
    vuln_scan.main()
    host_wazuh.main()
    identity_ad.main()
    easm.main()
    k8s_kubescape.main()
    code_secrets.main()
    saas_idp.main()


def test_emit_always_writes_sensor_evidence_md(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("PACK_ROOT", str(ROOT))
    from shared.io_util import emit
    from shared.schema import asset

    rec = asset("CLD-", "x", "x", source="t", asset_type="SP")
    emit("cloud", [rec], [])
    path = tmp_path / "out" / "evidence" / "cloud.md"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert text.startswith("# Evidence — cloud")
    assert "cloud" in text.lower()
    for sensor in SENSORS:
        emit(sensor, [rec], [])
        md = tmp_path / "out" / "evidence" / f"{sensor}.md"
        assert md.exists(), sensor
        body = md.read_text(encoding="utf-8")
        assert body.startswith(f"# Evidence — {sensor}")
        assert sensor.lower() in body.lower()


def test_discover_empty_in_uses_fixtures(tmp_path, monkeypatch) -> None:
    import shutil

    from shared.io_util import discover_input_files

    pack = tmp_path / "pack"
    shutil.copytree(ROOT / "fixtures", pack / "fixtures")
    for sensor in SENSORS:
        (pack / "in" / sensor).mkdir(parents=True)
    monkeypatch.setenv("PACK_ROOT", str(pack))
    files = discover_input_files("cloud")
    assert files, "empty in/ must fall back to fixtures"
    assert all("fixtures" in str(p).replace("\\", "/") for p in files)


def test_discover_prefers_in_over_fixtures(tmp_path, monkeypatch) -> None:
    from shared.io_util import discover_input_files

    pack = tmp_path / "pack"
    sensor_in = pack / "in" / "cloud"
    sensor_in.mkdir(parents=True)
    demo = pack / "fixtures" / "demo" / "cloud"
    demo.mkdir(parents=True)
    (sensor_in / "only-in.json").write_text("{}", encoding="utf-8")
    (demo / "only-fix.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("PACK_ROOT", str(pack))
    names = [p.name for p in discover_input_files("cloud")]
    assert names == ["only-in.json"]


def test_loader_exclusive_lock_blocks_second(tmp_path) -> None:
    from shared.io_util import exclusive_file_lock

    lock = tmp_path / "out" / ".loader.lock"
    with exclusive_file_lock(lock, timeout=1):
        assert lock.exists()
        with pytest.raises(SystemExit) as exc:
            with exclusive_file_lock(lock, timeout=0.2):
                pass
        assert "lock" in str(exc.value).lower()
    with exclusive_file_lock(lock, timeout=1):
        assert lock.exists()


def test_loader_refuses_race_without_canonical(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PACK_ROOT", str(ROOT))
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    from collectors.grc_loader import run_loader

    with pytest.raises(SystemExit) as exc:
        run_loader()
    assert "missing canonical" in str(exc.value)


def test_double_loader_idempotent(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PACK_ROOT", str(ROOT))
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("GRC_LIVE_SCAN", "1")
    monkeypatch.setenv("CISO_PUSH", "0")
    monkeypatch.setenv("RISKREADY_PUSH", "0")
    _run_collectors()
    from collectors.grc_loader import run_loader

    first = run_loader()
    _run_collectors()
    second = run_loader()
    assert first == second
    assert first["assets"] >= 20
    assert first["findings"] >= 20
    assert first["evidence"] >= 8
    assets = list(
        csv.DictReader((tmp_path / "out" / "ciso-assistant" / "assets.csv").open(encoding="utf-8"))
    )
    refs = [row["ref_id"] for row in assets]
    assert len(refs) == len(set(refs))
    risks = json.loads((tmp_path / "out" / "riskready" / "risks_proposed.json").read_text(encoding="utf-8"))
    assert risks
    assert all(str(r.get("severity")).lower() in {"high", "critical"} for r in risks)
    findings = list(
        csv.DictReader((tmp_path / "out" / "ciso-assistant" / "findings.csv").open(encoding="utf-8"))
    )
    high_crit = [row for row in findings if row.get("severity") in {"high", "critical"}]
    from shared.schema import FINDING_STATUSES

    assert all(row.get("status") in FINDING_STATUSES for row in findings)
    with (tmp_path / "out" / "ciso-assistant" / "risk_scenarios.csv").open(encoding="utf-8", newline="") as handle:
        scenarios = list(csv.DictReader(handle, delimiter=";"))
    assert len(scenarios) == len(high_crit)
    assert {r["ref_id"] for r in scenarios} == {f"RSK-{r['ref_id']}" for r in high_crit}
