"""Cold-start SAMPLE → CISO operator entrypoint. SAMPLE ≠ client KEEP."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from keep.ciso_import import (
    CISO_REQUIRED,
    SampleHonestyError,
    verify_sample_sor,
)
from shared.ciso_shape import (
    FINDING_SEV,
    REGISTER_OK_LINE,
    SCENARIO_LEVELS,
    assert_risk_register_and_poam,
    csv_rows,
    write_minimal_register,
)


def _tree_fingerprint(folder: Path) -> dict[str, str]:
    """Relative path → sha256. Missing folder is empty (pack keep/work may be absent)."""
    out: dict[str, str] = {}
    if not folder.is_dir():
        return out
    for path in sorted(folder.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(folder)).replace("\\", "/")
        out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def _assert_import_honesty(ciso: Path) -> dict:
    import_doc = json.loads((ciso / "IMPORT.json").read_text(encoding="utf-8"))
    assert import_doc["demo"] is True
    assert import_doc["sample"] is True
    assert import_doc["client_keep"] is False
    assert import_doc["paying_day"] == "FAIL"
    assert import_doc["posted"] is False
    shape = assert_risk_register_and_poam(ciso)
    assert shape["findings"] >= 1
    assert shape["risk_scenarios"] >= shape["poam_rows"]
    assert shape["poam_rows"] >= 1
    assert shape["vulnerabilities"] >= 1, "SAMPLE keep-samples include testssl/prowler CVE-class rows"
    for row in csv_rows(ciso / "findings.csv"):
        assert row["severity"] in FINDING_SEV, row
        assert row["ref_id"]
        assert row["name"]
    scenarios = csv_rows(ciso / "risk_scenarios.csv", delimiter=";")
    assert len(scenarios) >= shape["poam_rows"]
    excluded_path = ciso.parent / "poam" / "excluded.csv"
    excluded = csv_rows(excluded_path) if excluded_path.is_file() else []
    from shared.ciso_shape import assert_register_no_double_treatment
    from shared.egp_collapse import is_merged_into_reason

    accept_n = 0
    mitigate_n = 0
    for row in scenarios:
        assert row["ref_id"]
        assert row["name"]
        assert row.get("current_risk") in SCENARIO_LEVELS, row
        treat = row.get("treatment")
        assert treat in {"mitigate", "accept"}, row
        assert (row.get("existing_controls") or "") == "", row
        if treat == "accept":
            accept_n += 1
            assert (row.get("additional_controls") or "") == ""
            assert row.get("residual_risk") == row.get("current_risk"), row
        else:
            mitigate_n += 1
            assert str(row.get("additional_controls") or "").startswith("CTL-"), row
    non_merged = [
        row
        for row in excluded
        if not is_merged_into_reason(str(row.get("excluded_reason") or ""))
    ]
    assert mitigate_n == shape["poam_rows"]
    assert accept_n == len(non_merged)
    overlap = assert_register_no_double_treatment(ciso.parent)
    assert not overlap["title_host_overlap"]
    assert not overlap["egp_overlap"]
    poam = csv_rows(ciso.parent / "poam" / "poam.csv")
    assert poam
    for row in poam:
        assert row["weakness"]
        assert row["severity"] in FINDING_SEV, row
        assert row["status"] == "open"
        assert (row.get("owner") or "") == ""
        assert (row.get("due") or "") == ""
        assert row.get("recommended_fix")
    return import_doc

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sample_to_sor.sh"
PS1 = ROOT / "scripts" / "sample_to_sor.ps1"


def _honest_bundle(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "IMPORT.json").write_text(
        json.dumps(
            {
                "demo": True,
                "sample": True,
                "client_keep": False,
                "paying_day": "FAIL",
                "posted": False,
                "http": False,
                "wrap": "review-only",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    write_minimal_register(folder, with_poam=True)


def test_sample_to_sor_scripts_force_safety_env() -> None:
    sh = SCRIPT.read_text(encoding="utf-8")
    ps1 = PS1.read_text(encoding="utf-8")
    assert SCRIPT.is_file()
    assert PS1.is_file()
    assert os.access(SCRIPT, os.X_OK)
    for blob in (sh, ps1):
        assert "DRY_RUN" in blob and "1" in blob
        assert "GRC_LIVE_SCAN" in blob
        assert "CISO_PUSH" in blob
        assert "RISKREADY_PUSH" in blob
        assert "DROPBOX_LIVE" in blob
        assert "keep lab" in blob or "-m keep" in blob
        assert "keep verify" in blob
        assert "elapsed" in blob
        assert "ciso-assistant" in blob
        assert "/api/risks" in sh or "SAMPLE" in blob
    assert "export DRY_RUN=1" in sh
    assert "export GRC_LIVE_SCAN=0" in sh
    assert "export CISO_PUSH=0" in sh
    assert "export RISKREADY_PUSH=0" in sh
    assert "export DROPBOX_LIVE=0" in sh
    assert "python3 -m keep lab" in sh or '-m keep lab' in sh
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "sample-to-sor:" in makefile
    assert "scripts/sample_to_sor.sh" in makefile


def test_readme_and_operator_first_lines_point_at_one_command() -> None:
    readme_head = "".join((ROOT / "README.md").read_text(encoding="utf-8").splitlines()[:12])
    op_head = "".join((ROOT / "keep" / "OPERATOR.md").read_text(encoding="utf-8").splitlines()[:12])
    assert "sample_to_sor.sh" in readme_head
    assert "sample-to-sor" in readme_head or "sample_to_sor" in readme_head
    assert "sample_to_sor.ps1" in readme_head
    assert "SAMPLE ≠ client" in readme_head or "SAMPLE ≠ client KEEP" in readme_head
    assert "keep_status" in readme_head
    assert "keep_ciso" in readme_head
    assert "sample_to_sor.sh" in op_head
    assert "sample_to_sor.ps1" in op_head
    assert "SAMPLE ≠ client KEEP" in op_head or "SAMPLE ≠ client" in op_head
    op = (ROOT / "keep" / "OPERATOR.md").read_text(encoding="utf-8")
    assert "python3 -m keep lab" in op
    assert "keep_status" in op and "keep_ciso" in op
    dry = (ROOT / "docs" / "DESKTOP_DRY_RUN.md").read_text(encoding="utf-8")
    assert "sample_to_sor.sh" in dry
    assert "keep/__main__.py" in dry
    assert "full git clone" in dry
    assert "cold-path-gate" in dry
    op = (ROOT / "keep" / "OPERATOR.md").read_text(encoding="utf-8")
    assert "keep/__main__.py" in op
    assert "full git clone" in op
    assert "cold-path-gate" in op


def test_sample_to_sor_console_prints_are_ascii_cp1252() -> None:
    """DESKTOP-222GHQV Windows cp1252 cannot print U+2260 / U+2192."""
    assert REGISTER_OK_LINE.isascii()
    REGISTER_OK_LINE.encode("cp1252")
    for path in (SCRIPT, PS1):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("echo ", "Write-Host ")):
                stripped.encode("cp1252")
                assert "\u2260" not in stripped
                assert "\u2192" not in stripped


def test_lab_yml_has_cold_sample_to_sor_job() -> None:
    yml = (ROOT / ".github" / "workflows" / "lab.yml").read_text(encoding="utf-8")
    assert "sample-to-sor-cold:" in yml
    assert "scripts/sample_to_sor.sh" in yml
    assert "--exporters" in yml
    assert "IMPORT.json" in yml
    assert "client_keep" in yml
    assert "paying_day" in yml
    assert "assert_risk_register_and_poam" in yml
    assert "poam_rows" in yml
    assert "POAM_HEADER" in yml
    assert "risk_scenarios" in yml
    assert "ubuntu-latest" in yml
    assert "No Docker" in yml
    assert "keep/__main__.py" in yml


def test_verify_sample_sor_fail_closed_on_dishonest_import(tmp_path: Path) -> None:
    folder = tmp_path / "ciso-assistant"
    _honest_bundle(folder)
    assert verify_sample_sor(folder)["ok"] is True

    dishonest = {
        "paying_day": "PASS",
        "sample": False,
        "demo": False,
        "client_keep": True,
        "posted": True,
    }
    for key, value in dishonest.items():
        doc = json.loads((folder / "IMPORT.json").read_text(encoding="utf-8"))
        doc[key] = value
        (folder / "IMPORT.json").write_text(json.dumps(doc) + "\n", encoding="utf-8")
        with pytest.raises(SampleHonestyError):
            verify_sample_sor(folder)
        _honest_bundle(folder)

    (folder / "findings.csv").unlink()
    with pytest.raises(SampleHonestyError, match="missing"):
        verify_sample_sor(folder)


def test_verify_sample_sor_fail_closed_on_wrong_headers(tmp_path: Path) -> None:
    folder = tmp_path / "ciso-assistant"
    _honest_bundle(folder)
    (folder / "findings.csv").write_text("ref_id,name\nDEMO-1,sample\n", encoding="utf-8")
    with pytest.raises(SampleHonestyError, match="header mismatch"):
        verify_sample_sor(folder)


def test_verify_sample_sor_fail_closed_when_findings_without_poam(tmp_path: Path) -> None:
    folder = tmp_path / "ciso-assistant"
    write_minimal_register(folder, with_poam=False)
    (folder / "IMPORT.json").write_text(
        json.dumps(
            {
                "demo": True,
                "sample": True,
                "client_keep": False,
                "paying_day": "FAIL",
                "posted": False,
                "http": False,
                "wrap": "review-only",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(SampleHonestyError, match="POA&M"):
        verify_sample_sor(folder)


def test_sample_to_sor_verify_only_fail_closed(tmp_path: Path) -> None:
    work = tmp_path / "work"
    ciso = work / "out" / "ciso-assistant"
    _honest_bundle(ciso)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DRY_RUN"] = "1"
    env["CISO_PUSH"] = "0"
    honest = subprocess.run(
        ["bash", str(SCRIPT), "--verify-only", "--work", str(work)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert honest.returncode == 0, honest.stderr or honest.stdout
    assert "elapsed=" in honest.stdout
    assert str(ciso) in honest.stdout

    doc = json.loads((ciso / "IMPORT.json").read_text(encoding="utf-8"))
    doc["paying_day"] = "PASS"
    doc["client_keep"] = True
    doc["sample"] = False
    (ciso / "IMPORT.json").write_text(json.dumps(doc) + "\n", encoding="utf-8")
    bad = subprocess.run(
        ["bash", str(SCRIPT), "--verify-only", "--work", str(work)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode != 0
    assert "SAMPLE_HONESTY_FAIL" in (bad.stderr or "") or "paying_day" in (bad.stderr or "")


def _run_sample_to_sor_isolated(
    tmp_path: Path, *, exporters: bool = False
) -> subprocess.CompletedProcess[str]:
    empty = tmp_path / "empty-in"
    empty.mkdir(exist_ok=True)
    work = tmp_path / ("work-exporters" if exporters else "work")
    pack_in = ROOT / "in"
    pack_work = ROOT / "keep" / "work"
    before_in = _tree_fingerprint(pack_in)
    before_work = _tree_fingerprint(pack_work)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DRY_RUN"] = "0"
    env["CISO_PUSH"] = "1"
    env["RISKREADY_PUSH"] = "1"
    env["GRC_LIVE_SCAN"] = "1"
    env["DROPBOX_LIVE"] = "1"
    cmd = [
        "bash",
        str(SCRIPT),
        "--pack-in",
        str(empty),
        "--work",
        str(work),
    ]
    if exporters:
        cmd.append("--exporters")
    proc = subprocess.run(
        cmd,
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    out_blob = (proc.stdout or "") + (proc.stderr or "")
    out_blob.encode("cp1252")
    assert "\u2260" not in out_blob
    assert "\u2192" not in out_blob
    assert work.resolve() != pack_work.resolve()
    assert work.is_relative_to(tmp_path)
    assert _tree_fingerprint(pack_in) == before_in
    assert _tree_fingerprint(pack_work) == before_work
    assert "elapsed=" in proc.stdout
    assert "ciso=" in proc.stdout
    stamp = json.loads((work / "keep-lab.json").read_text(encoding="utf-8"))
    assert stamp["status"] == "pass"
    assert stamp["sample"] is True
    assert stamp["client_keep"] is False
    assert stamp["paying_day"] == "FAIL"
    assert stamp["posted"] is False
    ciso = work / "out" / "ciso-assistant"
    _assert_import_honesty(ciso)
    for name in CISO_REQUIRED:
        assert (ciso / name).is_file()
    assert (work / "out" / "opengrc" / "risks.csv").is_file()
    assert (work / "out" / "import_preview" / "probo.json").is_file()
    return proc


def test_sample_to_sor_sh_isolated_keep_lab(tmp_path: Path) -> None:
    _run_sample_to_sor_isolated(tmp_path, exporters=False)


def test_sample_to_sor_sh_isolated_keep_lab_exporters(tmp_path: Path) -> None:
    proc = _run_sample_to_sor_isolated(tmp_path, exporters=True)
    assert "exporters" in proc.stdout.lower() or "opengrc" in proc.stdout


def test_sample_to_sor_wipe_work_then_sample_to_sor_emits_ciso_csvs(tmp_path: Path) -> None:
    """DESKTOP stranger path: sample_to_sor → wipe keep/work → sample_to_sor still emits CSVs."""
    from keep.wipe import wipe_tree

    _run_sample_to_sor_isolated(tmp_path, exporters=True)
    work = tmp_path / "work-exporters"
    ciso = work / "out" / "ciso-assistant"
    for name in CISO_REQUIRED:
        assert (ciso / name).is_file()
    wipe_tree(work)
    assert not work.exists() or not any(work.rglob("*.csv"))
    _run_sample_to_sor_isolated(tmp_path, exporters=True)
    for name in CISO_REQUIRED:
        path = ciso / name
        assert path.is_file(), name
        assert path.stat().st_size > 0
    _assert_import_honesty(ciso)


def test_keep_verify_cli_and_main_usage() -> None:
    main = (ROOT / "keep" / "__main__.py").read_text(encoding="utf-8")
    assert "verify" in main
    assert "sample_to_sor" in main
    proc = subprocess.run(
        [sys.executable, "-m", "keep", "verify"],
        cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
