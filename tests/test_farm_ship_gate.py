"""Brick 4: wipe/clone farm_drop→SoR ship-gate. SAMPLE/DEMO != client KEEP."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from shared.ciso_shape import CISO_HEADERS, POAM_HEADER, write_minimal_register
from shared.farm_ship import (
    FARM_SHIP_OK_LINE,
    FARM_SHIP_PATHS,
    FARM_SHIP_TREES,
    ZERO_SHA,
    FarmShipError,
    assert_farm_ship_sor,
    decide_ship,
    surface_fingerprint,
)

ROOT = Path(__file__).resolve().parents[1]
WIPE = ROOT / "scripts" / "ci" / "farm_drop_wipe_clone_ship.sh"
SURFACE = ROOT / "scripts" / "ci" / "farm_ship_surface.py"


def _run_git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return (proc.stdout or "").strip()


def _init_surface_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "surface"
    for rel in FARM_SHIP_PATHS:
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"stub {rel}\n", encoding="utf-8")
    nmap = repo / "fixtures" / "pack_drop" / "nmap"
    nmap.mkdir(parents=True, exist_ok=True)
    (nmap / "meta.json").write_text('{"demo": true}\n', encoding="utf-8")
    (repo / "README.md").write_text("unrelated\n", encoding="utf-8")
    _run_git(repo, "init")
    _run_git(repo, "config", "user.email", "lab@example.com")
    _run_git(repo, "config", "user.name", "lab")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-m", "base")
    return repo


def _honest_farm_work(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    ciso = folder / "out" / "ciso-assistant"
    ciso.mkdir(parents=True, exist_ok=True)
    write_minimal_register(ciso, with_poam=True)
    (ciso / "vulnerabilities.csv").write_text(
        CISO_HEADERS["vulnerabilities.csv"] + "\n",
        encoding="utf-8",
    )
    out = folder / "out"
    label = "SAMPLE DATA: NOT A CLIENT"
    (out / "SCOPE_AND_TRUST.md").write_text(
        f"> **{label}**: Every finding below comes from bundled example files.\n"
        "> Run `not recorded` · generated not recorded · pack `not recorded`\n\n"
        "### Authorization\n"
        "- No client authorization applies. No client systems were touched.\n\n"
        "### What was in scope\n"
        "| Area | Targets / source | Scanner or export used | Version | Collected (date/time) | Records |\n"
        "|---|---|---|---|---|---|\n"
        "| Host / network exposure | bundled sample / fixture | inventory-nmap | not recorded | not recorded | 1 |\n\n"
        "Out of scope, or no data supplied: none.\n",
        encoding="utf-8",
    )
    (out / "EXECUTIVE_SUMMARY.md").write_text(
        f"> **{label}**: Every finding below comes from bundled example files. None describes any real organization.\n",
        encoding="utf-8",
    )
    from shared.estate_pages import write_export_manifest

    write_export_manifest(out)
    (out / "summary.json").write_text(
        json.dumps(
            {
                "findings": 1,
                "poam": 1,
                "excluded": 2,
                "pending_carried": 0,
                "flood_guard": {
                    "findings_in": 3,
                    "poam_rows": 1,
                    "excluded_rows": 2,
                    "pending_carried": 0,
                    "identity": "findings_in + pending_carried == poam_rows + excluded_rows",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (folder / "prove-ciso.json").write_text(
        json.dumps(
            {
                "status": "pass",
                "demo": True,
                "sample": True,
                "client": False,
                "client_keep": False,
                "paying_day": "FAIL",
                "posted": False,
                "counts": {"poam": 1, "findings": 1},
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_ci_scripts_are_lab_only_not_public_entrypoints() -> None:
    assert WIPE.is_file()
    assert SURFACE.is_file()
    assert os.access(WIPE, os.X_OK)
    sh = WIPE.read_text(encoding="utf-8")
    py = SURFACE.read_text(encoding="utf-8")
    for blob in (sh, py):
        assert "CI/lab" in blob or "CI/lab only" in blob
        assert "Not a public operator entrypoint" in blob or "not an operator entrypoint" in blob.lower()
        assert "SAMPLE" in blob
        assert "paying_day" in blob
        assert "client" in blob.lower()
    assert "git archive" in sh
    assert "farm_drop_to_sor" in sh
    assert "assert_risk_register_and_poam" in sh or "assert_farm_ship_sor" in sh
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "farm_drop_wipe_clone_ship" not in makefile
    assert "farm_ship_surface" not in makefile
    readme_head = "\n".join((ROOT / "README.md").read_text(encoding="utf-8").splitlines()[:12])
    assert "farm_drop_wipe_clone_ship" not in readme_head
    assert "farm_ship_surface" not in readme_head
    assert "sample_to_sor.sh" in readme_head
    assert "farm_drop_to_sor.sh" in readme_head


def test_lab_yml_has_cold_farm_ship_gate_job() -> None:
    yml = (ROOT / ".github" / "workflows" / "lab.yml").read_text(encoding="utf-8")
    assert "farm-drop-to-sor-cold:" in yml
    assert "sample-to-sor-cold:" in yml
    assert "farm_drop_wipe_clone_ship.sh" in yml
    assert "farm_ship_surface.py" in yml
    assert "assert_risk_register_and_poam" in yml
    assert "FARM_SHIP=skip" in yml
    assert "paying_day" in yml
    assert "Not client KEEP" in yml
    assert "Identical re-PASS" in yml
    assert "fetch-depth: 0" in yml
    assert "steps.surface.outputs.ship == 'yes'" in yml
    assert "github.event.pull_request.base.sha" in yml
    assert "github.event.before" in yml
    # Warm lab farm step (PR #102) still present — do not regress.
    assert "bash scripts/farm_drop_to_sor.sh --work" in yml


def test_farm_ship_gate_doc_states_when_and_what() -> None:
    doc = (ROOT / "docs" / "FARM_SHIP_GATE.md").read_text(encoding="utf-8")
    assert "Brick 4" in doc
    assert "FARM_SHIP=yes" in doc
    assert "FARM_SHIP=skip" in doc
    assert "identical re-pass" in doc.lower()
    assert "assert_risk_register_and_poam" in doc
    assert "Not client KEEP" in doc or "not client KEEP" in doc
    assert "paying_day" in doc and "FAIL" in doc
    assert "fixtures/pack_drop" in doc
    assert "shared/ciso_shape.py" in doc
    assert "lab_drop_to_sor" in doc
    assert "LAB != SAMPLE != client" in doc or "lab != sample != client" in doc.lower()
    assert "192.168.64.0/24" in doc
    assert "172.16.10.0/24" in doc
    assert "out of scope here" not in doc
    prove = (ROOT / "docs" / "PROVE_CISO.md").read_text(encoding="utf-8")
    assert "FARM_SHIP_GATE.md" in prove
    assert "farm-drop-to-sor-cold" in prove
    assert "scripts/ci/" in prove
    assert "lab_drop_to_sor" in prove


def test_ship_surface_lists_head_and_assertion_paths() -> None:
    assert ".github/workflows/lab.yml" in FARM_SHIP_PATHS
    assert "scripts/farm_drop_to_sor.sh" in FARM_SHIP_PATHS
    assert "scripts/prove_ciso.py" in FARM_SHIP_PATHS
    assert "shared/ciso_shape.py" in FARM_SHIP_PATHS
    assert "shared/estate_pages.py" in FARM_SHIP_PATHS
    assert "shared/farm_ship.py" in FARM_SHIP_PATHS
    assert "shared/control_map.py" in FARM_SHIP_PATHS
    assert "shared/port_fold.py" in FARM_SHIP_PATHS
    assert "fixtures/pack_drop" in FARM_SHIP_TREES
    for rel in FARM_SHIP_PATHS:
        assert (ROOT / rel).is_file(), rel
    assert (ROOT / "fixtures" / "pack_drop" / "nmap" / "meta.json").is_file()


def test_decide_ship_skip_when_only_unrelated_files_change(tmp_path: Path) -> None:
    repo = _init_surface_repo(tmp_path)
    base = _run_git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text("unrelated restamp\n", encoding="utf-8")
    _run_git(repo, "add", "README.md")
    _run_git(repo, "commit", "-m", "not a ship")
    decision = decide_ship(repo, base)
    assert decision["ship"] == "skip"
    assert decision["reason"] == "surface-unchanged"
    assert decision["changed"] == []


def test_decide_ship_yes_when_assertion_surface_changes(tmp_path: Path) -> None:
    repo = _init_surface_repo(tmp_path)
    base = _run_git(repo, "rev-parse", "HEAD")
    shape = repo / "shared" / "ciso_shape.py"
    shape.write_text(shape.read_text(encoding="utf-8") + "# assertion change\n", encoding="utf-8")
    _run_git(repo, "add", "shared/ciso_shape.py")
    _run_git(repo, "commit", "-m", "assertion surface")
    decision = decide_ship(repo, base)
    assert decision["ship"] == "yes"
    assert decision["reason"] == "surface-changed"
    assert any(path.endswith("ciso_shape.py") for path in decision["changed"])


def test_decide_ship_yes_when_pack_drop_fixture_changes(tmp_path: Path) -> None:
    repo = _init_surface_repo(tmp_path)
    base = _run_git(repo, "rev-parse", "HEAD")
    meta = repo / "fixtures" / "pack_drop" / "nmap" / "meta.json"
    meta.write_text('{"demo": true, "note": "surface"}\n', encoding="utf-8")
    _run_git(repo, "add", "fixtures/pack_drop/nmap/meta.json")
    _run_git(repo, "commit", "-m", "pack_drop")
    decision = decide_ship(repo, base)
    assert decision["ship"] == "yes"
    assert "fixtures/pack_drop/nmap/meta.json" in decision["changed"]


def test_decide_ship_yes_on_zero_or_missing_compare_ref(tmp_path: Path) -> None:
    repo = _init_surface_repo(tmp_path)
    assert decide_ship(repo, "")["ship"] == "yes"
    assert decide_ship(repo, ZERO_SHA)["reason"] == "no-compare-ref"
    missing = decide_ship(repo, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    assert missing["ship"] == "yes"
    assert missing["reason"] == "compare-ref-unresolved"


def test_decide_ship_skip_when_compare_ref_is_head(tmp_path: Path) -> None:
    repo = _init_surface_repo(tmp_path)
    head = _run_git(repo, "rev-parse", "HEAD")
    decision = decide_ship(repo, head)
    assert decision["ship"] == "skip"
    assert decision["reason"] == "compare-ref-is-head"


def test_surface_fingerprint_stable_until_bytes_change(tmp_path: Path) -> None:
    repo = _init_surface_repo(tmp_path)
    first = surface_fingerprint(repo)
    second = surface_fingerprint(repo)
    assert first == second
    assert len(first) == 64
    (repo / "shared" / "ciso_shape.py").write_text("changed\n", encoding="utf-8")
    assert surface_fingerprint(repo) != first


def test_farm_ship_surface_cli_writes_github_output(tmp_path: Path) -> None:
    repo = _init_surface_repo(tmp_path)
    base = _run_git(repo, "rev-parse", "HEAD")
    env_path = tmp_path / "gha.env"
    proc = subprocess.run(
        [
            "python3",
            str(SURFACE),
            "--root",
            str(repo),
            "--compare-ref",
            base,
            "--write-env",
            str(env_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    blob = proc.stdout or ""
    assert "FARM_SHIP=skip" in blob
    assert "paying_day=FAIL" in blob
    assert "not a ship event" in blob
    env = env_path.read_text(encoding="utf-8")
    assert "ship=skip" in env
    assert "reason=compare-ref-is-head" in env


def test_assert_farm_ship_sor_ok_and_fail_closed(tmp_path: Path) -> None:
    work = tmp_path / "work"
    _honest_farm_work(work)
    shape = assert_farm_ship_sor(work)
    assert shape["ok"] is True
    assert shape["paying_day"] == "FAIL"
    assert shape["findings"] >= 1
    assert shape["poam_rows"] >= 1
    assert shape["risk_scenarios"] >= shape["findings"]

    doc = json.loads((work / "prove-ciso.json").read_text(encoding="utf-8"))
    doc["paying_day"] = "PASS"
    (work / "prove-ciso.json").write_text(json.dumps(doc) + "\n", encoding="utf-8")
    with pytest.raises(FarmShipError, match="paying_day"):
        assert_farm_ship_sor(work)
    _honest_farm_work(work)
    (work / "out" / "poam" / "poam.csv").write_text(POAM_HEADER + "\n", encoding="utf-8")
    with pytest.raises(FarmShipError, match="POA"):
        assert_farm_ship_sor(work)
    _honest_farm_work(work)
    broken = json.loads((work / "out" / "summary.json").read_text(encoding="utf-8"))
    broken["flood_guard"]["findings_in"] = 99
    (work / "out" / "summary.json").write_text(json.dumps(broken) + "\n", encoding="utf-8")
    with pytest.raises(FarmShipError, match="flood_guard"):
        assert_farm_ship_sor(work)


def test_wipe_clone_script_fail_closed_on_partial_page(tmp_path: Path) -> None:
    repo = tmp_path / "partial"
    repo.mkdir()
    _run_git(repo, "init")
    _run_git(repo, "config", "user.email", "lab@example.com")
    _run_git(repo, "config", "user.name", "lab")
    (repo / "README.md").write_text("partial\n", encoding="utf-8")
    _run_git(repo, "add", "README.md")
    _run_git(repo, "commit", "-m", "partial")
    clone = tmp_path / "clone"
    work = tmp_path / "work"
    proc = subprocess.run(
        [
            "bash",
            str(WIPE),
            "--from",
            str(repo),
            "--clone",
            str(clone),
            "--work",
            str(work),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stderr or "") + (proc.stdout or "")
    assert "incomplete" in blob or "missing" in blob
    assert "full git checkout" in blob or "fail-closed" in blob


def test_wipe_clone_script_echoes_are_ascii_cp1252() -> None:
    assert FARM_SHIP_OK_LINE.isascii()
    FARM_SHIP_OK_LINE.encode("cp1252")
    text = WIPE.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("echo "):
            stripped.encode("cp1252")
            assert "\u2260" not in stripped
            assert "\u2192" not in stripped


def test_wipe_clone_then_farm_drop_emits_register_shape(tmp_path: Path) -> None:
    """True wipe/clone of a committed pack snapshot, then farm_drop→SoR."""
    dest = tmp_path / "pack"
    ignore = shutil.ignore_patterns(
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "*.pyc",
        "out",
    )
    shutil.copytree(ROOT, dest, ignore=ignore, symlinks=True)
    for rel in ("prove/work", "keep/work", "out"):
        shutil.rmtree(dest / rel, ignore_errors=True)
    _run_git(dest, "init")
    _run_git(dest, "config", "user.email", "lab@example.com")
    _run_git(dest, "config", "user.name", "lab")
    _run_git(dest, "add", "-A")
    _run_git(dest, "commit", "-m", "lab wipe clone")
    clone = tmp_path / "clone"
    work = tmp_path / "work"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(dest)
    env["DRY_RUN"] = "1"
    env["CISO_PUSH"] = "0"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [
            "bash",
            str(WIPE),
            "--from",
            str(dest),
            "--clone",
            str(clone),
            "--work",
            str(work),
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert "LAB=farm_wipe_clone" in blob
    assert "paying_day FAIL" in blob
    assert "Not client KEEP" in blob or "!= client" in blob
    assert FARM_SHIP_OK_LINE in blob
    assert (clone / ".farm-ship-head").is_file()
    assert (clone / "scripts" / "farm_drop_to_sor.sh").is_file()
    assert not (clone / "prove" / "work").exists()
    stamp = json.loads((work / "prove-ciso.json").read_text(encoding="utf-8"))
    assert stamp["sample"] is True
    assert stamp["client"] is False
    assert stamp["paying_day"] == "FAIL"
    assert stamp["posted"] is False
    shape = assert_farm_ship_sor(work)
    assert shape["findings"] >= 1
    assert shape["poam_rows"] >= 1
    assert shape["risk_scenarios"] >= shape["findings"]
    blob.encode("cp1252")
