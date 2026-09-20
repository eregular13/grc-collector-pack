"""Brick 3: malformed/incomplete KEEP stress fixtures fail closed.

Not SAMPLE success theater. Not a client KEEP drop. Stable KEEP_FIXTURE_*
codes on inspect / keep-lab / sample_to_sor / MCP keep_status+keep_ciso.
No SoR CSVs written as if success. No silent skip-to-PASS.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from dropbox.keep_preflight import (
    KEEP_FAIL_CLAIM_MISMATCH,
    KEEP_FAIL_CORRUPT_ZIP,
    KEEP_FAIL_EMPTY,
    KEEP_FAIL_GARBAGE_BINARY,
    KEEP_FAIL_MISSING_LEAF,
    KEEP_FAIL_TRUNCATED_JSON,
    KEEP_FAIL_WRONG_SCHEMA,
    KEEP_PACKAGE_SCHEMA,
    KeepFixtureError,
    KeepFixtureIncomplete,
    KeepFixtureMalformed,
    abort_keep_samples,
    inspect_keep_fixture_tree,
    require_keep_samples,
)
from dropbox.mcp_stub import dispatch
from keep.adapters import scan_keep_dir
from keep.lab import keep_lab, main as keep_lab_main

ROOT = Path(__file__).resolve().parents[1]
STRESS = ROOT / "fixtures" / "keep-stress"
SAMPLES = ROOT / "fixtures" / "keep-samples"
SCOPE = ROOT / "dropbox" / "SCOPE.yaml"
CATALOG = json.loads((STRESS / "CATALOG.json").read_text(encoding="utf-8"))
SHAPES = list(CATALOG["shapes"])
SHAPE_IDS = [row["id"] for row in SHAPES]
CODES = {row["id"]: row["code"] for row in SHAPES}

EXPECTED_CODES = {
    "truncated-json": KEEP_FAIL_TRUNCATED_JSON,
    "garbage-binary": KEEP_FAIL_GARBAGE_BINARY,
    "wrong-schema": KEEP_FAIL_WRONG_SCHEMA,
    "missing-leaf": KEEP_FAIL_MISSING_LEAF,
    "empty-required": KEEP_FAIL_EMPTY,
    "claim-mismatch": KEEP_FAIL_CLAIM_MISMATCH,
    "corrupt-zip": KEEP_FAIL_CORRUPT_ZIP,
}


def _shape_dir(shape_id: str) -> Path:
    return STRESS / shape_id


def _plant_leftover_sor(work: Path) -> Path:
    """Leftover success-looking SoR that fail-closed must not inherit."""
    findings = work / "out" / "ciso-assistant" / "findings.csv"
    findings.parent.mkdir(parents=True, exist_ok=True)
    findings.write_text("ref_id,name,severity\nSTALE,should-not-survive,high\n", encoding="utf-8")
    (work / "out" / "ciso-assistant" / "IMPORT.json").write_text(
        json.dumps({"demo": True, "sample": True, "paying_day": "PASS"}) + "\n",
        encoding="utf-8",
    )
    return findings


def _no_success_sor(work: Path) -> None:
    findings = work / "out" / "ciso-assistant" / "findings.csv"
    assert not findings.is_file(), findings
    import_doc = work / "out" / "ciso-assistant" / "IMPORT.json"
    assert not import_doc.is_file(), import_doc
    poam = work / "out" / "poam" / "poam.csv"
    assert not poam.is_file(), poam


@pytest.mark.parametrize("shape", SHAPES, ids=SHAPE_IDS)
def test_catalog_codes_match_constants(shape: dict) -> None:
    assert shape["id"] in EXPECTED_CODES
    assert shape["code"] == EXPECTED_CODES[shape["id"]]
    assert (STRESS / shape["id"]).is_dir()


def test_stress_readme_and_catalog_are_honest() -> None:
    readme = (STRESS / "README.md").read_text(encoding="utf-8")
    assert "not" in readme.lower()
    assert "client KEEP" in readme
    assert "Brick 3" in readme
    assert CATALOG["schema"] == "keep.stress.v1"
    assert "Not SAMPLE success" in CATALOG["note"] or "not" in CATALOG["note"].lower()
    assert len(SHAPES) >= 3
    assert KEEP_PACKAGE_SCHEMA == "keep.package.v1"


@pytest.mark.parametrize("shape", SHAPES, ids=SHAPE_IDS)
def test_inspect_fail_closed_with_stable_code(shape: dict) -> None:
    tree = _shape_dir(shape["id"])
    report = inspect_keep_fixture_tree(tree, root=ROOT)
    assert report["ok"] is False
    assert report["code"] == shape["code"]
    message = str(report["message"])
    assert shape["code"] in message
    for token in shape.get("substr") or []:
        assert token in message
    assert "PASS" not in message
    with pytest.raises(KeepFixtureError) as excinfo:
        require_keep_samples(ROOT, samples_dir=tree)
    assert excinfo.value.code == shape["code"]
    assert shape["code"] in str(excinfo.value)
    if shape["code"] in {KEEP_FAIL_MISSING_LEAF, KEEP_FAIL_EMPTY}:
        assert isinstance(excinfo.value, KeepFixtureIncomplete)
    else:
        assert isinstance(excinfo.value, KeepFixtureMalformed)


@pytest.mark.parametrize("shape", SHAPES, ids=SHAPE_IDS)
def test_abort_keep_samples_nonzero_on_stress(shape: dict) -> None:
    with pytest.raises(SystemExit) as abort_exc:
        abort_keep_samples(ROOT, samples_dir=_shape_dir(shape["id"]))
    assert abort_exc.value.code == 1


def test_real_keep_samples_still_pass_inspect() -> None:
    report = inspect_keep_fixture_tree(SAMPLES, root=ROOT)
    assert report["ok"] is True
    assert report["code"] == ""
    assert report["missing"] == []
    assert require_keep_samples(ROOT) == ROOT


@pytest.mark.parametrize("shape", SHAPES, ids=SHAPE_IDS)
def test_keep_lab_fail_closed_no_sor_csv(
    shape: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _shape_dir(shape["id"])
    work = tmp_path / "work"
    leftover = _plant_leftover_sor(work)

    def _require(root, samples_dir=None):
        return require_keep_samples(root, samples_dir=tree)

    def _sources(root, pack_in):
        return scan_keep_dir(tree), False, "keep-samples"

    monkeypatch.setattr("keep.lab.require_keep_samples", _require)
    monkeypatch.setattr("keep.lab._choose_sources", _sources)
    empty = tmp_path / "empty-in"
    empty.mkdir()
    stamp = keep_lab(ROOT, pack_in=empty, work=work)
    assert stamp["status"] == "fail"
    assert stamp.get("fail_code") == shape["code"]
    reason = str(stamp.get("reason") or "")
    assert shape["code"] in reason
    assert leftover.exists() is False or leftover.read_text(encoding="utf-8").find("STALE") < 0
    _no_success_sor(work)
    lab_stamp = json.loads((work / "keep-lab.json").read_text(encoding="utf-8"))
    assert lab_stamp["status"] == "fail"
    assert lab_stamp.get("fail_code") == shape["code"]


@pytest.mark.parametrize(
    "shape_id",
    ["truncated-json", "garbage-binary", "wrong-schema", "claim-mismatch"],
)
def test_keep_lab_cli_nonzero_on_malformed(
    shape_id: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _shape_dir(shape_id)
    work = tmp_path / "cli-work"
    empty = tmp_path / "empty-in"
    empty.mkdir()

    def _require(root, samples_dir=None):
        return require_keep_samples(root, samples_dir=tree)

    monkeypatch.setattr("keep.lab.require_keep_samples", _require)
    monkeypatch.setattr(
        "keep.lab._choose_sources",
        lambda root, pack_in: (scan_keep_dir(tree), False, "keep-samples"),
    )
    code = keep_lab_main(["--pack-in", str(empty), "--work", str(work)])
    assert code == 1
    _no_success_sor(work)


@pytest.mark.parametrize(
    "shape_id",
    ["truncated-json", "garbage-binary", "wrong-schema"],
)
def test_keep_status_and_keep_ciso_no_false_pass(
    shape_id: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _shape_dir(shape_id)
    expected = CODES[shape_id]
    work = tmp_path / "mcp-work"
    leftover = _plant_leftover_sor(work)
    pack_in = tmp_path / "in"
    pack_in.mkdir()

    def _require(root, samples_dir=None):
        return require_keep_samples(root, samples_dir=tree)

    monkeypatch.setattr("dropbox.mcp_stub.require_keep_samples", _require)
    monkeypatch.setattr("keep.lab.require_keep_samples", _require)
    monkeypatch.setattr(
        "keep.lab._choose_sources",
        lambda root, pack_in: (scan_keep_dir(tree), False, "keep-samples"),
    )
    status = dispatch(
        "keep_status",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in)},
    )
    assert status["ok"] is False
    assert status.get("fail_code") == expected
    assert expected in str(status.get("stderr") or status.get("error") or "")
    assert status.get("paying_day") == "FAIL"
    ciso = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work), "isolate_work": False},
    )
    assert ciso["ok"] is False
    blob = str(ciso.get("stderr") or ciso.get("error") or "")
    assert expected in blob or ciso.get("fail_code") == expected
    assert leftover.exists() is False or "STALE" not in leftover.read_text(encoding="utf-8")
    _no_success_sor(work)


def test_python_m_keep_lab_uses_preflight_codes() -> None:
    """CLI still fail-closes through keep.lab.main (no new entrypoint)."""
    lab = (ROOT / "keep" / "lab.py").read_text(encoding="utf-8")
    assert "fail_code" in lab
    assert "KeepFixtureError" in lab
    stub = (ROOT / "dropbox" / "mcp_stub.py").read_text(encoding="utf-8")
    assert "require_keep_samples" in stub
    assert "fail_code" in stub
    pre = (ROOT / "dropbox" / "keep_preflight.py").read_text(encoding="utf-8")
    assert "inspect_keep_fixture_tree" in pre
    assert "KEEP_FIXTURE_TRUNCATED_JSON" in pre


def test_sample_to_sor_script_still_names_keep_package() -> None:
    """No new operator entrypoint; cold script still fail-closes via keep lab."""
    sh = (ROOT / "scripts" / "sample_to_sor.sh").read_text(encoding="utf-8")
    assert "python -m keep lab" in sh or "-m keep lab" in sh
    assert "require_keep_package" in sh


def test_keep_lab_subprocess_fail_closed_truncated(tmp_path: Path) -> None:
    """Subprocess python -m keep lab against a monkeypatched samples overlay.

    Uses a tiny helper module on PYTHONPATH so we do not add a public CLI flag.
    """
    tree = _shape_dir("truncated-json")
    work = tmp_path / "sub-work"
    empty = tmp_path / "empty-in"
    empty.mkdir()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DRY_RUN"] = "1"
    env["CISO_PUSH"] = "0"
    env["RISKREADY_PUSH"] = "0"
    env["GRC_LIVE_SCAN"] = "0"
    env["DROPBOX_LIVE"] = "0"
    # Drive the same keep_lab function the CLI uses, with samples_dir overlay,
    # through a one-shot -c so we do not invent an operator flag.
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from pathlib import Path;"
                "from dropbox.keep_preflight import require_keep_samples;"
                "from keep.lab import keep_lab;"
                f"tree=Path({str(tree)!r});"
                "import keep.lab as lab;"
                "lab.require_keep_samples=lambda root, samples_dir=None: "
                "require_keep_samples(root, samples_dir=tree);"
                f"stamp=keep_lab(Path({str(ROOT)!r}), pack_in=Path({str(empty)!r}), "
                f"work=Path({str(work)!r}));"
                "print(stamp.get('fail_code') or '');"
                "raise SystemExit(0 if stamp.get('status')=='pass' else 1)"
            ),
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert KEEP_FAIL_TRUNCATED_JSON in blob
    _no_success_sor(work)
