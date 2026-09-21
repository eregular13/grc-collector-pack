"""LAB_SHAPE_ASSERT: lab dest_in cannot silently become DEMO-seeded.

When LAB.txt (or nmap pack_drop lab:true) is present, prove --use-existing-in
refuses seeded=true and unexpected DEMO adapter trees (honeypot / fixtures
pack_drop siblings beyond the operator nmap leaf). After a lab prove,
assert_risk_register_and_poam runs on out/. LAB != SAMPLE != client.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.prove_ciso import (
    LAB_SHAPE_FAIL,
    LabShapeError,
    assert_lab_dest_in_shape,
    dest_in_has_lab_stamp,
    prove_ciso,
    unexpected_demo_adapter_trees,
)
from shared.ciso_shape import assert_risk_register_and_poam
from tests.test_lab_prove_lock import (
    LAB_NET,
    MIN_LAB_FINDINGS,
    MIN_LAB_POAM,
    stage_lab_drop_dest_in,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lab_drop_to_sor.sh"
HONEYPOT_FIXTURE = ROOT / "fixtures" / "demo" / "honeypot"
RUSTSCAN_FIXTURE = ROOT / "fixtures" / "pack_drop" / "rustscan"


def _copy_tree(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for path in src.rglob("*"):
        if not path.is_file():
            continue
        target = dest / path.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def test_lab_stamp_detects_lab_txt_and_meta_lab(tmp_path: Path) -> None:
    assert dest_in_has_lab_stamp(ROOT / "fixtures" / "lab-drop") is True
    sample_nmap = ROOT / "fixtures" / "pack_drop" / "nmap"
    # SAMPLE nmap leaf has no LAB.txt and meta.lab is not true.
    empty = tmp_path / "missing"
    assert dest_in_has_lab_stamp(empty) is False
    staged = tmp_path / "sample-leaf"
    leaf = staged / "nmap" / "pack_drop"
    leaf.mkdir(parents=True)
    shutil.copy2(sample_nmap / "meta.json", leaf / "meta.json")
    assert dest_in_has_lab_stamp(staged) is False
    meta = json.loads((sample_nmap / "meta.json").read_text(encoding="utf-8"))
    assert meta.get("lab") is not True


def test_assert_lab_dest_in_shape_refuses_seeded_true(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    stage_lab_drop_dest_in(dest_in)
    assert dest_in_has_lab_stamp(dest_in) is True
    assert unexpected_demo_adapter_trees(dest_in) == []
    ok = assert_lab_dest_in_shape(dest_in, seeded=False)
    assert ok["ok"] is True
    assert ok["lab"] is True
    with pytest.raises(LabShapeError, match=LAB_SHAPE_FAIL):
        assert_lab_dest_in_shape(dest_in, seeded=True)
    with pytest.raises(LabShapeError, match="seeded=true"):
        assert_lab_dest_in_shape(dest_in, seeded=True)


def test_assert_lab_dest_in_shape_refuses_honeypot(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    stage_lab_drop_dest_in(dest_in)
    _copy_tree(HONEYPOT_FIXTURE, dest_in / "honeypot")
    assert "honeypot" in unexpected_demo_adapter_trees(dest_in)
    with pytest.raises(LabShapeError, match=LAB_SHAPE_FAIL):
        assert_lab_dest_in_shape(dest_in, seeded=False)
    with pytest.raises(LabShapeError, match="honeypot"):
        assert_lab_dest_in_shape(dest_in, seeded=False)


def test_assert_lab_dest_in_shape_refuses_pack_drop_siblings(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    stage_lab_drop_dest_in(dest_in)
    _copy_tree(RUSTSCAN_FIXTURE, dest_in / "nmap" / "pack_drop" / "rustscan")
    unexpected = unexpected_demo_adapter_trees(dest_in)
    assert "nmap/pack_drop/rustscan" in unexpected
    with pytest.raises(LabShapeError, match=LAB_SHAPE_FAIL):
        assert_lab_dest_in_shape(dest_in, seeded=False)
    with pytest.raises(LabShapeError, match="rustscan"):
        assert_lab_dest_in_shape(dest_in, seeded=False)


def test_lab_prove_asserts_risk_register_and_poam(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    dest_in = dest / "in"
    stage_lab_drop_dest_in(dest_in)
    stamp = prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["seeded"] is False
    assert stamp["lab"] is True
    assert stamp["sample"] is False
    assert stamp["client"] is False
    assert dest_in_has_lab_stamp(dest_in) is True
    assert unexpected_demo_adapter_trees(dest_in) == []
    shape = assert_risk_register_and_poam(Path(stamp["out_dir"]))
    assert shape["ok"] is True
    assert shape["findings"] >= MIN_LAB_FINDINGS
    assert shape["risk_scenarios"] >= 1
    assert shape["poam_rows"] >= MIN_LAB_POAM
    assert stamp["counts"]["findings"] == shape["findings"]
    assert stamp["counts"]["poam"] == shape["poam_rows"]
    assert stamp["counts"]["risk_scenarios"] == shape["risk_scenarios"]
    assets = (Path(stamp["out_dir"]) / "ciso-assistant" / "assets.csv").read_text(
        encoding="utf-8"
    )
    assert LAB_NET in assets
    assert "filesrv.corp.local" not in assets


def test_prove_use_existing_in_fail_closed_on_honeypot(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    dest_in = dest / "in"
    marker = stage_lab_drop_dest_in(dest_in)
    _copy_tree(HONEYPOT_FIXTURE, dest_in / "honeypot")
    before = {p.relative_to(dest_in) for p in dest_in.rglob("*") if p.is_file()}
    with pytest.raises(LabShapeError, match=LAB_SHAPE_FAIL):
        prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    after = {p.relative_to(dest_in) for p in dest_in.rglob("*") if p.is_file()}
    assert after == before
    assert marker.is_file()
    assert (dest_in / "LAB.txt").is_file()
    assert not (dest / "prove-ciso.json").exists()


def test_prove_use_existing_in_fail_closed_on_rustscan_sibling(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    dest_in = dest / "in"
    stage_lab_drop_dest_in(dest_in)
    _copy_tree(RUSTSCAN_FIXTURE, dest_in / "nmap" / "pack_drop" / "rustscan")
    with pytest.raises(LabShapeError, match=LAB_SHAPE_FAIL):
        prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    assert (dest_in / "LAB.txt").is_file()
    assert (dest_in / "nmap" / "pack_drop" / "rustscan" / "meta.json").is_file()
    assert not (dest / "prove-ciso.json").exists()


def test_lab_shape_fail_cli_and_wrapper_are_stable(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    dest_in = dest / "in"
    stage_lab_drop_dest_in(dest_in)
    _copy_tree(HONEYPOT_FIXTURE, dest_in / "honeypot")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["CISO_PUSH"] = "0"
    env["DRY_RUN"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "prove_ciso.py"),
            "--work",
            str(dest),
            "--use-existing-in",
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert LAB_SHAPE_FAIL in blob
    assert "honeypot" in blob
    blob.encode("cp1252")
    assert "\u2260" not in blob
    wrapper = subprocess.run(
        ["bash", str(SCRIPT), "--work", str(dest)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert wrapper.returncode != 0
    wrap_blob = (wrapper.stdout or "") + (wrapper.stderr or "")
    assert LAB_SHAPE_FAIL in wrap_blob
    wrap_blob.encode("cp1252")
    assert "\u2260" not in wrap_blob


def test_use_existing_in_without_lab_stamp_still_allows_tiny_nmap(
    tmp_path: Path,
) -> None:
    """#104 path: SAMPLE nmap leaf, no LAB.txt — not LAB_SHAPE_FAIL."""
    dest = tmp_path / "prove"
    dest_in = dest / "in"
    src = ROOT / "fixtures" / "pack_drop" / "nmap"
    leaf = dest_in / "nmap" / "pack_drop"
    leaf.mkdir(parents=True)
    for name in ("meta.json", "assets.jsonl", "findings.jsonl"):
        (leaf / name).write_text((src / name).read_text(encoding="utf-8"), encoding="utf-8")
    assert dest_in_has_lab_stamp(dest_in) is False
    stamp = prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["lab"] is True
    assert stamp["seeded"] is False
    shape = assert_risk_register_and_poam(Path(stamp["out_dir"]))
    assert shape["findings"] >= 1
    assert shape["poam_rows"] >= 1


def test_verify_only_fail_closed_if_honeypot_appears_after_lab_prove(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "prove"
    stage_lab_drop_dest_in(dest / "in")
    stamp = prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    assert stamp["status"] == "pass", stamp.get("reason")
    _copy_tree(HONEYPOT_FIXTURE, dest / "in" / "honeypot")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["CISO_PUSH"] = "0"
    env["DRY_RUN"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "prove_ciso.py"),
            "--work",
            str(dest),
            "--verify-only",
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert LAB_SHAPE_FAIL in blob
    assert "honeypot" in blob


def test_lab_shape_error_message_is_ascii_cp1252() -> None:
    assert LAB_SHAPE_FAIL.isascii()
    LAB_SHAPE_FAIL.encode("cp1252")
    dest_in = ROOT / "fixtures" / "lab-drop"
    try:
        assert_lab_dest_in_shape(dest_in, seeded=True)
    except LabShapeError as exc:
        text = str(exc)
        text.encode("cp1252")
        assert "\u2260" not in text
        assert "\u2192" not in text
        assert LAB_SHAPE_FAIL in text
    else:
        raise AssertionError("expected LabShapeError")
