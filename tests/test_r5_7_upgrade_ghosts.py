"""R5-7: upgrading a 1f8d347 out/ must drop pack-owned ghosts, keep operator files.

The pack wrote exactly four files under out/riskready/. Cleanup unlinks those
regular files (lstat, no symlink follow), rmdirs the dir only when empty, and
never touches a user file, a top-level risks_proposed.json, a regular file
named riskready, or a symlink. Cleanup errors do not abort load().
SAMPLE/DEMO != client KEEP. No POST /api/risks.
"""

from __future__ import annotations

import importlib
import json
import logging
from pathlib import Path

import pytest

from shared.ciso_shape import POAM_HEADER
from shared.pack_outputs import (
    RETIRED_PACK_OWNED_DIRS,
    RETIRED_PACK_OWNED_FILES,
    clean_retired_pack_outputs,
    is_retired_pack_owned,
    looks_like_pack_json,
    pack_shaped_bytes,
)

_PACK_JSON = ("assets.json", "incidents.json", "evidence.json", "risks_proposed.json")


def _finding(ref: str = "f1") -> dict:
    return {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": ref,
        "name": f"FTP exposed {ref}",
        "description": f"{ref} has open TCP/21 (ftp).",
        "severity": "high",
        "category": "exposure",
        "assets": ["host-a"],
        "labels": ["nmap"],
        "extra": {"port": "21", "service": "ftp", "ip": "10.0.0.5", "check_id": f"test-{ref}"},
    }


def _asset() -> dict:
    return {
        "kind": "asset",
        "source": "inventory-nmap",
        "ref_id": "asset-host-a",
        "name": "host-a",
        "description": "Host host-a",
        "severity": "info",
        "category": "host",
        "assets": ["host-a"],
        "labels": ["nmap"],
        "extra": {"asset_type": "PR", "ip": "10.0.0.5"},
    }


def _plant_1f8d347_layout(out: Path) -> None:
    """True 1f8d347 sink: the four riskready JSON files. Plus operator files."""
    rr = out / "riskready"
    rr.mkdir(parents=True)
    for name in _PACK_JSON:
        (rr / name).write_bytes(pack_shaped_bytes(name))
    # Pack never wrote a top-level risks_proposed.json — this is a user file.
    (out / "risks_proposed.json").write_text("[]\n", encoding="utf-8")
    (out / "canonical").mkdir(parents=True)
    (out / "poam").mkdir(parents=True)
    (out / "ciso-assistant").mkdir(parents=True)
    (out / "operator-notes.txt").write_text("keep me\n", encoding="utf-8")
    (out / "MANIFEST").write_text(
        "0" * 64 + "  poam/poam.csv\n"
        + "0" * 64 + "  ciso-assistant/assets.csv\n"
        + "0" * 64 + "  riskready/risks_proposed.json\n",
        encoding="utf-8",
    )


def _run_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, records: list[dict]) -> Path:
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    (out / "canonical").mkdir(parents=True, exist_ok=True)
    with (out / "canonical" / "inventory-nmap.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    return out


def test_retired_paths_are_pack_owned_only() -> None:
    assert is_retired_pack_owned("riskready")
    assert is_retired_pack_owned("./riskready")
    assert is_retired_pack_owned("riskready/assets.json")
    assert is_retired_pack_owned("riskready/incidents.json")
    assert is_retired_pack_owned("riskready/evidence.json")
    assert is_retired_pack_owned("riskready/risks_proposed.json")
    assert is_retired_pack_owned("./riskready/assets.json")
    assert not is_retired_pack_owned("risks_proposed.json")
    assert not is_retired_pack_owned(".riskready")
    assert not is_retired_pack_owned("./.riskready")
    assert not is_retired_pack_owned("operator-notes.txt")
    assert not is_retired_pack_owned("canonical/inventory-nmap.jsonl")
    assert not is_retired_pack_owned("poam/poam.csv")
    assert "riskready" in RETIRED_PACK_OWNED_DIRS
    assert "riskready/assets.json" in RETIRED_PACK_OWNED_FILES
    assert "risks_proposed.json" not in RETIRED_PACK_OWNED_FILES


def test_clean_drops_four_pack_files_and_empty_dir(tmp_path: Path) -> None:
    out = tmp_path / "out"
    _plant_1f8d347_layout(out)
    removed = clean_retired_pack_outputs(out)
    assert set(removed) >= {
        "riskready/assets.json",
        "riskready/incidents.json",
        "riskready/evidence.json",
        "riskready/risks_proposed.json",
        "riskready",
    }
    assert not (out / "riskready").exists()
    assert (out / "risks_proposed.json").read_text(encoding="utf-8") == "[]\n"
    assert (out / "operator-notes.txt").read_text(encoding="utf-8") == "keep me\n"
    assert (out / "MANIFEST").is_file()


def test_user_file_in_riskready_survives_and_dir_stays(tmp_path: Path) -> None:
    out = tmp_path / "out"
    rr = out / "riskready"
    rr.mkdir(parents=True)
    (rr / "assets.json").write_text("pack\n", encoding="utf-8")
    (rr / "notes.txt").write_text("user\n", encoding="utf-8")
    clean_retired_pack_outputs(out)
    assert (rr / "notes.txt").read_text(encoding="utf-8") == "user\n"
    assert rr.is_dir()
    # Known name but not pack JSON — keep it.
    assert (rr / "assets.json").read_text(encoding="utf-8") == "pack\n"


def test_user_toplevel_risks_proposed_survives(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    planted = out / "risks_proposed.json"
    planted.write_text("operator-json\n", encoding="utf-8")
    clean_retired_pack_outputs(out)
    assert planted.read_text(encoding="utf-8") == "operator-json\n"


def test_regular_file_named_riskready_survives(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    planted = out / "riskready"
    planted.write_text("not-a-dir\n", encoding="utf-8")
    clean_retired_pack_outputs(out)
    assert planted.is_file()
    assert planted.read_text(encoding="utf-8") == "not-a-dir\n"


def test_symlinked_riskready_dir_inside_out_is_skipped(tmp_path: Path) -> None:
    """Removing the symlink check fails: resolve() stays under out/."""
    out = tmp_path / "out"
    inner = out / "stash"
    inner.mkdir(parents=True)
    (inner / "assets.json").write_bytes(pack_shaped_bytes("assets.json"))
    (inner / "notes.txt").write_text("keep-inner\n", encoding="utf-8")
    (out / "riskready").symlink_to(inner)
    clean_retired_pack_outputs(out)
    assert (inner / "assets.json").read_bytes() == pack_shaped_bytes("assets.json")
    assert (inner / "notes.txt").read_text(encoding="utf-8") == "keep-inner\n"
    assert (out / "riskready").is_symlink()


def test_known_name_without_pack_json_is_kept(tmp_path: Path) -> None:
    out = tmp_path / "out"
    rr = out / "riskready"
    rr.mkdir(parents=True)
    (rr / "assets.json").write_text('[{"foo": 1}]\n', encoding="utf-8")
    clean_retired_pack_outputs(out)
    assert (rr / "assets.json").read_text(encoding="utf-8") == '[{"foo": 1}]\n'
    assert rr.is_dir()
    assert looks_like_pack_json("assets.json", pack_shaped_bytes("assets.json"))
    assert not looks_like_pack_json("assets.json", b'{"name": "x"}\n')


def test_symlinked_riskready_dir_is_skipped(tmp_path: Path) -> None:
    """Containment: do not follow out/riskready → a user project."""
    victim = tmp_path / "project" / "riskready"
    victim.mkdir(parents=True)
    (victim / "assets.json").write_text("user-assets\n", encoding="utf-8")
    (victim / "src.py").write_text("print(1)\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "riskready").symlink_to(victim)
    clean_retired_pack_outputs(out)
    assert (victim / "assets.json").read_text(encoding="utf-8") == "user-assets\n"
    assert (victim / "src.py").read_text(encoding="utf-8") == "print(1)\n"
    assert (out / "riskready").is_symlink()


def test_symlinked_target_file_is_skipped(tmp_path: Path) -> None:
    """Regular-file check: lstat of a symlink is not S_ISREG; target stays."""
    out = tmp_path / "out"
    rr = out / "riskready"
    rr.mkdir(parents=True)
    victim = tmp_path / "outside.json"
    victim.write_text("keep-outside\n", encoding="utf-8")
    (rr / "assets.json").symlink_to(victim)
    (rr / "incidents.json").write_bytes(pack_shaped_bytes("incidents.json"))
    clean_retired_pack_outputs(out)
    assert victim.read_text(encoding="utf-8") == "keep-outside\n"
    assert (rr / "assets.json").is_symlink()
    assert not (rr / "incidents.json").exists()
    assert rr.is_dir()


def test_empty_dir_rmdir_works(tmp_path: Path) -> None:
    out = tmp_path / "out"
    rr = out / "riskready"
    rr.mkdir(parents=True)
    for name in _PACK_JSON:
        (rr / name).write_bytes(pack_shaped_bytes(name))
    removed = clean_retired_pack_outputs(out)
    assert "riskready" in removed
    assert not rr.exists()


def test_hidden_dot_riskready_is_not_cleaned(tmp_path: Path) -> None:
    out = tmp_path / "out"
    hidden = out / ".riskready"
    hidden.mkdir(parents=True)
    (hidden / "assets.json").write_text("hidden\n", encoding="utf-8")
    clean_retired_pack_outputs(out)
    assert (hidden / "assets.json").read_text(encoding="utf-8") == "hidden\n"


def test_loader_upgrade_from_1f8d347_drops_ghosts_keeps_operator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _plant_1f8d347_layout(out)
    assert (out / "riskready" / "risks_proposed.json").is_file()
    loaded = _run_loader(tmp_path, monkeypatch, [_asset(), _finding()])
    assert loaded == out
    leftover = [p for p in out.rglob("*") if "riskready" in p.as_posix().lower()]
    assert leftover == []
    assert (out / "risks_proposed.json").read_text(encoding="utf-8") == "[]\n"
    assert (out / "operator-notes.txt").read_text(encoding="utf-8") == "keep me\n"
    assert (out / "poam" / "poam.csv").is_file()
    assert (out / "poam" / "excluded.csv").is_file()
    header = (out / "poam" / "poam.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header.strip() == POAM_HEADER or header.startswith("weakness,")
    manifest = (out / "MANIFEST").read_text(encoding="utf-8")
    assert "riskready" not in manifest
    assert "excluded.csv" in manifest
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert "risks_proposed" not in summary


def test_loader_user_file_in_riskready_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    rr = out / "riskready"
    rr.mkdir(parents=True)
    (rr / "assets.json").write_bytes(pack_shaped_bytes("assets.json"))
    (rr / "operator-notes.txt").write_text("keep-inside\n", encoding="utf-8")
    loaded = _run_loader(tmp_path, monkeypatch, [_asset(), _finding()])
    assert (loaded / "riskready" / "operator-notes.txt").read_text(encoding="utf-8") == "keep-inside\n"
    assert (loaded / "riskready").is_dir()
    assert not (loaded / "riskready" / "assets.json").exists()
    assert (loaded / "poam" / "poam.csv").is_file()


def test_loader_readonly_riskready_does_not_abort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    out = tmp_path / "out"
    rr = out / "riskready"
    rr.mkdir(parents=True)
    pack = rr / "assets.json"
    pack.write_bytes(pack_shaped_bytes("assets.json"))
    pack.chmod(0o444)
    rr.chmod(0o555)
    caplog.set_level(logging.WARNING)
    try:
        loaded = _run_loader(tmp_path, monkeypatch, [_asset(), _finding()])
        assert (loaded / "poam" / "poam.csv").is_file()
        assert (loaded / "summary.json").is_file()
        assert (loaded / "ciso-assistant" / "findings.csv").is_file()
    finally:
        rr.chmod(0o755)
        pack.chmod(0o644)


def test_cleanup_runs_at_start_and_end_of_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kills a mutant that drops the start call or the end call."""
    calls: list[str] = []

    import shared.pack_outputs as pack_outputs

    real = pack_outputs.clean_retired_pack_outputs

    def spy(out):
        calls.append(str(out))
        return real(out)

    monkeypatch.setattr(pack_outputs, "clean_retired_pack_outputs", spy)
    import collectors.grc_loader as loader

    monkeypatch.setattr(loader, "clean_retired_pack_outputs", spy)
    _run_loader(tmp_path, monkeypatch, [_asset(), _finding()])
    assert len(calls) == 2


def test_start_cleanup_alone_drops_pack_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the end call is a no-op, start still unlinks the four files."""
    import collectors.grc_loader as loader
    import shared.pack_outputs as pack_outputs

    real = pack_outputs.clean_retired_pack_outputs
    state = {"n": 0}

    def once(out):
        state["n"] += 1
        if state["n"] == 1:
            return real(out)
        return []

    monkeypatch.setattr(pack_outputs, "clean_retired_pack_outputs", once)
    importlib.reload(loader)
    monkeypatch.setattr(loader, "clean_retired_pack_outputs", once)
    out = tmp_path / "out"
    _plant_1f8d347_layout(out)
    _run_loader(tmp_path, monkeypatch, [_asset(), _finding()])
    assert not (out / "riskready").exists()
    assert (out / "operator-notes.txt").is_file()


def test_end_cleanup_alone_drops_pack_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the start call is a no-op, end still unlinks the four files."""
    import collectors.grc_loader as loader
    import shared.pack_outputs as pack_outputs

    real = pack_outputs.clean_retired_pack_outputs
    state = {"n": 0}

    def second_only(out):
        state["n"] += 1
        if state["n"] == 1:
            return []
        return real(out)

    monkeypatch.setattr(pack_outputs, "clean_retired_pack_outputs", second_only)
    importlib.reload(loader)
    monkeypatch.setattr(loader, "clean_retired_pack_outputs", second_only)
    out = tmp_path / "out"
    _plant_1f8d347_layout(out)
    _run_loader(tmp_path, monkeypatch, [_asset(), _finding()])
    assert not (out / "riskready").exists()
    assert (out / "poam" / "poam.csv").is_file()


def test_loader_does_not_delete_unrelated_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _plant_1f8d347_layout(out)
    other = tmp_path / "client-drop" / "keep.bin"
    other.parent.mkdir(parents=True)
    other.write_bytes(b"operator")
    _run_loader(tmp_path, monkeypatch, [_asset(), _finding()])
    assert other.read_bytes() == b"operator"
    assert (out / "operator-notes.txt").is_file()
    assert (out / "risks_proposed.json").is_file()
