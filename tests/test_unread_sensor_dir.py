"""ITERATION-1 #1: non-empty sensor dirs without collectors fail closed."""
from __future__ import annotations

from pathlib import Path

import pytest

from dropbox.orchestrator.ciso_path import (
    UNREAD_SENSOR_DIR,
    UnreadSensorDirError,
    assert_no_unread_sensor_dirs,
    run_ciso_path,
    unread_sensor_dirs,
)
from dropbox.scope import ROOT

SCOPE = ROOT / "dropbox" / "SCOPE.yaml"


def test_empty_k8s_dir_is_silent(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    (dest_in / "k8s").mkdir(parents=True)
    (dest_in / "k8s" / ".gitkeep").write_text("", encoding="utf-8")
    assert unread_sensor_dirs(dest_in) == []
    assert_no_unread_sensor_dirs(dest_in)


def test_absent_code_dir_is_silent(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    dest_in.mkdir()
    assert unread_sensor_dirs(dest_in) == []


def test_nonempty_k8s_without_collector_fails_closed(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    k8s = dest_in / "k8s"
    k8s.mkdir(parents=True)
    (k8s / "dummy.json").write_text('{"note":"synthetic"}\n', encoding="utf-8")
    bad = unread_sensor_dirs(dest_in)
    assert bad == ["k8s"]
    with pytest.raises(UnreadSensorDirError) as ei:
        assert_no_unread_sensor_dirs(dest_in)
    msg = str(ei.value)
    assert UNREAD_SENSOR_DIR in msg
    assert "k8s" in msg


def test_run_ciso_path_unread_k8s_raises(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    dest_out = tmp_path / "out"
    (dest_in / "k8s").mkdir(parents=True)
    (dest_in / "k8s" / "dummy.txt").write_text("x\n", encoding="utf-8")
    nmap = dest_in / "nmap"
    nmap.mkdir(parents=True)
    with pytest.raises(UnreadSensorDirError) as ei:
        run_ciso_path(dest_in, dest_out, scope_path=SCOPE, write_pack_in=False)
    assert "k8s" in str(ei.value)
    assert UNREAD_SENSOR_DIR in str(ei.value)


def test_known_sensor_nmap_not_unread(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    (dest_in / "nmap").mkdir(parents=True)
    (dest_in / "nmap" / "note.txt").write_text("not really nmap\n", encoding="utf-8")
    assert "nmap" not in unread_sensor_dirs(dest_in)


def test_prior_out_assets_dir_not_unread(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    (dest_in / "assets").mkdir(parents=True)
    (dest_in / "assets" / "asset-ledger.json").write_text("{}", encoding="utf-8")
    (dest_in / "poam").mkdir(parents=True)
    (dest_in / "poam" / "poam-ledger.json").write_text("{}", encoding="utf-8")
    assert unread_sensor_dirs(dest_in) == []
