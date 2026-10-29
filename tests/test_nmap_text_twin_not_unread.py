"""nmap -oA .nmap text next to its .xml is not flagged unread; alone it is.

Synthetic (203.0.113.50).
"""
from __future__ import annotations

from pathlib import Path

from shared import io_util


def test_nmap_text_twin(tmp_path: Path, monkeypatch) -> None:
    inv = tmp_path / "in" / "nmap"
    inv.mkdir(parents=True)
    (inv / "svc.xml").write_text('<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>', encoding="utf-8")
    (inv / "svc.nmap").write_text("# Nmap 7.94 scan\n80/tcp open http\n", encoding="utf-8")
    (inv / "lone.nmap").write_text("# Nmap 7.94 scan\n22/tcp open ssh\n", encoding="utf-8")
    monkeypatch.setattr(io_util, "in_dir", lambda: tmp_path / "in")
    monkeypatch.setattr(io_util, "_sensor_folders", lambda source: ["nmap"])
    unread = sorted(p.name for p in io_util.unread_input_files("inventory-nmap", [".xml", ".gnmap"]))
    assert unread == ["lone.nmap"], unread
