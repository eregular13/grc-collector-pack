"""Private farm layout: slots only, no vendored scanners, same scanner-free asserts."""

from __future__ import annotations

from pathlib import Path

from dropbox.scanner_free import assert_image_files_scanner_free, image_files, scan_text
from dropbox.yaml_lite import load_yaml

ROOT = Path(__file__).resolve().parents[1]
FARM = ROOT / "farm"


def test_farm_readme_is_private_not_hub() -> None:
    text = (FARM / "README.md").read_text(encoding="utf-8")
    assert "Not a public Docker Hub" in text or "not a public" in text.lower()
    assert "written SCOPE" in text or "written SCOPE" in text
    assert "Layer A" in text
    assert "parse-only" in text.lower()
    assert "Submodule hexstrike-ai" in text or "submodule hexstrike-ai" in text.lower()


def test_farm_slots_are_adapters_not_binaries() -> None:
    data = load_yaml((FARM / "SLOTS.yaml").read_text(encoding="utf-8"))
    assert data.get("private") is True
    assert data.get("hub_publish") is False
    assert data.get("vendored_binaries") is False
    slots = data.get("slots") or {}
    assert isinstance(slots, dict)
    for required in ("nmap", "nessus", "testssl", "curl", "lynis", "hardeningkitty-export", "prowler", "maester"):
        assert required in slots
        slot = slots[required]
        assert slot.get("vendored") is False
        assert slot.get("sensor")
        assert slot.get("stage")
    # No binary files under farm/tool-bin
    tool_bin = FARM / "tool-bin"
    for path in tool_bin.iterdir():
        if path.name in {".gitkeep", "README.md"}:
            continue
        assert not path.is_file() or path.stat().st_size == 0


def test_farm_image_files_are_scanner_free() -> None:
    files = image_files()
    assert FARM / "Dockerfile" in files
    assert FARM / "docker-compose.yml" in files
    assert_image_files_scanner_free()
    docker = (FARM / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.12-slim" in docker
    assert not any(line.strip().upper().startswith("RUN ") for line in docker.splitlines())
    assert "apt" not in docker.lower()
    compose = (FARM / "docker-compose.yml").read_text(encoding="utf-8")
    assert "DROPBOX_LIVE: \"0\"" in compose
    assert "GRC_LIVE_SCAN: \"0\"" in compose
    assert "apt-get" not in compose.lower()
    assert "farm-discover" in compose and "farm-deepen" in compose
    hits = scan_text(compose, "farm/docker-compose.yml")
    assert hits == []
    hits = scan_text(docker, "farm/Dockerfile")
    assert hits == []


def test_farm_does_not_vendor_scanner_binaries() -> None:
    forbidden_ext = {".deb", ".rpm", ".exe", ".nbin", ".nasl"}
    hits = []
    for path in FARM.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in forbidden_ext:
            hits.append(path)
        if path.name.lower() in {"nmap", "nessus", "nuclei", "openvas"}:
            hits.append(path)
    assert hits == []
