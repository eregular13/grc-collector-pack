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
    op = (FARM / "OPERATOR.md").read_text(encoding="utf-8")
    assert "FARM_TOOL_BIN" in op
    assert "written SCOPE" in op
    assert "quiet" in op.lower()
    assert "mcpServers" in op or "dropbox.mcp_stub" in op


def test_farm_slots_are_adapters_not_binaries() -> None:
    data = load_yaml((FARM / "SLOTS.yaml").read_text(encoding="utf-8"))
    assert data.get("private") is True
    assert data.get("hub_publish") is False
    assert data.get("vendored_binaries") is False
    slots = data.get("slots") or {}
    assert isinstance(slots, dict)
    assert len(slots) >= 40
    for required in ("nmap", "nessus", "testssl", "curl", "lynis", "hardeningkitty-export", "prowler", "maester"):
        assert required in slots
        slot = slots[required]
        assert slot.get("vendored") is False
        assert slot.get("sensor")
        assert slot.get("stage")
        assert slot.get("license_class")
        assert slot.get("output_glob")
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
    assert "apt-get" not in docker.lower()
    assert "apt install" not in docker.lower()
    compose = (FARM / "docker-compose.yml").read_text(encoding="utf-8")
    assert "DROPBOX_LIVE: \"0\"" in compose
    assert "GRC_LIVE_SCAN: \"0\"" in compose
    assert "apt-get" not in compose.lower()
    assert "farm-discover" in compose and "farm-deepen" in compose and "farm-ingest" in compose
    assert "farm-internal" in compose
    assert "internal: true" in compose
    hits = scan_text(compose, "farm/docker-compose.yml")
    assert hits == []
    hits = scan_text(docker, "farm/Dockerfile")
    assert hits == []


def test_farm_tree_has_no_embedded_scanners() -> None:
    forbidden_ext = {".deb", ".rpm", ".exe", ".nbin", ".nasl"}
    hits = []
    for path in FARM.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in forbidden_ext:
            hits.append(path)
        if path.name.lower() in {"nmap", "nessus", "nuclei", "openvas"}:
            hits.append(path)
        if path.suffix.lower() in {".py", ".yml", ".yaml", ".md"}:
            text_hits = scan_text(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))
            hits.extend(text_hits)
    assert hits == []
