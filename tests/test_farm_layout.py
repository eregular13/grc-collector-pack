"""Private farm layout: slots only, no vendored scanners, same scanner-free asserts."""

from __future__ import annotations

from pathlib import Path

from dropbox.scanner_free import (
    assert_image_files_scanner_free,
    image_files,
    is_demo_lab_stub,
    scan_text,
)
from dropbox.yaml_lite import load_yaml

ROOT = Path(__file__).resolve().parents[1]
FARM = ROOT / "farm"


def test_farm_quickstart_and_root_readme() -> None:
    qs = (FARM / "QUICKSTART.md").read_text(encoding="utf-8")
    assert len(qs.splitlines()) <= 40
    assert "DEMO" in qs
    assert "client estate" in qs.lower() or "≠ client" in qs
    assert "SCOPE" in qs
    assert "make farm-toolbin-e2e" in qs
    assert "--live" in qs
    assert "CISO" in qs or "ciso" in qs
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Private drop-box farm" in readme
    assert "farm/QUICKSTART.md" in readme
    assert "ARCHITECTURE.md" in readme
    assert "Layer" in readme
    assert "not a client estate" in readme.lower()


def test_farm_readme_is_private_not_hub() -> None:
    text = (FARM / "README.md").read_text(encoding="utf-8")
    assert "Not a public Docker Hub" in text or "not a public" in text.lower()
    assert "written SCOPE" in text or "written SCOPE" in text
    assert "Layer A" in text
    assert "parse-only" in text.lower()
    assert "Submodule hexstrike-ai" in text or "submodule hexstrike-ai" in text.lower()
    op = (FARM / "OPERATOR.md").read_text(encoding="utf-8")
    assert "FARM_TOOL_BIN" in op
    assert "never resolves LICENSE-LOCK" in op
    assert "written SCOPE" in op
    assert "quiet" in op.lower()
    assert "mcpServers" in op or "dropbox.mcp_stub" in op
    assert '"cwd"' in op
    assert "PYTHONPATH" in op
    assert ".cursor/mcp.json" in op
    integrity = (FARM / "INTEGRITY.md").read_text(encoding="utf-8")
    assert "## Brakes defaults" in integrity
    assert "`max_workers`" in integrity
    assert "2–5" in integrity or "2-5" in integrity
    assert "host_timeout_sec" in integrity
    assert "0.0.0.0/0" in integrity
    assert "review-only" in integrity.lower()
    from farm.adapters.catalog import brakes_defaults

    brakes = brakes_defaults()
    assert brakes["max_workers"] == "2"
    assert "2-5" in brakes["deepen_batch"] or "2–5" in brakes["deepen_batch"]
    assert "30" in brakes["host_timeout_sec"]
    assert "0.0.0.0/0" in brakes["wildcard_cidr"]
    assert "never probe" in brakes["external_ingest"]
    assert "file-drop inventory" in integrity.lower() or "File-drop inventory" in integrity


def test_farm_slots_are_adapters_not_binaries() -> None:
    data = load_yaml((FARM / "SLOTS.yaml").read_text(encoding="utf-8"))
    assert data.get("private") is True
    assert data.get("hub_publish") is False
    assert data.get("vendored_binaries") is False
    slots = data.get("slots") or {}
    assert isinstance(slots, dict)
    assert len(slots) >= 95
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
        if path.name in {".gitkeep", "README.md", "lab"}:
            continue
        assert not path.is_file() or path.stat().st_size == 0
    lab = tool_bin / "lab"
    assert lab.is_dir()
    for path in lab.iterdir():
        if path.name == "README.md":
            continue
        assert path.is_file()
        assert is_demo_lab_stub(path), path


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
            if is_demo_lab_stub(path):
                continue
            hits.append(path)
        if path.suffix.lower() in {".py", ".yml", ".yaml", ".md"}:
            text_hits = scan_text(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))
            hits.extend(text_hits)
    assert hits == []
