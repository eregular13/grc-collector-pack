"""Dockerfile + dropbox compose stay scanner-free. Runtime skip is honest."""

from __future__ import annotations

from pathlib import Path

import pytest

from dropbox.scanner_free import (
    assert_dropbox_compose_is_demo_dry,
    assert_image_files_scanner_free,
    docker_available,
    scan_text,
)
from dropbox.scope import NEVER_EMBED

ROOT = Path(__file__).resolve().parents[1]


def test_apt_install_nmap_is_caught() -> None:
    hits = scan_text("RUN apt-get install -y nmap curl\n", "Dockerfile")
    assert hits and any("nmap" in h for h in hits)
    hits = scan_text("RUN pip install python-nmap\n", "Dockerfile")
    assert hits
    hits = scan_text("RUN wget https://example.invalid/nessus.deb\n", "Dockerfile")
    assert hits
    hits = scan_text("FROM kalilinux/kali-rolling\n", "Dockerfile")
    assert hits
    clean = scan_text(
        "FROM python:3.12-slim\nCMD [\"python\", \"collectors/inventory_nmap.py\"]\n",
        "Dockerfile",
    )
    assert clean == []


def test_dockerfile_and_compose_are_scanner_free() -> None:
    assert_image_files_scanner_free()
    assert_dropbox_compose_is_demo_dry()
    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.12-slim" in docker
    assert "GRC_LIVE_SCAN=0" in docker
    assert "RISKREADY_PUSH=0" in docker
    assert not any(line.strip().upper().startswith("RUN ") for line in docker.splitlines())


def test_never_embed_names_are_not_installed_in_image_files() -> None:
    blob = ""
    for rel in ("Dockerfile", "docker-compose.yml", "docker-compose.dropbox.yml"):
        blob += "\n" + (ROOT / rel).read_text(encoding="utf-8").lower()
    for tool in sorted(NEVER_EMBED | {"masscan", "naabu"}):
        if tool in {"riskready"}:
            continue
        assert f"apt-get install {tool}" not in blob
        assert f"apt-get install -y {tool}" not in blob
        assert f"apt install {tool}" not in blob
        assert f"apk add {tool}" not in blob
        assert f"pip install {tool}" not in blob


def test_dropbox_compose_runtime_skips_honestly_without_docker() -> None:
    ok, reason = docker_available()
    if ok:
        pytest.skip("docker is present — runtime path covered by scripts/dropbox_compose_lab.py")
    assert "docker" in reason.lower() or "daemon" in reason.lower() or "PATH" in reason
    # Honest skip: this is not a compose pass.
    pytest.skip(f"compose_lab absent: {reason}")
