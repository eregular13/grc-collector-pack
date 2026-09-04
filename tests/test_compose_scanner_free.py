"""Dockerfile + dropbox compose stay scanner-free. Runtime skip is honest."""

from __future__ import annotations

from pathlib import Path

import pytest

from dropbox.scanner_free import (
    assert_dropbox_compose_is_demo_dry,
    assert_farm_compose_is_skeleton,
    assert_image_files_scanner_free,
    compose_lab,
    docker_available,
    scan_text,
)
from dropbox.scope import NEVER_EMBED, default_scope_path, load_scope

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


def test_apk_yum_dnf_and_copy_clone_are_caught() -> None:
    assert scan_text("RUN apk add nmap\n", "Dockerfile")
    assert scan_text("RUN yum install -y nessus\n", "Dockerfile")
    assert scan_text("RUN dnf install nuclei\n", "Dockerfile")
    assert scan_text("RUN apk add zeek\n", "Dockerfile")
    assert scan_text("COPY nessus.deb /tmp/nessus.deb\n", "Dockerfile")
    assert scan_text("ADD openvas.rpm /tmp/openvas.rpm\n", "Dockerfile")
    assert scan_text("RUN git clone https://github.com/example/nuclei.git\n", "Dockerfile")
    assert scan_text("image: instrumentisto/nmap:latest\n", "compose")
    assert scan_text("FROM greenbone/openvas\n", "Dockerfile")


def test_wrap_post_in_image_file_is_caught() -> None:
    hits = scan_text("RUN curl -X POST https://x.invalid/api/risks\n", "Dockerfile")
    assert hits and any("wrap-post" in h for h in hits)
    hits = scan_text("wget -q https://wrap.invalid/api/auth/login\n", "Dockerfile")
    assert hits
    clean = scan_text(
        "# Never POST /api/risks. RISKREADY_PUSH stays 0.\nFROM python:3.12-slim\n",
        "Dockerfile",
    )
    assert clean == []
    comment = scan_text(
        "# Do not apt-install nmap/nessus/nuclei/openvas/gvm/zeek.\n",
        "compose",
    )
    assert comment == []


def test_dockerfile_and_compose_are_scanner_free() -> None:
    assert_image_files_scanner_free()
    assert_dropbox_compose_is_demo_dry()
    assert_farm_compose_is_skeleton()
    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.12-slim" in docker
    assert "GRC_LIVE_SCAN=0" in docker
    assert "RISKREADY_PUSH=0" in docker
    assert not any(line.strip().upper().startswith("RUN ") for line in docker.splitlines())


def test_never_embed_names_are_not_installed_in_image_files() -> None:
    blob = ""
    for rel in (
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.dropbox.yml",
        "farm/Dockerfile",
        "farm/docker-compose.yml",
    ):
        path = ROOT / rel
        if path.is_file():
            blob += "\n" + path.read_text(encoding="utf-8").lower()
    for tool in sorted(NEVER_EMBED | {"masscan", "naabu", "arp-scan", "fping", "netdiscover", "nbtscan"}):
        if tool in {"riskready"}:
            continue
        assert f"apt-get install {tool}" not in blob
        assert f"apt-get install -y {tool}" not in blob
        assert f"apt install {tool}" not in blob
        assert f"apk add {tool}" not in blob
        assert f"pip install {tool}" not in blob
        assert f"curl -x post" not in blob or "/api/risks" not in blob


def test_compose_skeletons_bind_scope_work_and_tool_bin() -> None:
    dropbox = (ROOT / "docker-compose.dropbox.yml").read_text(encoding="utf-8")
    farm = (ROOT / "farm" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "DROPBOX_SCOPE" in dropbox and "SCOPE.yaml" in dropbox
    assert "FARM_TOOL_BIN" in dropbox and "/opt/farm/bin" in dropbox
    assert "compose-in" in dropbox and "compose-out" in dropbox
    assert "FARM_SCOPE" in farm and "SCOPE.yaml" in farm
    assert "FARM_IN" in farm and "FARM_OUT" in farm
    assert "FARM_TOOL_BIN" in farm and "/opt/farm/bin" in farm
    assert "FARM_WORK" in farm
    assert "image: nmap" not in dropbox.lower()
    assert "image: nmap" not in farm.lower()


def test_dropbox_scope_env_overrides_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DROPBOX_SCOPE", raising=False)
    assert default_scope_path() == ROOT / "dropbox" / "SCOPE.yaml"
    alt = tmp_path / "SCOPE.yaml"
    alt.write_text((ROOT / "dropbox" / "SCOPE.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setenv("DROPBOX_SCOPE", str(alt))
    assert default_scope_path() == alt
    loaded = load_scope()
    assert "DEMO" in loaded.client_name
    monkeypatch.delenv("DROPBOX_SCOPE", raising=False)


def test_compose_lab_stamps_absent_without_docker() -> None:
    ok, reason = docker_available()
    stamp = compose_lab()
    assert stamp["scanner_free"] is True
    assert stamp["farm_skeleton"] is True
    assert stamp["wrap_free"] is True
    if not ok:
        assert stamp["status"] == "absent"
        assert stamp["status"] != "pass"
        assert "docker" in reason.lower() or "daemon" in reason.lower() or "PATH" in reason
        assert stamp["profiles_run"] == []
    else:
        assert stamp["status"] in {"pass", "fail"}
        assert stamp["status"] != "absent" or stamp["profiles_run"] == []


def test_dropbox_compose_runtime_skips_honestly_without_docker() -> None:
    ok, reason = docker_available()
    if ok:
        pytest.skip("docker is present — runtime path covered by scripts/dropbox_compose_lab.py")
    assert "docker" in reason.lower() or "daemon" in reason.lower() or "PATH" in reason
    # Honest skip: this is not a compose pass.
    pytest.skip(f"compose_lab absent: {reason}")
