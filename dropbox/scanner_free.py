"""LICENSE-LOCK: Dockerfile + compose stay scanner-free.

Static checks always run. Runtime compose is optional: when Docker is
absent the lab stamps absent/skip — it does not fake a pass.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dropbox.scope import NEVER_EMBED, ROOT

IMAGE_FILES = (
    ROOT / "Dockerfile",
    ROOT / "docker-compose.yml",
    ROOT / "docker-compose.dropbox.yml",
)
LAB_STUB_DIR = ROOT / "farm" / "tool-bin" / "lab"
_FORBIDDEN_STUB_EXT = {".deb", ".rpm", ".exe", ".nbin", ".nasl"}


def is_demo_lab_stub(path: Path) -> bool:
    """True for DEMO shell stubs under farm/tool-bin/lab/. Not ELF/deb scanners."""
    try:
        resolved = path.resolve()
        resolved.relative_to(LAB_STUB_DIR.resolve())
    except (ValueError, OSError):
        return False
    if not resolved.is_file() or resolved.suffix.lower() in _FORBIDDEN_STUB_EXT:
        return False
    try:
        raw = resolved.read_bytes()[:8]
    except OSError:
        return False
    if raw.startswith(b"\x7fELF") or raw.startswith(b"MZ"):
        return False
    body = resolved.read_text(encoding="utf-8", errors="replace")
    head = body.lstrip()
    return head.startswith("#!") and "DEMO" in body and "not a real scanner" in body.lower()


def image_files() -> tuple[Path, ...]:
    """Pack image files plus private farm Dockerfile/compose when present."""
    rows = list(IMAGE_FILES)
    farm = ROOT / "farm"
    if farm.is_dir():
        for name in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml"):
            path = farm / name
            if path.is_file():
                rows.append(path)
    return tuple(rows)

# Package / binary names that must never be installed or downloaded into the image.
SCANNER_PKGS = tuple(
    sorted(
        {
            "nmap",
            "ncat",
            "nping",
            "nuclei",
            "openvas",
            "gvm",
            "gvmd",
            "ospd-openvas",
            "nessus",
            "nessusd",
            "nessuscli",
            "zeek",
            "masscan",
            "naabu",
            "rustscan",
            "arp-scan",
            "fping",
            "netdiscover",
            "nbtscan",
            "metasploit",
            "msfconsole",
            "hexstrike",
            "hexstrike-ai",
        }
        | {n for n in NEVER_EMBED if n not in {"riskready", "bro"}}
    )
)

_PKG = "|".join(re.escape(p) for p in SCANNER_PKGS)

INSTALL_RE = re.compile(
    rf"(?:apt-get|apt|apk|yum|dnf|microdnf)\s+(?:install|add)\s+[^\n#]*\b(?:{_PKG})\b",
    re.IGNORECASE,
)
PIP_RE = re.compile(
    rf"pip(?:3)?\s+install\s+[^\n#]*\b(?:python-nmap|nuclei|{_PKG})\b",
    re.IGNORECASE,
)
FETCH_RE = re.compile(
    rf"(?:curl|wget)\s+[^\n]*\b(?:{_PKG})\b",
    re.IGNORECASE,
)
FROM_RE = re.compile(
    rf"^\s*(?:FROM|image:)\s+\S*\b(?:{_PKG}|kalilinux|instrumentisto/nmap|greenbone)\b",
    re.IGNORECASE | re.MULTILINE,
)
COPY_PKG_RE = re.compile(
    rf"^\s*(?:COPY|ADD)\s+\S*\b(?:{_PKG})\b\S*\.(?:deb|rpm|exe|nbin|nasl)",
    re.IGNORECASE | re.MULTILINE,
)
CLONE_RE = re.compile(
    rf"git\s+clone\s+[^\n]*\b(?:{_PKG}|hexstrike)\b",
    re.IGNORECASE,
)
WRAP_POST_RE = re.compile(
    r"(?:curl|wget)\s+[^\n]*(?:/api/risks|/api/auth/login|/itsm/assets|\$\{API\}/risks)",
    re.IGNORECASE,
)
RUN_SCANNER_RE = re.compile(
    r"^\s*RUN\s+(?:apt|apk|yum|dnf|pip)",
    re.IGNORECASE | re.MULTILINE,
)
ALLOWED_COMPOSE_IMAGES = (
    "grc-collector-pack:local",
    "${FARM_ORCH_IMAGE:-grc-collector-pack:local}",
)


def scan_text(text: str, label: str) -> list[str]:
    """Return human-readable hits. Service names like inventory-nmap are not installs."""
    hits: list[str] = []
    for rx, kind in (
        (INSTALL_RE, "package-install"),
        (PIP_RE, "pip-install"),
        (FETCH_RE, "download"),
        (FROM_RE, "base-image"),
        (COPY_PKG_RE, "copy-package"),
        (CLONE_RE, "git-clone"),
        (WRAP_POST_RE, "wrap-post"),
    ):
        for match in rx.finditer(text):
            hits.append(f"{label}: {kind}: {match.group(0).strip()[:160]}")
    return hits


def assert_image_files_scanner_free(paths: tuple[Path, ...] | None = None) -> None:
    files = paths or image_files()
    hits: list[str] = []
    for path in files:
        assert path.is_file(), f"missing {path}"
        text = path.read_text(encoding="utf-8")
        hits.extend(scan_text(text, path.name))
        if path.name == "Dockerfile":
            if RUN_SCANNER_RE.search(text):
                hits.append("Dockerfile: RUN package-manager (image must stay python:3.12-slim + COPY)")
            if "python:3.12-slim" not in text.splitlines()[0] and "FROM python:3.12-slim" not in text:
                hits.append("Dockerfile: base image is not python:3.12-slim")
    assert not hits, "scanner embed in image/compose:\n  " + "\n  ".join(hits)


def _compose_images_are_local(text: str, label: str) -> list[str]:
    hits: list[str] = []
    for match in re.finditer(r"^\s*image:\s+(\S+)", text, re.MULTILINE):
        image = match.group(1).strip().strip("\"'")
        if image not in ALLOWED_COMPOSE_IMAGES and not image.startswith("${"):
            hits.append(f"{label}: hub-soup image: {image}")
    return hits


def assert_dropbox_compose_is_demo_dry() -> None:
    path = ROOT / "docker-compose.dropbox.yml"
    text = path.read_text(encoding="utf-8")
    assert "DROPBOX_DEMO: \"1\"" in text or "DROPBOX_DEMO: '1'" in text
    assert "DROPBOX_LIVE: \"0\"" in text or "DROPBOX_LIVE: '0'" in text
    assert "GRC_LIVE_SCAN: \"0\"" in text
    assert "RISKREADY_PUSH: \"0\"" in text
    assert "DROPBOX_SCOPE" in text
    assert "SCOPE.yaml" in text
    assert "/opt/farm/bin" in text
    assert "compose-in" in text and "compose-out" in text
    assert "apt-get" not in text.lower()
    assert "apt install" not in text.lower()
    assert "apk add" not in text.lower()
    assert "hub.docker.com" not in text.lower()
    for profile in ("internal", "external"):
        assert f"--profile {profile}" in text or f'"{profile}"' in text
    hits = scan_text(text, path.name) + _compose_images_are_local(text, path.name)
    assert not hits, "dropbox compose skeleton drifted:\n  " + "\n  ".join(hits)


def assert_farm_compose_is_skeleton() -> None:
    """Farm compose is an operator bind-mount skeleton. No scanner packages. No Hub soup."""
    path = ROOT / "farm" / "docker-compose.yml"
    text = path.read_text(encoding="utf-8")
    docker = (ROOT / "farm" / "Dockerfile").read_text(encoding="utf-8")
    assert "DROPBOX_LIVE: \"0\"" in text
    assert "GRC_LIVE_SCAN: \"0\"" in text
    assert "RISKREADY_PUSH: \"0\"" in text
    assert "DROPBOX_SCOPE" in text
    assert "SCOPE.yaml" in text
    assert "/opt/farm/bin" in text or "FARM_TOOL_BIN" in text
    assert "FARM_IN" in text and "FARM_OUT" in text
    assert "farm-internal" in text
    assert "internal: true" in text
    assert "apt-get" not in text.lower()
    assert "apt install" not in text.lower()
    assert "hub.docker.com" not in text.lower()
    assert not any(line.strip().upper().startswith("RUN ") for line in docker.splitlines())
    for service in ("farm-discover", "farm-deepen", "farm-ingest", "farm-orchestrator"):
        assert service in text
    hits = scan_text(text, "farm/docker-compose.yml") + scan_text(docker, "farm/Dockerfile")
    hits.extend(_compose_images_are_local(text, "farm/docker-compose.yml"))
    assert not hits, "farm compose skeleton drifted:\n  " + "\n  ".join(hits)


def docker_available() -> tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "docker CLI not on PATH"
    try:
        info = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker info failed: {exc}"
    if info.returncode != 0:
        err = (info.stderr or info.stdout or "daemon not reachable").strip().splitlines()
        return False, err[-1] if err else "docker daemon not available"
    try:
        compose = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker compose unavailable: {exc}"
    if compose.returncode != 0:
        return False, "docker compose plugin not available"
    return True, (compose.stdout or "docker compose available").strip().splitlines()[0]


def _stamp_path() -> Path:
    dest = ROOT / "dropbox" / "work" / "compose-lab.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    return dest


def write_stamp(data: dict[str, Any]) -> Path:
    data = dict(data)
    data.setdefault("generated_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    path = _stamp_path()
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    out = os.environ.get("OUT_DIR")
    if out:
        extra = Path(out) / "compose_lab.json"
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return path


def run_dropbox_compose_profiles() -> dict[str, Any]:
    """Demo/dry internal+external via compose. Never --live. Never pack in/."""
    work_in = ROOT / "dropbox" / "work" / "compose-in"
    work_out = ROOT / "dropbox" / "work" / "compose-out"
    work_in.mkdir(parents=True, exist_ok=True)
    work_out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["DROPBOX_COMPOSE_IN"] = str(work_in)
    env["DROPBOX_COMPOSE_OUT"] = str(work_out)
    env["DROPBOX_DEMO"] = "1"
    env["DROPBOX_LIVE"] = "0"
    compose = [
        "docker",
        "compose",
        "-f",
        str(ROOT / "docker-compose.dropbox.yml"),
    ]
    ran: list[str] = []
    for profile in ("internal", "external"):
        proc = subprocess.run(
            compose + ["--profile", profile, "run", "--rm", "-T", f"dropbox-{profile}"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            env=env,
        )
        ran.append(profile)
        if proc.returncode != 0:
            raise RuntimeError(
                f"dropbox compose {profile} exit {proc.returncode}: "
                f"{(proc.stderr or proc.stdout)[-800:]}"
            )
    image = "grc-collector-pack:local"
    probe = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            image,
            "-c",
            "for b in nmap ncat nuclei openvas nessus nessuscli gvm zeek; "
            "do command -v $b && exit 10; done; exit 0",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if probe.returncode != 0:
        raise RuntimeError(f"scanner binary present in image: {(probe.stdout or probe.stderr)[:400]}")
    return {
        "status": "pass",
        "reason": "dropbox compose internal+external demo/dry; image has no scanner binaries",
        "scanner_free": True,
        "profiles_run": ran,
        "image": image,
    }


def compose_lab() -> dict[str, Any]:
    """Static scanner-free always. Runtime only if Docker is up. Never fake pass."""
    assert_image_files_scanner_free()
    assert_dropbox_compose_is_demo_dry()
    assert_farm_compose_is_skeleton()
    ok, reason = docker_available()
    if not ok:
        stamp = {
            "status": "absent",
            "reason": reason,
            "scanner_free": True,
            "farm_skeleton": True,
            "dropbox_skeleton": True,
            "wrap_free": True,
            "profiles_run": [],
            "note": "static scanner-free assertions passed; runtime compose not run",
        }
        write_stamp(stamp)
        return stamp
    try:
        stamp = run_dropbox_compose_profiles()
        stamp["farm_skeleton"] = True
        stamp["dropbox_skeleton"] = True
        stamp["wrap_free"] = True
    except Exception as exc:  # noqa: BLE001 — lab records the failure honestly
        stamp = {
            "status": "fail",
            "reason": str(exc)[:400],
            "scanner_free": True,
            "farm_skeleton": True,
            "dropbox_skeleton": True,
            "wrap_free": True,
            "profiles_run": [],
        }
        write_stamp(stamp)
        return stamp
    write_stamp(stamp)
    return stamp
