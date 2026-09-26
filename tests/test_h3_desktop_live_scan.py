"""H3 DESKTOP: GRC_LIVE_SCAN=1 live collectors do not nmap 172.28.x.

Captures the DESKTOP refusal (no host nmap, no docker-network runner).
Expected XFAIL on ce67328 until hermes/h3-live-docker-runner-2026-09-26.
LAB != SAMPLE != client. Never POST /api/risks.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from dropbox.mcp_stub import run_live_collectors
from dropbox.scope import load_scope

ROOT = Path(__file__).resolve().parents[1]


def _consent(tmp_path: Path) -> tuple[Path, str]:
    att = tmp_path / "consent.md"
    att.write_text("LAB estate H3 xfail\n", encoding="utf-8")
    return att, hashlib.sha256(att.read_bytes()).hexdigest()


def _lab_scope(tmp_path: Path) -> Path:
    att, digest = _consent(tmp_path)
    path = tmp_path / "SCOPE.yaml"
    path.write_text(
        "client:\n  name: DEMO — not a client estate\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  cidrs:\n    - 172.28.10.0/24\n"
        "    - 172.28.11.0/24\n  hosts:\n    - 172.28.10.10\n"
        "external:\n  ips:\n    - 192.0.2.10\nallow_tools:\n  - nmap\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.xfail(
    reason=(
        "H3 DESKTOP: GRC_LIVE_SCAN=1 run_live_collectors does not spawn nmap "
        "against 172.28.10.10 (no host nmap, no docker-network runner)"
    ),
    strict=True,
)
def test_h3_run_live_collectors_spawns_nmap_against_lab_estate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded: list[list[str]] = []
    real_run = subprocess.run

    def wrap(argv, *args, **kwargs):  # type: ignore[no-untyped-def]
        recorded.append([str(item) for item in argv])
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr("subprocess.run", wrap)
    monkeypatch.setattr("dropbox.runners.subprocess.run", wrap)
    monkeypatch.setattr(subprocess, "run", wrap)

    dest_in = tmp_path / "in"
    dest_in.mkdir()
    (dest_in / "LAB.txt").write_text(
        "LAB/DEMO -- not a client estate.\n", encoding="utf-8"
    )
    scope = load_scope(_lab_scope(tmp_path))
    run_live_collectors(
        scope=scope,
        targets=["172.28.10.10"],
        dest_in=dest_in,
        estate="lab",
    )
    nmap_calls = [
        row
        for row in recorded
        if row and Path(row[0]).name.lower().startswith("nmap")
    ]
    docker_nmap = [
        row
        for row in recorded
        if row
        and Path(row[0]).name.lower().startswith("docker")
        and any("nmap" in str(item).lower() for item in row)
    ]
    assert nmap_calls or docker_nmap, recorded
    joined = " ".join(" ".join(row) for row in (nmap_calls or docker_nmap))
    assert "172.28.10.10" in joined
