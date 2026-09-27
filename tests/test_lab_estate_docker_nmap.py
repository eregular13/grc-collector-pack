"""Docker-network nmap runner gated to LAB_ESTATE_NETWORKS.

Never host-PATH nmap. Never internet CIDRs. LAB != SAMPLE != client.
"""
from __future__ import annotations

import pytest

from dropbox.lab_estate_docker_nmap import (
    docker_network_for_target,
    docker_nmap_argv,
    run_lab_estate_docker_nmap,
)
from dropbox.scope import GateError, attestation_digest, load_scope
from dropbox.mcp_stub import run_live_collectors
import subprocess
from pathlib import Path


def test_docker_network_for_labnet_host() -> None:
    assert docker_network_for_target("172.28.10.10") == "evergreen-lab_labnet"


def test_docker_network_for_labnet2_host() -> None:
    assert docker_network_for_target("172.28.11.10") == "evergreen-lab_labnet2"


def test_docker_network_for_misconfig_overlay_host() -> None:
    assert docker_network_for_target("172.31.250.10") == "misconfig_misconfig_lab"


@pytest.mark.parametrize("target", ["8.8.8.8", "127.0.0.1", "192.168.64.10", "not-an-ip"])
def test_docker_network_refuses_outside_lab_estate(target: str) -> None:
    with pytest.raises(GateError) as exc:
        docker_network_for_target(target)
    assert "lab-estate" in str(exc.value).lower() or "non-IP" in str(exc.value)


def test_docker_nmap_argv_joins_labnet_and_does_not_use_host_nmap() -> None:
    argv = docker_nmap_argv(
        "evergreen-lab_labnet",
        ["172.28.10.10"],
        host_out=r"C:\lab-out",
        xml_name="labnet.xml",
    )
    assert argv[0] == "docker"
    assert "--network" in argv
    assert argv[argv.index("--network") + 1] == "evergreen-lab_labnet"
    assert "instrumentisto/nmap:7.95" in argv
    assert "-oX" in argv
    assert "/out/labnet.xml" in argv
    assert "172.28.10.10" in argv
    assert not any(str(item).lower().endswith("nmap.exe") for item in argv)
    assert "-sT" in argv
    assert "--host-timeout" in argv


def test_run_lab_estate_docker_nmap_groups_networks_and_writes_xml(tmp_path: Path) -> None:
    dest = tmp_path / "in" / "nmap"
    calls: list[list[str]] = []

    def fake_run(argv, *args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append([str(item) for item in argv])
        xml = dest / Path(argv[argv.index("-oX") + 1]).name
        xml.parent.mkdir(parents=True, exist_ok=True)
        xml.write_text(
            '<?xml version="1.0"?><nmaprun><host><address addr="172.28.10.10"/></host></nmaprun>\n',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    written = run_lab_estate_docker_nmap(
        ["172.28.10.10", "172.28.11.10"],
        tmp_path / "in",
        runner=fake_run,
        which=lambda _name: r"C:\Windows\System32\docker.exe",
    )
    assert len(calls) == 2
    nets = {c[c.index("--network") + 1] for c in calls}
    assert nets == {"evergreen-lab_labnet", "evergreen-lab_labnet2"}
    assert all(c[0] == "docker" for c in calls)
    assert written.is_dir()
    xmls = sorted(p.name for p in dest.glob("*.xml"))
    assert xmls == ["labnet.xml", "labnet2.xml"]


def test_run_lab_estate_docker_nmap_refuses_mixed_outside(tmp_path: Path) -> None:
    with pytest.raises(GateError) as exc:
        run_lab_estate_docker_nmap(
            ["172.28.10.10", "8.8.8.8"],
            tmp_path / "in",
            runner=lambda *_a, **_k: subprocess.CompletedProcess([], 0, "", ""),
            which=lambda _name: r"C:\Windows\System32\docker.exe",
        )
    assert "8.8.8.8" in str(exc.value)


def test_run_lab_estate_docker_nmap_refuses_missing_docker(tmp_path: Path) -> None:
    with pytest.raises(GateError) as exc:
        run_lab_estate_docker_nmap(
            ["172.28.10.10"],
            tmp_path / "in",
            which=lambda _name: None,
        )
    assert "docker" in str(exc.value).lower()


def _lab_scope(tmp_path: Path) -> Path:
    att = tmp_path / "consent.md"
    att.write_text("ok\n", encoding="utf-8")
    digest = attestation_digest(att.read_bytes())
    path = tmp_path / "SCOPE.yaml"
    path.write_text(
        "client:\n  name: DEMO — not a client estate\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  cidrs:\n    - 172.28.10.0/24\n"
        "  hosts:\n    - 172.28.10.10\nexternal:\n  ips:\n    - 192.0.2.10\n"
        "allow_tools:\n  - nmap\n",
        encoding="utf-8",
    )
    return path


def test_run_live_collectors_uses_docker_nmap_not_synthetic_gnmap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: dict[str, object] = {"n": 0, "targets": None}

    def fake_docker(targets, dest_in, **_kwargs):
        calls["n"] = int(calls["n"]) + 1
        calls["targets"] = list(targets)
        nmap = Path(dest_in) / "nmap"
        nmap.mkdir(parents=True, exist_ok=True)
        (nmap / "labnet.xml").write_text(
            '<?xml version="1.0"?><nmaprun></nmaprun>\n', encoding="utf-8"
        )
        return nmap

    monkeypatch.setattr(
        "dropbox.lab_estate_docker_nmap.run_lab_estate_docker_nmap", fake_docker
    )
    monkeypatch.setattr(
        "dropbox.mcp_stub.run_lab_estate_docker_nmap", fake_docker, raising=False
    )
    dest_in = tmp_path / "in"
    dest_in.mkdir()
    scope = load_scope(_lab_scope(tmp_path))
    pack = run_live_collectors(
        scope=scope, targets=["172.28.10.10"], dest_in=dest_in, estate="lab"
    )
    assert calls["n"] == 1
    assert calls["targets"] == ["172.28.10.10"]
    gnmap = dest_in / "nmap" / "dropbox-inventory.gnmap"
    if gnmap.is_file():
        blob = gnmap.read_text(encoding="utf-8")
        assert "Not Nmap" not in blob
    assert (dest_in / "nmap" / "labnet.xml").is_file()
    assert Path(pack) == dest_in / "nmap"
