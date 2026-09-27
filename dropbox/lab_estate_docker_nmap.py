"""Docker-network nmap runner gated to DESKTOP lab-estate CIDRs.

Host-PATH nmap is not used (Windows cannot route to 172.28.x).
Never internet targets. LAB != SAMPLE != client. Never POST /api/risks.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Callable

from dropbox.scope import GateError

WhichFn = Callable[[str], str | None]
RunnerFn = Callable[..., subprocess.CompletedProcess[str]]

NETWORK_XML_NAME = {
    "evergreen-lab_labnet": "labnet.xml",
    "evergreen-lab_labnet2": "labnet2.xml",
    "misconfig_misconfig_lab": "misconfig.xml",
}

LAB_CIDR_TO_DOCKER_NETWORK = {
    "172.28.10.0/24": "evergreen-lab_labnet",
    "172.28.11.0/24": "evergreen-lab_labnet2",
    "172.31.250.0/24": "misconfig_misconfig_lab",
}

NMAP_IMAGE = "instrumentisto/nmap:7.95"


def docker_network_for_target(target: str) -> str:
    raw = (target or "").strip()
    host = raw.split("://")[-1].split("/")[0].split(":")[0].lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise GateError(f"lab-estate docker nmap refuses non-IP target {target!r}") from exc
    for cidr, network in LAB_CIDR_TO_DOCKER_NETWORK.items():
        net = ipaddress.ip_network(cidr, strict=False)
        if ip in net:
            return network
    raise GateError(f"requested target(s) outside lab-estate networks: {target}")


def docker_nmap_argv(
    network: str,
    targets: list[str],
    *,
    host_out: str,
    xml_name: str,
) -> list[str]:
    net = str(network or "").strip()
    if not net:
        raise GateError("lab-estate docker nmap requires a docker network")
    hosts = [str(item).strip() for item in targets if str(item).strip()]
    if not hosts:
        raise GateError("lab-estate docker nmap requires at least one target")
    for host in hosts:
        mapped = docker_network_for_target(host)
        if mapped != net:
            raise GateError(f"target {host} is not on docker network {net}")
    name = str(xml_name or "").strip()
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise GateError("lab-estate docker nmap xml_name is not a basename")
    out = str(host_out or "").strip()
    if not out:
        raise GateError("lab-estate docker nmap requires host_out")
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        net,
        "-v",
        f"{out}:/out",
        NMAP_IMAGE,
        "-n",
        "-Pn",
        "-sT",
        "-T4",
        "--open",
        "--max-retries",
        "1",
        "--host-timeout",
        "30s",
        "-oX",
        f"/out/{name}",
        *hosts,
    ]


def run_lab_estate_docker_nmap(
    targets: list[str],
    dest_in: Path,
    *,
    runner: RunnerFn | None = None,
    which: WhichFn | None = None,
    timeout: int = 120,
) -> Path:
    """Spawn instrumentisto/nmap on the matching lab docker network. Never host nmap."""
    rows = [str(item).strip() for item in (targets or []) if str(item).strip()]
    if not rows:
        raise GateError("lab-estate docker nmap requires at least one target")
    grouped: dict[str, list[str]] = defaultdict(list)
    for raw in rows:
        grouped[docker_network_for_target(raw)].append(raw)

    which_fn = which or shutil.which
    if not which_fn("docker") and not which_fn("docker.exe"):
        raise GateError("lab-estate docker nmap: docker not on PATH (will not download nmap)")

    dest_in = Path(dest_in)
    nmap_dir = dest_in / "nmap"
    nmap_dir.mkdir(parents=True, exist_ok=True)
    run_fn = runner or subprocess.run
    for network, hosts in grouped.items():
        xml_name = NETWORK_XML_NAME.get(network)
        if not xml_name:
            raise GateError(f"lab-estate docker nmap has no xml name for {network}")
        argv = docker_nmap_argv(
            network,
            hosts,
            host_out=str(nmap_dir.resolve()),
            xml_name=xml_name,
        )
        run_fn(argv, capture_output=True, text=True, timeout=max(1, int(timeout)), check=False)
    xmls = list(nmap_dir.glob("*.xml"))
    if not xmls:
        raise GateError("lab-estate docker nmap produced no XML")
    return nmap_dir
