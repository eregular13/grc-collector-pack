"""CIDR sharding and host batching. Not one scanner on a /16."""

from __future__ import annotations

import ipaddress


def shard_cidrs(cidrs: list[str], prefix: int = 24) -> list[str]:
    """Split each IPv4 CIDR into prefix-length jobs (default /24)."""
    if not 8 <= int(prefix) <= 32:
        raise ValueError(f"discover_prefix must be 8..32, got {prefix}")
    out: list[str] = []
    for raw in cidrs:
        net = ipaddress.ip_network(str(raw), strict=False)
        if net.version != 4:
            raise ValueError(f"IPv6 not supported: {raw}")
        if net.prefixlen >= prefix:
            out.append(str(net))
            continue
        out.extend(str(sub) for sub in net.subnets(new_prefix=prefix))
    return out


def batch_hosts(hosts: list[str], size: int = 3) -> list[list[str]]:
    """Group live/SCOPE hosts into small deepen batches (2–5)."""
    if not 2 <= int(size) <= 5:
        raise ValueError(f"deepen_batch must be 2..5, got {size}")
    names = [h.strip() for h in hosts if str(h).strip()]
    if not names:
        return []
    return [names[i : i + size] for i in range(0, len(names), size)]


def reject_wide_deepen_target(target: str) -> None:
    """Deepen is per-host. Never a /16 (or any multi-address CIDR) in one worker."""
    text = str(target or "").strip()
    if "/" not in text:
        return
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return
    if net.num_addresses > 1:
        raise ValueError(
            f"deepen refuses network target {text} ({net.num_addresses} addresses); "
            "never a /16 in one worker"
        )
