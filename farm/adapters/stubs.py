"""Callable slot stubs. Plan-only unless allowlisted + on PATH. Never download."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Callable

from dropbox.orchestrator import byo
from dropbox.scope import FORBIDDEN_TOOLS, GateError, is_open_internet_cidr
from farm.adapters.catalog import load_slots

Which = Callable[[str], str | None]

# Never subprocess these, even if a slot is mis-marked wired.
NEVER_SUBPROCESS = frozenset(FORBIDDEN_TOOLS) | {
    "nuclei",
    "openvas",
    "gvm",
    "gvmd",
    "pingcastle",
    "purpleknight",
    "bloodhound",
    "osqueryi",
}


def _named_host(target: str, tool: str) -> str:
    raw = str(target or "").strip()
    if "*" in raw or "?" in raw or ("/" in raw and "://" not in raw):
        raise GateError(f"{tool} refuses wildcard/CIDR {target!r}")
    name = raw.split("://")[-1].split("/")[0].split(":")[0]
    if not name:
        raise GateError(f"{tool} refuses {target!r}")
    return name


def argv_for(slot_id: str, exe: str, target: str, timeout: int) -> list[str]:
    """Quiet/capture argv for an invoke slot. No installer flags."""
    name = (slot_id or "").strip().lower()
    timeout = max(1, int(timeout))
    if name in NEVER_SUBPROCESS:
        raise GateError(f"LICENSE-LOCK: farm adapter refuses {name!r}")
    if name == "nmap":
        return byo.nmap_quiet_argv(exe, target, timeout)
    if name in {"nessus", "nessuscli"}:
        return byo.nessus_batch_argv(exe, target, timeout)
    if name == "curl":
        url = target if "://" in target else f"https://{target}"
        return byo.curl_header_argv(exe, url, timeout)
    if name in {"testssl", "testssl.sh"}:
        return byo.testssl_argv(exe, target, timeout)
    if name == "lynis":
        return [exe, "audit", "system", "--quick", "--no-colors"]
    if name == "ss":
        return [exe, "-lntH"]
    if name == "ip":
        return [exe, "-br", "addr"]
    if name == "prowler":
        return [exe, "aws", "-M", "json"]
    if name == "hardeningkitty-export":
        return [exe, "--export", str(target)]
    if name == "maester":
        return [exe, "--output", str(target)]
    if name == "trivy":
        return [exe, "fs", "--format", "json", "--offline-scan", str(target)]
    if name == "rustscan":
        if is_open_internet_cidr(target):
            raise GateError("rustscan refuses 0.0.0.0/0")
        return [exe, "-a", target, "--greppable"]
    if name == "naabu":
        if is_open_internet_cidr(target):
            raise GateError("naabu refuses 0.0.0.0/0")
        return [exe, "-host", target, "-silent"]
    if name == "httpx":
        host = _named_host(target, "httpx")
        url = target if "://" in target else f"https://{host}"
        return [exe, "-u", url, "-silent"]
    if name == "dig":
        return [exe, "+short", _named_host(target, "dig")]
    if name == "whois":
        return [exe, _named_host(target, "whois")]
    if name == "sslscan":
        return [exe, "--no-failed", _named_host(target, "sslscan")]
    raise GateError(f"no adapter argv for slot {slot_id!r}")


def run_slot(
    slot_id: str,
    dest: Path,
    allow_tools: list[str],
    target: str = ".",
    timeout: int = 8,
    live: bool = False,
    which: Which | None = None,
) -> dict[str, Any]:
    """Invoke one wired slot or stay plan-only. Forbidden tools never run."""
    which_fn = which or shutil.which
    slots = load_slots()
    name = (slot_id or "").strip().lower()
    slot = slots.get(name)
    if not slot:
        raise GateError(f"unknown farm slot {slot_id!r}")
    binary = str(slot.get("binary") or name).lower()
    if binary in NEVER_SUBPROCESS or name in NEVER_SUBPROCESS:
        raise GateError(f"LICENSE-LOCK: farm adapter refuses {name!r}")
    base = {
        "slot": name,
        "ran": False,
        "sensor": slot.get("sensor"),
        "output_glob": slot.get("output_glob"),
        "invoke": bool(slot.get("invoke")),
        "subprocess": False,
    }
    if slot.get("wired") is True and slot.get("invoke") is False:
        return {
            **base,
            "mode": "file_drop",
            "tool_ready": False,
            "skip_reason": "file-drop stub (never subprocess)",
        }
    if slot.get("wired") is not True:
        return {
            **base,
            "mode": "catalog",
            "tool_ready": False,
            "skip_reason": "file-drop only (not a callable adapter)",
        }
    exe, reason = byo.which_allowed(binary, allow_tools, which=which_fn)
    if not exe:
        return {**base, "mode": "plan", "tool_ready": False, "skip_reason": reason}
    if not live:
        return {
            **base,
            "mode": "plan",
            "tool_ready": True,
            "skip_reason": "plan-only (live=false)",
        }
    argv = argv_for(name, exe, target, timeout)
    dest = Path(dest)
    rc = byo.run_allowed(argv, dest, timeout, allow_tools=allow_tools)
    return {
        **base,
        "mode": "live",
        "ran": True,
        "tool_ready": True,
        "subprocess": True,
        "rc": rc,
        "dest": str(dest),
        "argv": argv,
    }
