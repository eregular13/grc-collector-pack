"""Themis KEEP-minimum schedule set. Inventory only. No new parsers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from keep.adapters import SAMPLE_MARKERS, detect_family, family_group, is_sample_text

# Themis schedule set. Do not add the 111-catalog zoo here.
KEEP_MINIMUM = (
    "hardeningkitty",
    "lynis",
    "nmap",
    "testssl",
    "maester",
    "cloud",
)

VANITY_SCHEDULE = frozenset(
    {
        "nuclei",
        "trivy",
        "nessus",
        "nessuscli",
        "openvas",
        "gvm",
        "bloodhound",
        "sharphound",
        "nikto",
        "gobuster",
        "ffuf",
        "amass",
        "subfinder",
        "checkov",
    }
)

_SENSOR = {
    "hardeningkitty": "identity",
    "lynis": "wazuh",
    "nmap": "nmap",
    "testssl": "vuln",
    "maester": "saas",
    "cloud": "cloud",
    "prowler": "cloud",
    "scoutsuite": "cloud",
}

SKIP_NAMES = frozenset({".gitkeep", ".DS_Store", "SAMPLE.txt", "README.md", "plan.json"})


def _is_lynis(path: Path, text: str) -> bool:
    name = path.name.lower()
    if "lynis" in name or name.endswith("report.dat"):
        return True
    if "lynis" in text.lower() and (
        "warning" in text.lower() or "warning[]=" in text.lower() or "! " in text
    ):
        return True
    return False


def _is_nmap(path: Path, text: str) -> bool:
    suffix = path.suffix.lower()
    if suffix in {".xml", ".gnmap", ".nmap"} and (
        "<nmaprun" in text or "nmaprun" in text[:400].lower() or "Host:" in text
    ):
        return True
    if text.lstrip().startswith("<nmaprun") or "<nmaprun " in text[:800]:
        return True
    return any(line.startswith("Host:") for line in text.splitlines()[:20])


def detect_keepmin(path: Path) -> str | None:
    """KEEP-minimum family or None. Detect + land only. Never subprocess."""
    if not path.is_file() or path.name in SKIP_NAMES:
        return None
    family = detect_family(path)
    if family:
        return family_group(family)
    text = path.read_text(encoding="utf-8", errors="replace")
    if _is_lynis(path, text):
        return "lynis"
    if _is_nmap(path, text):
        return "nmap"
    return None


def inventory_keepmin(folder: Path) -> list[dict[str, Any]]:
    """List KEEP-minimum files already on disk. Never probes."""
    rows: list[dict[str, Any]] = []
    if not folder.is_dir():
        return rows
    for path in sorted(folder.rglob("*")):
        family = detect_keepmin(path)
        if not family:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        sample = is_sample_text(text) or any(m in text for m in SAMPLE_MARKERS)
        if "DEMO — not a client estate" in text or "DEMO fixture" in text:
            sample = True
        rows.append(
            {
                "path": str(path),
                "name": path.name,
                "family": family,
                "sensor": _SENSOR.get(family, family),
                "sample": sample,
                "invoke": False,
                "permission": "allow",
            }
        )
    return rows


def landed_sensors(rows: list[dict[str, Any]]) -> set[str]:
    return {str(row.get("sensor") or "") for row in rows if row.get("sensor")}


def refuse_vanity(name: str, *, file_on_disk: bool) -> str | None:
    """Refuse vanity schedule unless the file already landed."""
    tool = (name or "").strip().lower()
    if tool not in VANITY_SCHEDULE:
        return None
    if not file_on_disk:
        return f"KEEP-minimum only: refuse to schedule {tool} (no landed file)"
    return None
