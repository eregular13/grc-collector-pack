"""File-drop adapters for KEEP-chain families. Never subprocess. Never scan."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from shared.testssl import is_testssl

SAMPLE_MARKERS = (
    "SAMPLE — redacted KEEP-chain",
    "not a client KEEP",
    "keep.invalid",
    "onmicrosoft.invalid",
    '"sample": true',
    "sample-dc01",
    "sample-tenant",
    "sample-vpn.example.invalid",
    "sample-public-assets",
    "sample-scout-public",
)

# Four KEEP families. Prowler | ScoutSuite share the cloud sensor.
KEEP_FAMILIES = (
    "hardeningkitty",
    "maester",
    "testssl",
    "cloud",
)

_SENSOR = {
    "hardeningkitty": "identity",
    "maester": "saas",
    "testssl": "vuln",
    "prowler": "cloud",
    "scoutsuite": "cloud",
    "cloud": "cloud",
}

_KEEP_COLLECTORS = (
    ("cloud-prowler", "cloud_prowler.py"),
    ("vuln-scan", "vuln_scan.py"),
    ("identity-ad", "identity_ad.py"),
    ("saas-idp", "saas_idp.py"),
)


def is_sample_text(text: str) -> bool:
    blob = text or ""
    return any(marker in blob for marker in SAMPLE_MARKERS)


def _load_json(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff").strip()
        if not raw or raw[0] not in "{[":
            return None
        return json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return None


def _hk_csv(text: str) -> bool:
    head = text[:800].lower()
    if "result" not in head:
        return False
    return "severity" in head and ("name" in head or "id" in head) and (
        "computername" in head or "hostname" in head or "failed" in text.lower()
    )


def _maester(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    rows = payload.get("TestResults") or payload.get("Tests") or payload.get("tests") or payload.get("Maester")
    if not isinstance(rows, list) or not rows:
        return False
    row = rows[0] if isinstance(rows[0], dict) else {}
    blob = " ".join(str(row.get(k) or "") for k in ("Id", "id", "Name", "name"))
    return "MT." in blob or "Result" in row or "Passed" in row


def _prowler(payload: Any) -> bool:
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        rows = payload["findings"]
        return bool(rows) and isinstance(rows[0], dict) and (
            "CheckID" in rows[0] or "CheckTitle" in rows[0]
        )
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return "CheckID" in payload[0] or "CheckTitle" in payload[0]
    return False


def _scoutsuite(payload: Any) -> bool:
    services = payload.get("services") if isinstance(payload, dict) else None
    if not isinstance(services, dict):
        return False
    for svc in services.values():
        if isinstance(svc, dict) and isinstance(svc.get("findings"), dict):
            return True
    return False


def detect_family(path: Path) -> str | None:
    """Return KEEP family id or None. File-drop detect only."""
    if not path.is_file() or path.name in {".gitkeep", ".DS_Store", "SAMPLE.txt", "README.md"}:
        return None
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".csv" or _hk_csv(text[:2000]):
        return "hardeningkitty" if _hk_csv(text) else None
    payload = _load_json(path)
    if payload is None:
        return None
    if is_testssl(payload):
        return "testssl"
    if _maester(payload):
        return "maester"
    if _prowler(payload):
        return "prowler"
    if _scoutsuite(payload):
        return "scoutsuite"
    return None


def family_group(family: str) -> str:
    if family in {"prowler", "scoutsuite", "cloud"}:
        return "cloud"
    return family


def scan_keep_dir(folder: Path) -> list[dict[str, Any]]:
    """Inventory KEEP-shaped files under a directory (recursive)."""
    rows: list[dict[str, Any]] = []
    if not folder.is_dir():
        return rows
    for path in sorted(folder.rglob("*")):
        family = detect_family(path)
        if not family:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        rows.append(
            {
                "path": str(path),
                "name": path.name,
                "family": family,
                "group": family_group(family),
                "sensor": _SENSOR[family],
                "sample": is_sample_text(text),
                "adapter": f"keep.adapters.{family}",
                "invoke": False,
            }
        )
    return rows


def client_keep_ready(rows: list[dict[str, Any]]) -> bool:
    """True only when all four families are present and none are samples."""
    groups = {str(row.get("group") or "") for row in rows if not row.get("sample")}
    return set(KEEP_FAMILIES) <= groups


def land_keep_files(
    sources: list[dict[str, Any]],
    dest_in: Path,
) -> list[dict[str, Any]]:
    """Copy KEEP files into Layer C sensor dirs. Never subprocess."""
    dest_in.mkdir(parents=True, exist_ok=True)
    landed: list[dict[str, Any]] = []
    for row in sources:
        src = Path(row["path"])
        sensor = str(row.get("sensor") or _SENSOR.get(row["family"], ""))
        if not sensor or not src.is_file():
            continue
        dest = dest_in / sensor
        dest.mkdir(parents=True, exist_ok=True)
        target = dest / src.name
        if src.resolve() != target.resolve():
            shutil.copy2(src, target)
        item = dict(row)
        item["dest"] = str(target)
        item["landed"] = True
        landed.append(item)
    return landed


def keep_collectors() -> tuple[tuple[str, str], ...]:
    """Existing Layer C collectors only. No new sensor scaffolding."""
    return _KEEP_COLLECTORS
