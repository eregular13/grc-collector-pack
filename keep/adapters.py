"""File-drop adapters for KEEP-chain families. Never subprocess. Never scan."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from shared.lab_stamp import path_is_lab
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

LAB_MARKERS = (
    "LAB/DEMO",
    '"lab": true',
    "LAB dest_in",
    "Scan-shaped compose-lab",
    "LAB != SAMPLE",
    "LAB -- not a client",
)

# fixtures/demo KEEP-shaped files are a different estate. They must not
# flip client_keep just because they lack the keep-samples banner.
DEMO_MARKERS = (
    "DEMO — not a client",
    "demo-public-assets",
    "iam-admin-breakglass",
    "dev-api.example.com",
    "arn:aws:s3:::demo-public-assets",
    ",win-dc01",
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
    return any(marker in blob for marker in SAMPLE_MARKERS + DEMO_MARKERS)


def is_lab_text(text: str) -> bool:
    blob = text or ""
    return any(marker in blob for marker in LAB_MARKERS)


def pack_in_is_lab(folder: Path) -> bool:
    """True when dest_in/pack in/ is a LAB tree. LAB never counts as KEEP."""
    dest = Path(folder)
    if (dest / "LAB.txt").is_file():
        return True
    for path in dest.rglob("LAB.txt"):
        if path.is_file():
            return True
    return False


def sample_as_client_reason(
    rows: list[dict[str, Any]],
    *,
    sample: bool,
    client_keep: bool,
) -> str | None:
    """Fail-closed when SAMPLE/DEMO/LAB would stamp as a client KEEP drop."""
    if client_keep and sample:
        return "SAMPLE/DEMO cannot stamp client_keep"
    if client_keep and any(row.get("sample") for row in rows):
        return "sample-marked KEEP file cannot stamp client_keep"
    if client_keep and any(row.get("lab") for row in rows):
        return "LAB cannot stamp client_keep"
    if client_keep and any(is_lab_text(str(row.get("path") or "")) for row in rows):
        return "LAB cannot stamp client_keep"
    return None


def _load_json(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff").strip()
        if not raw or raw[0] not in "{[":
            return None
        return json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return None


def _hk_csv(text: str) -> bool:
    first = ""
    for line in text.splitlines():
        if line.strip():
            first = line.strip().lstrip("\ufeff")
            break
    if not first or first[0] in "{[":
        return False
    head = first.lower().replace(" ", "")
    if "result" not in head:
        return False
    return "severity" in head or "name" in head or "id" in head


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
    """Return KEEP family id or None. File-drop detect only.

    LAB dest_in never enters the KEEP inventory (LAB != SAMPLE != client).
    """
    skip = {".gitkeep", ".DS_Store", "SAMPLE.txt", "README.md", "LAB.txt", "MANIFEST", "MANIFEST.json"}
    if not path.is_file() or path.name in skip:
        return None
    if path_is_lab(path):
        return None
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".csv" or _hk_csv(text):
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
        lab = path_is_lab(path) or is_lab_text(text)
        rows.append(
            {
                "path": str(path),
                "name": path.name,
                "family": family,
                "group": family_group(family),
                "sensor": _SENSOR[family],
                "sample": is_sample_text(text),
                "lab": lab,
                "adapter": f"keep.adapters.{family}",
                "invoke": False,
            }
        )
    return rows


def client_keep_ready(rows: list[dict[str, Any]]) -> bool:
    """True only when all four families are present and none are samples/LAB."""
    groups = {
        str(row.get("group") or "")
        for row in rows
        if not row.get("sample") and not row.get("lab")
    }
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
