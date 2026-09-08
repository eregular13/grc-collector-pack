"""Parse dropped Intune / Jamf endpoint-inventory exports.

Parse-only. Does not call Graph, Intune, or Jamf APIs.
Missing encryption / EDR / enrollment fields invent nothing.
"""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path
from typing import Any

_ENCRYPTED_TRUE = frozenset(
    {"true", "1", "yes", "encrypted", "compliant", "filevault2", "enabled", "on", "complete"}
)
_ENCRYPTED_FALSE = frozenset(
    {"false", "0", "no", "not encrypted", "unencrypted", "off", "disabled", "none", "notencrypted"}
)
_ENROLLED_TRUE = frozenset(
    {"true", "1", "yes", "enrolled", "managed", "on", "supervised", "mdm"}
)
_ENROLLED_FALSE = frozenset(
    {
        "false",
        "0",
        "no",
        "off",
        "unenrolled",
        "not enrolled",
        "never",
        "retirepending",
        "retire pending",
        "unknown",
    }
)
_EDR_TRUE = frozenset({"true", "1", "yes", "enabled", "installed", "updated", "healthy", "on"})
_EDR_FALSE = frozenset(
    {"false", "0", "no", "not installed", "missing", "disabled", "notupdated", "not updated", "off", "none"}
)


def _token(raw: Any) -> str:
    return str(raw or "").strip().lower().replace("_", " ").replace("-", " ")


def _as_flag(raw: Any, yes: frozenset[str], no: frozenset[str]) -> bool | None:
    if raw is True:
        return True
    if raw is False:
        return False
    token = _token(raw)
    compact = token.replace(" ", "")
    yes_c = {t.replace(" ", "") for t in yes}
    no_c = {t.replace(" ", "") for t in no}
    if token in yes or compact in yes_c:
        return True
    if token in no or compact in no_c:
        return False
    return None


def _encrypted(device: dict[str, Any]) -> bool | None:
    for key in ("isEncrypted", "encrypted", "encryptionState", "disk_encryption_enabled"):
        if key in device:
            return _as_flag(device.get(key), _ENCRYPTED_TRUE, _ENCRYPTED_FALSE)
    disk = device.get("disk_encryption")
    if isinstance(disk, dict):
        for key in ("filevault2_enabled", "filevault_enabled", "encrypted", "status"):
            if key in disk:
                return _as_flag(disk.get(key), _ENCRYPTED_TRUE, _ENCRYPTED_FALSE)
    hardware = device.get("hardware")
    if isinstance(hardware, dict):
        for key in ("filevault2_status", "filevault_status", "encrypted"):
            if key in hardware:
                return _as_flag(hardware.get(key), _ENCRYPTED_TRUE, _ENCRYPTED_FALSE)
    users = device.get("filevault2_users")
    if isinstance(users, list):
        return len(users) > 0
    return None


def _mdm_enrolled(device: dict[str, Any]) -> bool | None:
    for key in (
        "azureADRegistered",
        "azureAdRegistered",
        "mdmEnrolled",
        "isSupervised",
        "managedDeviceOwnerType",
    ):
        if key in device:
            val = device.get(key)
            if key == "managedDeviceOwnerType":
                token = _token(val)
                if token in {"company", "corporate", "supervised"}:
                    return True
                if token in {"unknown", "none", "personal"}:
                    return None if token == "personal" else False
            return _as_flag(val, _ENROLLED_TRUE, _ENROLLED_FALSE)
    state = device.get("managementState") or device.get("management_state")
    if state is not None and str(state).strip() != "":
        flagged = _as_flag(state, _ENROLLED_TRUE, _ENROLLED_FALSE)
        if flagged is not None:
            return flagged
        token = _token(state)
        if token in {"managed", "enrolled"}:
            return True
        if token in {"retirepending", "retire pending", "unenrolled", "unknown", "wipepending"}:
            return False
    general = device.get("general") if isinstance(device.get("general"), dict) else {}
    if "mdm_capable" in general:
        capable = _as_flag(general.get("mdm_capable"), _ENROLLED_TRUE, _ENROLLED_FALSE)
        users = general.get("mdm_capable_users")
        if isinstance(users, dict):
            inner = users.get("mdm_capable_user")
            if isinstance(inner, list) and not inner and capable is True:
                return False
        return capable
    mdm = device.get("mdm") if isinstance(device.get("mdm"), dict) else {}
    enroll = mdm.get("enrollment_status") or mdm.get("enrollment")
    if enroll is not None:
        token = _token(enroll)
        if token.startswith("on"):
            return True
        return _as_flag(enroll, _ENROLLED_TRUE, _ENROLLED_FALSE)
    return None


def _edr_present(device: dict[str, Any]) -> bool | None:
    for key in (
        "antivirusStatus",
        "antivirus_status",
        "defenderStatus",
        "edrStatus",
        "edr",
        "endpointProtection",
    ):
        if key in device:
            return _as_flag(device.get(key), _EDR_TRUE, _EDR_FALSE)
    security = device.get("security") if isinstance(device.get("security"), dict) else {}
    for key in ("antivirus_status", "edr", "gatekeeper"):
        if key in security:
            return _as_flag(security.get(key), _EDR_TRUE, _EDR_FALSE)
    apps = device.get("detectedApps")
    if isinstance(apps, list):
        names = " ".join(str(a.get("displayName") if isinstance(a, dict) else a) for a in apps).lower()
        if any(tok in names for tok in ("defender", "crowdstrike", "falcon", "sentinelone", "carbon black")):
            return True
        if apps == [] and ("detectedApps" in device):
            return False
    return None


def _device_name(device: dict[str, Any]) -> str:
    general = device.get("general") if isinstance(device.get("general"), dict) else {}
    return str(
        device.get("deviceName")
        or device.get("name")
        or device.get("hostname")
        or device.get("computer_name")
        or general.get("name")
        or device.get("id")
        or ""
    ).strip()


def _normalize_device(device: dict[str, Any]) -> dict[str, Any] | None:
    name = _device_name(device)
    if not name:
        return None
    general = device.get("general") if isinstance(device.get("general"), dict) else {}
    return {
        "name": name,
        "encrypted": _encrypted(device),
        "mdm_enrolled": _mdm_enrolled(device),
        "edr_present": _edr_present(device),
        "platform": str(
            device.get("operatingSystem")
            or device.get("os")
            or device.get("platform")
            or general.get("platform")
            or ""
        ),
        "compliance": str(device.get("complianceState") or device.get("compliance") or ""),
    }


def _looks_fleet(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    hosts = payload.get("hosts")
    if isinstance(payload.get("data"), dict) and isinstance(payload["data"].get("hosts"), list):
        hosts = payload["data"]["hosts"]
    if isinstance(payload.get("host"), dict):
        hosts = [payload["host"]]
    if not isinstance(hosts, list) or not hosts:
        return False
    sample = hosts[0] if isinstance(hosts[0], dict) else {}
    return "disk_encryption_enabled" in sample or "primary_ip" in sample or "computer_name" in sample


def _looks_wazuh(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if isinstance(payload.get("agents"), list):
        return True
    data = payload.get("data")
    return isinstance(data, dict) and isinstance(data.get("affected_items"), list)


def is_mdm_inventory(payload: Any, *, name: str = "", text: str = "") -> bool:
    """True for Intune/Jamf device inventory. Fleet / Wazuh / osquery stay out."""
    if _looks_fleet(payload) or _looks_wazuh(payload):
        return False
    if isinstance(payload, dict):
        ctx = str(payload.get("@odata.context") or "")
        if "manageddevices" in ctx.lower() or "devicemanagement" in ctx.lower():
            return True
        if isinstance(payload.get("managedDevices"), list):
            return True
        if isinstance(payload.get("computers"), list):
            rows = [c for c in payload["computers"] if isinstance(c, dict)]
            if rows and (rows[0].get("general") or rows[0].get("disk_encryption") or rows[0].get("hardware")):
                return True
        if isinstance(payload.get("computer"), dict) and payload["computer"].get("general"):
            return True
        devices = payload.get("devices") or payload.get("value")
        if isinstance(devices, list) and devices and isinstance(devices[0], dict):
            sample = devices[0]
            return any(
                k in sample
                for k in ("isEncrypted", "complianceState", "encryptionState", "antivirusStatus", "managementState")
            )
    head = (text or "")[:800].lower().replace(" ", "")
    if "devicename" in head or "computername" in head:
        return any(tok in head for tok in ("encryption", "filevault", "bitlocker", "edr", "mdm", "compliance"))
    low_name = (name or "").lower()
    return any(tok in low_name for tok in ("intune", "jamf", "mdm-devices"))


def _device_rows(payload: Any) -> tuple[str, list[dict[str, Any]]]:
    provider = "mdm"
    rows: list[Any] = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        ctx = str(payload.get("@odata.context") or "")
        if "jamf" in ctx.lower() or payload.get("computers") or payload.get("computer"):
            provider = "jamf"
        else:
            provider = "intune"
        if isinstance(payload.get("managedDevices"), list):
            rows = payload["managedDevices"]
        elif isinstance(payload.get("computers"), list):
            rows = payload["computers"]
            provider = "jamf"
        elif isinstance(payload.get("computer"), dict):
            rows = [payload["computer"]]
            provider = "jamf"
        elif isinstance(payload.get("devices"), list):
            rows = payload["devices"]
        elif isinstance(payload.get("value"), list):
            rows = payload["value"]
    return provider, [r for r in rows if isinstance(r, dict)]


def _csv_devices(text: str) -> list[dict[str, Any]]:
    sample = text[:4000]
    dialect = csv.excel
    if "," in sample or ";" in sample or "\t" in sample:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
    reader = csv.DictReader(StringIO(text), dialect=dialect)
    rows: list[dict[str, Any]] = []
    for row in reader:
        if not row:
            continue
        lower = {str(k).strip().lower().replace(" ", ""): (v or "").strip() for k, v in row.items() if k}
        name = (
            lower.get("devicename")
            or lower.get("computername")
            or lower.get("hostname")
            or lower.get("name")
            or ""
        )
        if not name:
            continue
        rows.append(
            {
                "deviceName": name,
                "isEncrypted": lower.get("encryption")
                or lower.get("encrypted")
                or lower.get("filevault")
                or lower.get("bitlocker")
                or "",
                "complianceState": lower.get("compliance") or "",
                "antivirusStatus": lower.get("edr") or lower.get("antivirus") or lower.get("defender") or "",
                "managementState": lower.get("mdmenrollment") or lower.get("mdm") or lower.get("enrollment") or "",
                "operatingSystem": lower.get("os") or lower.get("platform") or "",
            }
        )
    return rows


def parse_mdm_inventory(payload: Any, *, name: str = "", text: str = "") -> dict[str, Any] | None:
    """Return provider + devices + encryption compliance, or None when not MDM."""
    devices_raw: list[dict[str, Any]] = []
    provider = "mdm"
    if text and not (isinstance(payload, (dict, list)) and payload):
        if not is_mdm_inventory({}, name=name, text=text):
            return None
        devices_raw = _csv_devices(text)
        provider = "jamf" if "jamf" in (name or "").lower() or "filevault" in text[:400].lower() else "intune"
    elif is_mdm_inventory(payload, name=name, text=text):
        provider, devices_raw = _device_rows(payload)
    else:
        return None
    devices = []
    for row in devices_raw:
        norm = _normalize_device(row)
        if norm:
            devices.append(norm)
    if not devices:
        return None
    known = [d for d in devices if d.get("encrypted") is not None]
    enc_count = sum(1 for d in known if d.get("encrypted") is True)
    pct = round(100.0 * enc_count / len(known), 1) if known else None
    return {
        "provider": provider,
        "devices": devices,
        "encryption_pct": pct,
        "encrypted_count": enc_count,
        "measured_count": len(known),
        "device_count": len(devices),
    }


def parse_mdm_file(path: Path) -> dict[str, Any] | None:
    raw = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
    if path.suffix.lower() == ".csv":
        return parse_mdm_inventory({}, name=path.name, text=raw)
    stripped = raw.lstrip()
    if stripped[:1] in "{[":
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return None
        return parse_mdm_inventory(payload, name=path.name, text=raw)
    return parse_mdm_inventory({}, name=path.name, text=raw)
