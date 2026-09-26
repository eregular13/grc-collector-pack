"""FedRAMP SSP Appendix M Integrated Inventory Workbook export (spec §5.5).

Headers equal S22 row 2 B..Z verbatim, including the trailing space on
``End-of-Life ``. Blank cells, never ``N/A``. Missing mandatory fields
go to ``iiw_gaps.csv``.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from shared.asset_ids import display_uai, extra_dict, id_values
from shared.asset_ledger import AssetLedger, ledger_ids
from shared.io_util import out_dir, redact

# S22 Inventory tab row 2, columns B→Z. Trailing space on End-of-Life is required.
IIW_HEADERS: tuple[str, ...] = (
    "UNIQUE ASSET IDENTIFIER",
    "IPv4 or IPv6 Address",
    "Virtual",
    "Public",
    "DNS Name or URL",
    "NetBIOS Name",
    "MAC Address",
    "Authenticated Scan",
    "Baseline Configuration Name",
    "OS Name and Version",
    "Location",
    "Asset Type",
    "Hardware Make/Model",
    "In Latest Scan",
    "Software/ Database Vendor",
    "Software/ Database Name & Version",
    "Patch Level",
    "Diagram Label",
    "Comments",
    "Serial #/Asset Tag#",
    "VLAN/ Network ID",
    "System Administrator/ Owner",
    "Application Administrator/ Owner",
    "Function",
    "End-of-Life ",
)

GAPS_HEADERS: tuple[str, ...] = (
    "asset_uid",
    "uai",
    "field",
    "reason",
)

# Mandatory (row 5) for OS/Infra and containers — we cannot invent these.
_MANDATORY_WHEN_HOST = (
    ("IPv4 or IPv6 Address", "C"),
    ("Virtual", "D"),
    ("Public", "E"),
    ("Baseline Configuration Name", "J"),
    ("OS Name and Version", "K"),
    ("Asset Type", "M"),
    ("Hardware Make/Model", "N"),
    ("In Latest Scan", "O"),
    ("Diagram Label", "S"),
    ("Function", "Y"),
)


def _nl(values: list[str]) -> str:
    return "\n".join(v for v in values if v)


def _yes_no(value: Any) -> str:
    if value is True or str(value).strip().lower() in {"yes", "y", "true", "1"}:
        return "Yes"
    if value is False or str(value).strip().lower() in {"no", "n", "false", "0"}:
        return "No"
    return ""


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    if text.strip().lower() in {"n/a", "na", "none"}:
        return ""
    return text


def iiw_row(asset: dict[str, Any], *, in_latest: bool) -> tuple[list[str], list[list[str]]]:
    ids = ledger_ids(asset)
    extra_iiw = asset.get("iiw") if isinstance(asset.get("iiw"), dict) else {}
    uai = str(asset.get("uai") or extra_iiw.get("pin_uai") or display_uai(ids) or "")
    ips = id_values(ids, "ip")
    # Multi-IP: FQDN/image/ARN → one row, IPs newline-separated.
    # IP-as-UAI → still one row here; caller may fan out.
    comments = f"asset_uid={asset.get('asset_uid') or ''}"
    aliases = []
    for alias in asset.get("aliases") or []:
        if isinstance(alias, dict) and not alias.get("valid_to"):
            aliases.append(f"{alias.get('type')}={alias.get('value')}")
    if aliases:
        comments += "; aliases=" + ",".join(aliases[:24])
    auth = ""
    if any(
        str(a.get("type")) in {"uuid", "bios_uuid"} and not a.get("valid_to")
        for a in (asset.get("aliases") or [])
        if isinstance(a, dict)
    ):
        auth = "Yes"
    row = [
        _cell(uai),
        _cell(_nl(ips)),
        _cell(_yes_no(extra_iiw.get("virtual")) or ("Yes" if ids.get("arn") else "")),
        _cell(_yes_no(extra_iiw.get("public"))),
        _cell(ids.get("fqdn") or extra_iiw.get("dns") or ""),
        _cell(ids.get("netbios") or ""),
        _cell(_nl(id_values(ids, "mac"))),
        _cell(auth or extra_iiw.get("authenticated") or ""),
        _cell(extra_iiw.get("baseline") or ""),
        _cell(extra_iiw.get("os") or ""),
        _cell(extra_iiw.get("location") or ""),
        _cell(extra_iiw.get("asset_type") or ("Container" if asset.get("ephemeral") and ids.get("image_ref") else "")),
        _cell(extra_iiw.get("hw_model") or ""),
        _cell("Yes" if in_latest else ""),
        _cell(extra_iiw.get("sw_vendor") or ""),
        _cell(extra_iiw.get("sw_name") or ""),
        _cell(extra_iiw.get("patch") or ""),
        _cell(extra_iiw.get("diagram_label") or ""),
        _cell(comments),
        _cell(ids.get("serial") or extra_iiw.get("serial") or ""),
        _cell(extra_iiw.get("vlan") or ids.get("scope") or ""),
        _cell(extra_iiw.get("owner_sys") or ""),
        _cell(extra_iiw.get("owner_app") or ""),
        _cell(extra_iiw.get("function") or ""),
        _cell(extra_iiw.get("eol") or ""),
    ]
    gaps: list[list[str]] = []
    uid = str(asset.get("asset_uid") or "")
    if not uai:
        gaps.append([uid, uai, "UNIQUE ASSET IDENTIFIER", "missing UAI"])
    for header, _col in _MANDATORY_WHEN_HOST:
        idx = IIW_HEADERS.index(header)
        if not str(row[idx] or "").strip():
            gaps.append([uid, uai, header, "mandatory blank"])
    if any(str(c).strip().lower() in {"n/a", "na"} for c in row):
        gaps.append([uid, uai, "N/A", "forbidden token"])
    return row, gaps


def write_iiw(
    ledger: AssetLedger,
    *,
    dest_dir: Path | None = None,
    observed: set[str] | None = None,
) -> dict[str, Path]:
    folder = Path(dest_dir) if dest_dir is not None else out_dir() / "iiw"
    folder.mkdir(parents=True, exist_ok=True)
    inv = folder / "iiw_inventory.csv"
    gaps_path = folder / "iiw_gaps.csv"
    seen_uai: set[str] = set()
    rows: list[list[str]] = []
    gaps: list[list[str]] = []
    observed = observed if observed is not None else set()
    # One row per asset_uid, or per class_uid for ephemeral/containers.
    emitted_class: set[str] = set()
    for asset in ledger.assets.values():
        if asset.get("status") == "merged":
            continue
        class_uid = str(asset.get("class_uid") or "")
        if asset.get("ephemeral") and class_uid:
            if class_uid in emitted_class:
                continue
            emitted_class.add(class_uid)
        uai = str(asset.get("uai") or "")
        ids = ledger_ids(asset)
        ips = id_values(ids, "ip")
        in_latest = str(asset.get("asset_uid") or "") in observed or asset.get("status") == "active"
        if uai and not ids.get("fqdn") and not ids.get("image_ref") and not ids.get("arn") and len(ips) > 1:
            # UAI is an IP: one row per IP (S22 C3).
            for ip in ips:
                clone = dict(asset)
                clone["uai"] = ip
                row, row_gaps = iiw_row(clone, in_latest=bool(in_latest))
                row[0] = ip
                row[1] = ip
                if ip in seen_uai:
                    continue
                seen_uai.add(ip)
                rows.append(row)
                gaps.extend(row_gaps)
            continue
        row, row_gaps = iiw_row(asset, in_latest=bool(in_latest))
        token = row[0]
        if token and token in seen_uai:
            gaps.append([str(asset.get("asset_uid") or ""), token, "UNIQUE ASSET IDENTIFIER", "duplicate UAI"])
            continue
        if token:
            seen_uai.add(token)
        rows.append(row)
        gaps.extend(row_gaps)
    with inv.open("w", encoding="utf-8", newline="") as fh:
        # Raw header so ``End-of-Life `` keeps its trailing space (S22 row 2).
        fh.write(",".join(IIW_HEADERS) + "\n")
        writer = csv.writer(fh, lineterminator="\n")
        for row in rows:
            writer.writerow([redact(c) if isinstance(c, str) else c for c in row])
    with gaps_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(list(GAPS_HEADERS))
        for row in gaps:
            writer.writerow(row)
    return {"inventory": inv, "gaps": gaps_path}


def poam_h_value(uai: str, port: Any = "", proto: Any = "") -> str:
    """FedRAMP H display: UAI plus `` (port/PROTO)`` when a port is present."""
    base = str(uai or "").strip()
    p = str(port or "").strip()
    if not base:
        return ""
    if p and p != "0":
        pr = str(proto or "TCP").strip().upper() or "TCP"
        return f"{base} ({p}/{pr})"
    return base


def finding_uais(rec: dict[str, Any], ledger: AssetLedger | None = None) -> list[str]:
    extra = extra_dict(rec)
    uid = str(extra.get("asset_uid") or "")
    uai = ""
    if ledger and uid and uid in ledger.assets:
        uai = str(ledger.assets[uid].get("uai") or "")
    uai = uai or str(extra.get("uai") or "")
    port = extra.get("port")
    proto = extra.get("protocol") or extra.get("proto") or extra.get("service") and "TCP"
    if uai:
        return [poam_h_value(uai, port, proto if str(proto).isalpha() else "TCP")]
    return [poam_h_value(str(a), port, extra.get("protocol") or "TCP") for a in (rec.get("assets") or []) if a]
