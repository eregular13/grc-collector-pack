"""Append-only POA&M ID ledger. Offline, persistent, never auto-closes.

Fingerprint::

    fp_v1 = sha256("v1|" + source_family + "|" + weakness_key + "|" + asset_key)

``asset_key`` is the EGA- asset UID + PORT (see ``shared.asset_key.asset_key``),
not the lower-cased name. IDs are ``EGP-`` + first 10 hex of fp_v1, upper-cased.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from copy import deepcopy
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from shared.asset_key import (
    alias_display_names,
    asset_host,
    asset_id,
    asset_key,
    display_asset,
    legacy_asset_id_port_key,
    legacy_name_asset_key,
    legacy_port_only_asset_key,
    normalize_weakness_name,
)
from shared.finding_types import extra_dict, finding_type
from shared.io_util import in_dir, out_dir
from shared.kev import (
    collect_cves,
    effective_due,
    fedramp_risk_for_col_r,
    join_kev,
    kev_overdue_on_detection,
    template_due_date,
    KevCatalog,
)
from shared.poam_fields import _to_date
from shared.scan_time import NOT_RECORDED, artifact_detection, merge_detection
from shared.schema import PREFIX, ciso_finding_severity
from shared.vendor_dependency import (
    VD_INVALID_OVERRIDE,
    VD_NO,
    VD_NOT_CLOSED,
    VD_YES,
    canon_yes_no,
    finalize_vendor_fields,
)

LEDGER_IN_REL = Path("poam") / "poam-ledger.json"
LEDGER_OUT_REL = Path("poam") / "poam-ledger.json"
OVERRIDES_REL = Path("poam") / "overrides.csv"

TRACKED_FIELDS = (
    "asset_key",
    "current_scanner_rating",
    "kev_cves",
    "kev_due",
    "vendor_dependency",
    "vd_source",
    "last_vendor_checkin",
    "vendor_product",
    "point_of_contact",
    "remediation_plan",
)

REOPEN_SUFFIX = re.compile(r"-R(\d+)$")
LEDGER_CHAIN_BROKEN = "LEDGER_CHAIN_BROKEN"
LEDGER_LOST = "LEDGER_LOST"
_NMAP_PORT_REF = re.compile(r"^(NMAP-.+-)(\d+)$", re.I)
_NMAP_PORT_PROTO_REF = re.compile(r"^(NMAP-.+-)(\d+)-(tcp|udp|sctp)$", re.I)
_HOST_IN_TITLE = re.compile(
    r"\s+on\s+([A-Za-z0-9_.:\[\]-]+|\d{1,3}(?:\.\d{1,3}){3})\s*$",
    re.I,
)
_UUIDISH = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_HOST_PORT_PROTO_SLUG = re.compile(r".+-\d+-(tcp|udp|sctp)$", re.I)
_IPV4_PORT_SLUG = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}-\d+", re.I)
# Covey pack_drop observation/service row ids (nmap-10-microsoftds-445,
# rustscan-7-tcp-80). Not plugin/check ids. nmap-port-445/tcp is excluded.
_PACK_DROP_ROW_ADAPTERS = frozenset(
    {
        "nmap",
        "rustscan",
        "naabu",
        "nping",
        "unicornscan",
        "httpx",
        "sslscan",
        "tlsx",
        "whatweb",
        "hping3",
        "onesixtyone",
        "nbtscan",
        "braa",
        "ike-scan",
        "svmap",
        "fping",
    }
)
_PACK_DROP_ROW_PORT = re.compile(r"-\d+$")
_NMAP_PORT_CHECK_ID = re.compile(r"^nmap-port-\d+/(tcp|udp|sctp)$", re.I)
_SERVICE_NAMES = frozenset(
    {
        "kerberos",
        "kerberos-sec",
        "msrpc",
        "epmap",
        "microsoft-ds",
        "cifs",
        "smb",
        "ssh",
        "http",
        "https",
        "ftp",
        "telnet",
        "rdp",
        "ms-wbt-server",
        "snmp",
        "tftp",
        "smtp",
        "pop3",
        "imap",
        "dns",
        "ldap",
        "ldaps",
        "mysql",
        "ms-sql-s",
        "postgresql",
        "redis",
        "mongodb",
        "ntp",
        "rpcbind",
        "sunrpc",
        "netbios-ssn",
        "netbios-ns",
        "netbios-dgm",
        "ipp",
        "vnc",
        "nfs",
        "sip",
        "http-proxy",
    }
)


def source_family(rec: dict[str, Any]) -> str:
    src = str(rec.get("source") or "").strip()
    if src in PREFIX:
        return src
    return src or "unknown"


def _tool_tag(rec: dict[str, Any]) -> str:
    extra = extra_dict(rec)
    tool = str(extra.get("tool") or extra.get("scanner") or "").strip().lower()
    if tool:
        return tool
    labels = {str(x).lower() for x in (rec.get("labels") or [])}
    for known in (
        "nessus",
        "trivy",
        "nuclei",
        "nikto",
        "sarif",
        "prowler",
        "greenbone",
        "testssl",
    ):
        if known in labels:
            return known
    return {
        "vuln-scan": "vuln",
        "cloud-prowler": "prowler",
        "inventory-nmap": "nmap",
        "code-secrets": "sast",
        "k8s-kubescape": "k8s",
        "host-wazuh": "wazuh",
        "identity-ad": "ad",
        "easm": "easm",
        "saas-idp": "saas",
    }.get(source_family(rec), source_family(rec))


def strip_asset_from_title(rec: dict[str, Any]) -> str:
    """Drop the display host from a weakness title before any name fallback."""
    name = str(rec.get("name") or rec.get("ref_id") or "finding")
    extra = extra_dict(rec)
    hosts: list[str] = []
    for raw in list(rec.get("assets") or []):
        text = str(raw or "").strip()
        if text:
            hosts.append(text)
            if "." in text:
                hosts.append(text.split(".", 1)[0])
    for key in ("ip", "hostname", "fqdn", "host", "netbios"):
        val = extra.get(key)
        if isinstance(val, (list, tuple)):
            hosts.extend(str(x).strip() for x in val if str(x).strip())
        elif val not in (None, ""):
            hosts.append(str(val).strip())
    ids = extra.get("ids") if isinstance(extra.get("ids"), dict) else {}
    for key in ("ip", "hostname", "fqdn", "netbios"):
        val = ids.get(key)
        if isinstance(val, (list, tuple)):
            hosts.extend(str(x).strip() for x in val if str(x).strip())
        elif val not in (None, ""):
            hosts.append(str(val).strip())
    out = name
    for host in hosts:
        if not host:
            continue
        out = re.sub(rf"\s+on\s+{re.escape(host)}\b", "", out, flags=re.I)
    out = _HOST_IN_TITLE.sub("", out).strip()
    return out or name


def legacy_title_weakness_key(rec: dict[str, Any]) -> str:
    """Pre-check_id / title-derived key. Migration source only."""
    name = normalize_weakness_name(str(rec.get("name") or rec.get("ref_id") or "finding"))
    return f"name:{name}"


def legacy_master_weakness_key(rec: dict[str, Any]) -> str:
    """Pre-#161 key: extra.id|rule|check_id, else CVE, else title. Migration only."""
    extra = extra_dict(rec)
    scanner_id = ""
    for key in ("id", "rule", "check_id"):
        val = str(extra.get(key) or "").strip()
        if val:
            scanner_id = val
            break
    tool = _tool_tag(rec)
    if scanner_id:
        return f"{tool}:{scanner_id}"
    cves = collect_cves(rec)
    extra_cve = str(extra.get("cve") or "").strip()
    if extra_cve and cves:
        return f"cve:{cves[0]}"
    return legacy_title_weakness_key(rec)


def _is_literal_host_port_slug(text: str) -> bool:
    """True for observation host/IP slugs, not FIRE-4590 / C-0013 / OIDs."""
    if _IPV4_PORT_SLUG.match(text):
        return True
    if _HOST_PORT_PROTO_SLUG.match(text):
        return True
    return False


def _is_pack_drop_row_id(val: str) -> bool:
    """True for Covey row ids that must not become weakness identity.

    ``nmap-10-microsoftds-445`` / ``rustscan-7-tcp-80`` are lift keys.
    ``nmap-port-445/tcp`` is the stable XML/check id and stays accepted.
    """
    text = str(val or "").strip()
    if not text or _NMAP_PORT_CHECK_ID.match(text):
        return False
    prefix, sep, rest = text.lower().partition("-")
    if not sep or prefix not in _PACK_DROP_ROW_ADAPTERS:
        return False
    return bool(_PACK_DROP_ROW_PORT.search(rest))


def _nmap_port_weakness_key(port: str, proto: str) -> str:
    proto_n = proto if proto in {"tcp", "udp", "sctp"} else "tcp"
    return f"nmap:nmap-port-{port}/{proto_n}"


def _is_scanner_identity(val: str) -> bool:
    """True for plugin/check ids. Denylist: service names, obs-*, UUIDs, host/IP slugs, pack_drop row ids."""
    text = str(val or "").strip()
    if not text or "<" in text or text.endswith(">"):
        return False
    if _UUIDISH.match(text):
        return False
    lowered = text.lower()
    if lowered in _SERVICE_NAMES:
        return False
    if lowered.startswith("obs-") or lowered.startswith("observation"):
        return False
    if _is_literal_host_port_slug(text):
        return False
    if _is_pack_drop_row_id(text):
        return False
    return True
