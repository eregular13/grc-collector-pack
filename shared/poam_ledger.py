"""Append-only POA&M ID ledger. Offline, persistent, never auto-closes.

Fingerprint::

    fp_v1 = sha256("v1|" + source_family + "|" + weakness_key + "|" + asset_key)

``asset_key`` is the EGA- asset UID + PORT (see ``shared.asset_key.asset_key``),
not the lower-cased name. IDs are ``EGP-`` + first 10 hex of fp_v1, upper-cased.
Unknown Custodian needs-review rows roll up per policy+account as ``EGR-``
+ first 10 hex of ``egr_key(policy, account)`` — not resource order.
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
_PACK_DROP_HOST_INDEX = re.compile(
    r"^(" + "|".join(sorted(_PACK_DROP_ROW_ADAPTERS)) + r")-[a-z]?\d+-",
    re.I,
)
_NMAP_PORT_CHECK_ID = re.compile(r"^nmap-port-\d+/(tcp|udp|sctp)$", re.I)
_OPEN_PORT_OBSERVED = re.compile(
    r"^open(?:\s+[a-z0-9._/-]+(?:\s+on)?)?\s+(?:tcp|udp|sctp)/\d+\s+observed$",
    re.I,
)
_OPEN_PORT_N = re.compile(
    r"^open\s+port\s+\d+(?:/[a-z0-9._-]+)?$",
    re.I,
)
_PORT_EXPOSURE_TITLE = re.compile(
    r"^[a-z0-9._/+-]+(?:\s+\d+(?:/(?:tcp|udp|sctp))?)?(?:\s+[a-z0-9._/+-]+)?\s+exposed$",
    re.I,
)
_NOT_PORT_EXPOSURE_TITLE = re.compile(
    r"share|signing|protocol|enabled|required|directory|\.git|cipher|smbv1|tls\s+\d",
    re.I,
)
_URL_IN_TEXT = re.compile(r"https?://[^\s<>()\[\]'\",;]+", re.I)
_TRAILING_LOC = ").,;:\"'"
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


def _strip_pack_drop_host_index(row_id: str) -> str:
    """nmap-10-microsoftds-445 → nmap-microsoftds-445. Empty when not a row id."""
    text = str(row_id or "").strip()
    if not text or not _is_pack_drop_row_id(text):
        return ""
    return _PACK_DROP_HOST_INDEX.sub(r"\1-", text, count=1)


def _is_port_exposure_observation(rec: dict[str, Any]) -> bool:
    """True only for open-port / '{svc} {port} exposed' rows.

    Specific findings on the same host/port (SMBv1, TLS 1.0, .git) stay distinct.
    """
    name = strip_asset_from_title(rec)
    if _NOT_PORT_EXPOSURE_TITLE.search(name):
        return False
    extra = extra_dict(rec)
    if _extra_field(extra, "claim").lower() == "open_port_observed":
        return True
    if str(rec.get("kind") or "").strip().lower() == "observation":
        return True
    if _OPEN_PORT_OBSERVED.match(name) or _OPEN_PORT_N.match(name):
        return True
    return bool(_PORT_EXPOSURE_TITLE.match(name))


def _pack_drop_specific_port_key(
    rec: dict[str, Any],
    *,
    port: str,
    proto: str,
    token: str,
    title: str,
) -> str:
    """Keep a discriminator so SMBv1 ≠ SMB 445 exposed on the same port."""
    cls = finding_type(rec) or str(rec.get("category") or "exposure")
    proto_n = proto if proto in {"tcp", "udp", "sctp"} else "tcp"
    disc = token or title or _strip_pack_drop_host_index(_extra_field(extra_dict(rec), "id"))
    if not disc:
        disc = "specific"
    return f"port:{port}/{proto_n}:{cls.lower()}:{disc}"


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


def _extra_field(extra: dict[str, Any], key: str) -> str:
    raw = extra.get(key)
    if raw is None or raw == "":
        return ""
    return str(raw).strip()


def _title_discriminator(rec: dict[str, Any]) -> str:
    """Host-stripped title so two unkeyed findings on one asset stay distinct."""
    name = normalize_weakness_name(strip_asset_from_title(rec))
    if name and name not in {"finding", "unknown"}:
        return f"name:{name}"
    return ""


def _extra_identity_token(rec: dict[str, Any]) -> str:
    """Non-title token so two findings on one asset do not share a class-only key."""
    extra = extra_dict(rec)
    # Join record/stage/event so Palisade stage-1 hit ≠ same-stage session.
    disc_keys = (
        "finding_id",
        "stage",
        "event",
        "record",
        "record_type",
        "selector",
        "RuleID",
        "rule_id",
        "agent_status",
        "disk_encryption_enabled",
    )
    bits: list[str] = []
    for key in disc_keys:
        val = _extra_field(extra, key)
        if val:
            bits.append(f"{key}:{val}")
    if bits:
        return "|".join(bits)
    for key in (
        "edge",
        "relationship",
        "objectid",
        "object_id",
        "finding",
        "control_id",
        "plugin_name",
        "check",
        "nse_script",
        "template_id",
        "role",
        "policy",
        "user_type",
        "result",
    ):
        val = _extra_field(extra, key)
        if val and _is_scanner_identity(val):
            return f"{key}:{val}"
    return ""


_LOCATION_KEYS = (
    "path",
    "url",
    "file",
    "line",
    "user",
    "evidence",
    "evidence_ref",
    "cmd",
    "command",
)


def _location_suffix(rec: dict[str, Any]) -> str:
    """Path/url/file/line/user/evidence (and cmd/service) when present.

    Same-title fallback rows on one asset stay distinct. CVE keys omit this.
    """
    extra = extra_dict(rec)
    bits: list[str] = []
    seen: set[str] = set()
    for key in _LOCATION_KEYS:
        val = _extra_field(extra, key)
        if not val:
            continue
        token = f"{key}:{val.lower()}"
        if token not in seen:
            seen.add(token)
            bits.append(token)
    port = _extra_field(extra, "port")
    has_plugin = False
    for key in ("check_id", "plugin_id", "nse_script", "template_id", "rule", "finding_id", "id"):
        val = _extra_field(extra, key)
        if val and _is_scanner_identity(val):
            has_plugin = True
            break
    if (not port or port == "0") and not has_plugin:
        svc = _extra_field(extra, "service")
        if svc:
            token = f"service:{svc.lower()}"
            if token not in seen:
                bits.append(token)
    return "|".join(bits)


def _wazuh_host_segment(raw: str) -> str:
    """First DNS label, lowercased. ``hosta.corp.local`` → ``hosta``. IPs stay whole."""
    text = str(raw or "").strip().lower().rstrip(".")
    if not text:
        return ""
    token = text.split()[0]
    if not token:
        return ""
    if token[0].isdigit() or ":" in token:
        return token
    return token.split(".", 1)[0]


def _wazuh_raw_host(rec: dict[str, Any]) -> str:
    """Finding's own host/agent string before first-segment fold."""
    extra = extra_dict(rec)
    assets = [str(a).strip() for a in (rec.get("assets") or []) if str(a).strip()]
    if assets:
        return assets[0].split()[0].lower().rstrip(".")
    for key in ("agent", "hostname", "host"):
        val = _extra_field(extra, key)
        if val:
            return val.split()[0].lower().rstrip(".")
    ids = extra.get("ids") if isinstance(extra.get("ids"), dict) else {}
    for key in ("agent", "hostname"):
        val = str(ids.get(key) or "").strip()
        if val:
            return val.split()[0].lower().rstrip(".")
    return ""


def _is_dns_fqdn(raw: str) -> bool:
    text = str(raw or "").strip().lower().rstrip(".")
    if not text:
        return False
    token = text.split()[0]
    if not token or token[0].isdigit() or ":" in token:
        return False
    return "." in token


def _wazuh_host_token(rec: dict[str, Any]) -> str:
    """Finding's own host/agent — first name segment, not a ledger-merged hostname."""
    return _wazuh_host_segment(_wazuh_raw_host(rec))


def _stored_wazuh_hosts(item: dict[str, Any]) -> set[str]:
    """Host tokens from the stored display/host field only — never the title."""
    display = str(item.get("display_asset") or "").strip()
    if not display:
        return set()
    seg = _wazuh_host_segment(display)
    return {seg} if seg else set()


def _wazuh_hostless_item_matches(rec: dict[str, Any], item: dict[str, Any]) -> bool:
    """True only when the stored host-less Wazuh row is this incoming host.

    First-segment match covers short↔FQDN (``hosta`` / ``hosta.corp.local``).
    When both stored display and incoming host are FQDNs, require the full
    name so ``web01.corp-a.local`` cannot absorb ``web01.corp-b.local``.
    """
    incoming = _wazuh_raw_host(rec)
    display = str(item.get("display_asset") or "").strip()
    if not incoming or not display:
        return False
    parts = display.split()
    if not parts:
        return False
    stored = parts[0].lower().rstrip(".")
    if not stored:
        return False
    if _is_dns_fqdn(incoming) and _is_dns_fqdn(stored):
        return incoming == stored
    return _wazuh_host_segment(incoming) == _wazuh_host_segment(stored)


def _find_stored_wazuh_by_display(
    rec: dict[str, Any], items: dict[str, Any]
) -> list[tuple[str, dict[str, Any]]]:
    """Host-less Wazuh rows whose stored display first-segment is this host.

    29c4c3e keyed host-less; a later short-name vs FQDN observation may land on a
    different EGA. Match ``display_asset`` only — never title — so hostb cannot
    steal hosta's EGP.
    """
    extra = extra_dict(rec)
    if extra.get("agent_status") in (None, "") and extra.get("disk_encryption_enabled") in (
        None,
        "",
    ):
        return []
    hostless = _weakness_key_core(rec)
    if not hostless or hostless == weakness_key(rec):
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    for old_fp, item in items.items():
        if str(item.get("status") or "") == "closed":
            continue
        if str(item.get("weakness_key") or "") != hostless:
            continue
        if _wazuh_hostless_item_matches(rec, item):
            out.append((old_fp, item))
    incoming = _wazuh_raw_host(rec)
    if incoming and not _is_dns_fqdn(incoming):
        fqdn_hits = [
            pair
            for pair in out
            if _is_dns_fqdn(str(pair[1].get("display_asset") or ""))
        ]
        # Bare web01 vs two stored FQDNs is ambiguous — mint a new ID.
        if len(fqdn_hits) >= 2:
            return []
    return out


def _attach_wazuh_host(rec: dict[str, Any], key: str) -> str:
    """Keep host/agent on Wazuh coverage keys so IP-joined EGAs stay two EGPs."""
    if _tool_tag(rec) != "wazuh":
        return key
    extra = extra_dict(rec)
    if extra.get("agent_status") in (None, "") and extra.get("disk_encryption_enabled") in (
        None,
        "",
    ):
        return key
    host = _wazuh_host_token(rec)
    if not host:
        return key
    suffix = f":{host}"
    if key.lower().endswith(suffix):
        return key
    return f"{key}{suffix}"


def _weakness_key_core(rec: dict[str, Any]) -> str:
    """Pre-location / pre-host-suffix key. Migration source only."""
    extra = extra_dict(rec)
    tool = _tool_tag(rec)
    for key in ("check_id", "plugin_id", "nse_script", "template_id", "rule", "finding_id"):
        val = _extra_field(extra, key)
        if val and _is_scanner_identity(val):
            return f"{tool}:{val}"
    scanner_id = _extra_field(extra, "id")
    if scanner_id and _is_scanner_identity(scanner_id):
        return f"{tool}:{scanner_id}"
    share = _extra_field(extra, "share")
    if share:
        return f"{tool}:share:{share.lower()}"
    port = _extra_field(extra, "port")
    proto = (_extra_field(extra, "protocol") or _extra_field(extra, "proto")).lower()
    token = _extra_identity_token(rec)
    title = _title_discriminator(rec)
    adapter = _extra_field(extra, "adapter").lower()
    port_exposure = bool(port and port != "0" and _is_port_exposure_observation(rec))
    if (
        port_exposure
        and adapter in {"", "nmap"}
        and (tool == "nmap" or source_family(rec) == "inventory-nmap")
    ):
        # pack_drop extra.id is not identity; same host/port as XML nmap-port-*.
        return _nmap_port_weakness_key(port, proto)
    if port_exposure and adapter in _PACK_DROP_ROW_ADAPTERS:
        proto_n = proto if proto in {"tcp", "udp", "sctp"} else "tcp"
        return f"{adapter}:port:{port}/{proto_n}"
    if port and port != "0" and adapter in _PACK_DROP_ROW_ADAPTERS and not port_exposure:
        return _pack_drop_specific_port_key(
            rec, port=port, proto=proto, token=token, title=title
        )
    if port and port != "0":
        cls = finding_type(rec) or str(rec.get("category") or "exposure")
        if token:
            return f"port:{port}/{proto or 'tcp'}:{cls.lower()}:{token}"
        return f"port:{port}/{proto or 'tcp'}:{cls.lower()}"
    cves = collect_cves(rec)
    extra_cve = _extra_field(extra, "cve")
    if extra_cve and cves:
        return f"cve:{cves[0]}"
    ftype = finding_type(rec)
    if ftype and ftype not in {"", "unknown"}:
        if token:
            if token.startswith(("role:", "policy:", "user_type:", "result:")) and title:
                return f"class:{ftype}:{token}:{title}"
            return f"class:{ftype}:{token}"
        if title:
            return f"class:{ftype}:{title}"
    if extra.get("mfa_registered") is False:
        return f"{tool}:mfa_unregistered"
    if token:
        if token.startswith(("role:", "policy:", "user_type:", "result:")) and title:
            return f"{tool}:{token}:{title}"
        return f"{tool}:{token}"
    bits: list[str] = []
    for key in ("role", "policy", "user_type", "result", "product"):
        val = extra.get(key)
        if val not in (None, ""):
            bits.append(f"{key}:{str(val).lower()}")
    if bits:
        if title:
            return f"{tool}:{'|'.join(bits)}:{title}"
        return f"{tool}:{'|'.join(bits)}"
    if title:
        return f"{tool}:{title}"
    ref = str(rec.get("ref_id") or "").strip()
    if ref:
        return f"{tool}:ref:{ref}"
    return f"{tool}:unkeyed"


def legacy_pre_location_weakness_key(rec: dict[str, Any]) -> str:
    """#161 fallback key before path/url/file/line/user/evidence. Migration only."""
    return _weakness_key_core(rec)


def weakness_key(rec: dict[str, Any]) -> str:
    """Stable weakness identity: scanner id, share, port+class, then location."""
    core = _weakness_key_core(rec)
    if not core.startswith("cve:"):
        loc = _location_suffix(rec)
        if loc:
            core = f"{core}:{loc}"
    return _attach_wazuh_host(rec, core)


def fp_v1(
    rec: dict[str, Any],
    *,
    asset_key_fn=asset_key,
    weakness_key_fn=None,
) -> str:
    wk = (weakness_key_fn or weakness_key)(rec)
    payload = "v1|" + source_family(rec) + "|" + wk + "|" + asset_key_fn(rec)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def migrate_finding_refs(ref: str) -> list[str]:
    """Historically equivalent nmap ref slugs (``-445`` ↔ ``-445-tcp``)."""
    text = str(ref or "").strip()
    if not text:
        return []
    out = [text]
    proto = _NMAP_PORT_PROTO_REF.match(text)
    if proto:
        out.append(f"{proto.group(1)}{proto.group(2)}")
    bare = _NMAP_PORT_REF.match(text)
    if bare:
        out.append(f"{bare.group(1)}{bare.group(2)}-tcp")
    return list(dict.fromkeys(out))


def legacy_master_asset_key(rec: dict[str, Any]) -> str:
    """Pre-#161 EGA- key: UPN as FQDN, cloud short names as hostname, no scope.

    Master's ``ega_asset_id`` keyed the first asset (or extra host/arn/fqdn),
    never the finding title. Titles such as ``Write below binary dir`` classify
    as NetBIOS under ``classify_name_pre161`` and must not steal the cluster
    hostname. Current ``extra.ids`` may carry principal/scope — ignore them.
    """
    from shared.asset_ids import (
        classify_name_pre161,
        extra_dict as ids_extra,
        merge_ids,
        strongest_anchor,
    )
    from shared.asset_ledger import make_asset_uid
    from shared.asset_key import _port_proto

    extra = ids_extra(rec)
    assets = [a for a in (rec.get("assets") or []) if str(a).strip()]
    name = assets[0] if assets else (
        extra.get("host") or extra.get("arn") or extra.get("fqdn") or extra.get("hostname") or ""
    )
    lifted: dict[str, Any] = {}
    for key in (
        "ip",
        "mac",
        "fqdn",
        "hostname",
        "arn",
        "uuid",
        "bios_uuid",
        "agent",
        "netbios",
        "host",
    ):
        if extra.get(key) not in (None, ""):
            lifted[key] = extra.get(key)
    parts = [lifted, classify_name_pre161(name)]
    if assets:
        parts.append(classify_name_pre161(assets[0]))
    ids = merge_ids(*parts)
    typ, value = strongest_anchor(ids, skip={"principal"})
    uid = make_asset_uid(typ, value)
    suffix = _port_proto(rec)
    return f"{uid}{suffix}" if uid else suffix.lstrip(":")


def fingerprints_for(rec: dict[str, Any]) -> list[str]:
    """Current fp plus every legacy alias this row may have been stored under."""
    out = [fp_v1(rec)]
    for old_fp, _reason in _legacy_fps_for(rec):
        if old_fp:
            out.append(old_fp)
    return list(dict.fromkeys(out))


def item_maps_to_current(
    item: dict[str, Any],
    *,
    listed_ids: set[str],
    observed_refs: set[str],
    observed_fps: set[str],
) -> bool:
    """True when a carried ledger item is the same weakness as a current row."""
    pid = str(item.get("poam_id") or "")
    if pid and pid in listed_ids:
        return True
    fp = str(item.get("fp") or "")
    if fp and fp in observed_fps:
        return True
    ref = str(item.get("ref_id") or "")
    for cand in migrate_finding_refs(ref):
        if cand in observed_refs:
            return True
        for obs in observed_refs:
            if cand in migrate_finding_refs(obs):
                return True
    return False


def excluded_reason_for(rec: dict[str, Any]) -> str:
    """Why this finding is off the POA&M, or empty when it stays on."""
    from shared.control_map import poam_decision

    decision = poam_decision(rec)
    if decision.get("include"):
        return ""
    return str(decision.get("reason") or "unexplained")


def item_is_excluded(item: dict[str, Any]) -> bool:
    """True when a ledger item was recorded as excluded, not an open weakness."""
    return bool(str(item.get("excluded_reason") or "").strip())


def persist_ledger(ledger: dict[str, Any], out_root: Path | None = None) -> Path:
    """Rewrite out/poam/poam-ledger.json after in-memory stamps."""
    ledger["sha256"] = payload_sha256(ledger)
    dest = (out_root or out_dir()) / LEDGER_OUT_REL
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(ledger, indent=2, default=str) + "\n", encoding="utf-8")
    return dest


def egr_key(policy: str, account: str) -> str:
    """Stable digest for an EGR- rollup. Policy name + account, not resources."""
    acct = str(account or "").strip() or "unknown"
    payload = f"egr|{str(policy or '').strip().lower()}|{acct}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def is_egr_rollup(rec: dict[str, Any]) -> bool:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    if extra.get("rollup") is True:
        return True
    return str(extra.get("poam_prefix") or "").strip().upper() in {"EGR-", "EGR"}


def _egr_account(rec: dict[str, Any]) -> str:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    acct = str(extra.get("account_id") or "").strip()
    if acct:
        return acct
    assets = [str(a).strip() for a in (rec.get("assets") or []) if str(a).strip()]
    if assets and assets[0].lower().startswith("account:"):
        return assets[0].split(":", 1)[1] or "unknown"
    return "unknown"


def assign_poam_id(fp: str, used: dict[str, str], prefix: str = "EGP-") -> str:
    """EGP-/EGR- + first 10 hex, upper-cased. Collision with a different fp → 12 hex."""
    if prefix not in {"EGP-", "EGR-"}:
        prefix = "EGP-"
    short = prefix + fp[:10].upper()
    holder = used.get(short)
    if holder is None or holder == fp:
        return short
    return prefix + fp[:12].upper()


def next_reopen_id(base_id: str, existing: set[str]) -> str:
    core = REOPEN_SUFFIX.sub("", base_id)
    n = 1
    while f"{core}-R{n}" in existing:
        n += 1
    return f"{core}-R{n}"


def detection_time(rec: dict[str, Any], run_date: date | None = None) -> tuple[date | None, str]:
    """Artifact scan timestamp only. Never the pack run date or collected_at."""
    del run_date
    detected, basis, _tz = artifact_detection(rec)
    return detected, basis


def fan_out_instances(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """One instance per asset. Multi-asset records must not collapse."""
    out: list[dict[str, Any]] = []
    for rec in findings:
        assets = [a for a in (rec.get("assets") or []) if str(a).strip()]
        if len(assets) <= 1:
            out.append(rec)
            continue
        for asset in assets:
            clone = dict(rec)
            clone["assets"] = [asset]
            extra = dict(extra_dict(rec))
            clone["extra"] = extra
            out.append(clone)
    return out


def payload_sha256(doc: dict[str, Any]) -> str:
    body = {
        "items": doc.get("items") or {},
        "closed": doc.get("closed") or [],
        "events": doc.get("events") or [],
        "fp_migrations": doc.get("fp_migrations") or [],
    }
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def empty_ledger() -> dict[str, Any]:
    return {
        "version": 1,
        "prev_sha256": "",
        "sha256": "",
        "warnings": [],
        "items": {},
        "closed": [],
        "events": [],
        "fp_migrations": [],
    }


def load_ledger_file(path: Path) -> tuple[dict[str, Any], list[str]]:
    if not path.is_file():
        return empty_ledger(), [LEDGER_LOST]
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return empty_ledger(), [LEDGER_CHAIN_BROKEN]
    if not isinstance(doc, dict):
        return empty_ledger(), [LEDGER_CHAIN_BROKEN]
    warnings: list[str] = []
    stored = str(doc.get("sha256") or "")
    computed = payload_sha256(doc)
    if stored and stored != computed:
        warnings.append(LEDGER_CHAIN_BROKEN)
    doc.setdefault("items", {})
    doc.setdefault("closed", [])
    doc.setdefault("events", [])
    doc.setdefault("fp_migrations", [])
    doc.setdefault("warnings", [])
    return doc, warnings


def load_overrides(path: Path) -> dict[str, dict[str, str]]:
    if not path.is_file():
        return {}
    out: dict[str, dict[str, str]] = {}
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            poam_id = str(row.get("poam_id") or "").strip()
            if poam_id:
                out[poam_id] = {k: (v if v is not None else "") for k, v in row.items()}
    return out


def _used_ids(ledger: dict[str, Any]) -> dict[str, str]:
    used: dict[str, str] = {}
    for fp, item in (ledger.get("items") or {}).items():
        pid = str(item.get("poam_id") or "")
        if pid:
            used[pid] = fp
    for item in ledger.get("closed") or []:
        pid = str(item.get("poam_id") or "")
        if pid:
            used[pid] = str(item.get("fp") or "")
    return used


def _existing_id_set(ledger: dict[str, Any]) -> set[str]:
    return set(_used_ids(ledger))


def _event(run_iso: str, fp: str, poam_id: str, kind: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "at": run_iso,
        "fp": fp,
        "poam_id": poam_id,
        "kind": kind,
        "detail": detail or {},
    }


def _iso_date(raw: Any) -> str:
    got = _to_date(raw)
    return got.isoformat() if got else ""


def _new_item(
    rec: dict[str, Any],
    *,
    fp: str,
    poam_id: str,
    run_date: date,
    run_iso: str,
    kev: dict[str, Any],
    catalog_sha: str,
) -> dict[str, Any]:
    detected, basis = detection_time(rec, run_date)
    rating = fedramp_risk_for_col_r(rec.get("severity"))
    scanner = ciso_finding_severity(rec.get("severity"))
    kev_due = kev.get("kev_due")
    if detected is not None:
        tmpl = template_due_date(detected, rec.get("severity"))
        eff = effective_due(tmpl, kev_due)
        template_s = tmpl.isoformat()
        effective_s = (eff or tmpl).isoformat()
        odd = detected.isoformat()
    else:
        tmpl = None
        template_s = ""
        effective_s = kev_due.isoformat() if kev_due else ""
        odd = NOT_RECORDED
        basis = "not_recorded"
    return {
        "poam_id": poam_id,
        "fp": fp,
        "source_family": source_family(rec),
        "weakness_key": weakness_key(rec),
        "asset_key": asset_key(rec),
        "display_asset": display_asset(rec),
        "cves": list(kev.get("cves") or []),
        "kev_cves": list(kev.get("kev_cves") or []),
        "kev_due": kev_due.isoformat() if kev_due else "",
        "kev_catalog_sha256": catalog_sha,
        "kev_tracking": kev.get("tracking") or "",
        "kev_comments": list(kev.get("comments") or []),
        "first_seen": run_iso,
        "last_seen": run_iso,
        "original_detection_date": odd,
        "detection_date_basis": basis,
        "original_risk_rating": rating,
        "current_scanner_rating": scanner,
        "scanner_critical": scanner == "critical",
        "status": "open",
        "excluded_reason": "",
        "status_date": run_date.isoformat(),
        "closed_date": "",
        "closure_evidence": [],
        "vendor_dependency": "No",
        "vd_source": "default",
        "last_vendor_checkin": "",
        "vendor_product": "",
        "vd_comments": [],
        "vd_flags": [],
        "point_of_contact": "",
        "remediation_plan": "",
        "prior_poam_id": "",
        "missed_covered_runs": 0,
        "missed_dates": [],
        "effective_due": effective_s,
        "template_due": template_s,
        "kev_overdue_on_detection": kev_overdue_on_detection(detected, kev_due),
        "name": str(rec.get("name") or rec.get("ref_id") or ""),
        "description": str(rec.get("description") or rec.get("name") or ""),
        "ref_id": str(rec.get("ref_id") or ""),
        "severity": scanner,
    }


def _tracked_snapshot(item: dict[str, Any]) -> dict[str, Any]:
    return {k: item.get(k) for k in TRACKED_FIELDS}


VD_AUDIT_FIELDS = (
    "vendor_dependency",
    "vd_source",
    "last_vendor_checkin",
    "vendor_product",
)


def _vd_snapshot(item: dict[str, Any]) -> dict[str, Any]:
    return {k: item.get(k) for k in VD_AUDIT_FIELDS}


def _vd_is_schema_backfill(before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Pre-#160 rows lack vendor fields. Filling No/default is not a change."""
    if str(before.get("vendor_dependency") or "").strip():
        return False
    if str(before.get("vd_source") or "").strip():
        return False
    return (
        after.get("vendor_dependency") == VD_NO
        and after.get("vd_source") == "default"
        and not str(after.get("last_vendor_checkin") or "").strip()
        and not str(after.get("vendor_product") or "").strip()
    )


def _apply_override(
    item: dict[str, Any], override: dict[str, str], run_date: date
) -> tuple[list[str], list[str]]:
    changed: list[str] = []
    warns: list[str] = []
    mapping = {
        "vendor_dependency": "vendor_dependency",
        "last_vendor_checkin": "last_vendor_checkin",
        "vendor_product": "vendor_product",
        "point_of_contact": "point_of_contact",
        "remediation_plan": "remediation_plan",
    }
    for src, dest in mapping.items():
        if src not in override or override[src] == "":
            continue
        val = override[src]
        if dest == "vendor_dependency":
            canon = canon_yes_no(val)
            if canon is None:
                warns.append(
                    f"{VD_INVALID_OVERRIDE}:{item.get('poam_id')}:{val}"
                )
                continue
            val = canon
            if item.get("vd_source") != "operator":
                item["vd_source"] = "operator"
                changed.append("vd_source")
        if val != item.get(dest):
            item[dest] = val
            changed.append(dest)
    return changed, warns


def _already_mapped(ledger: dict[str, Any], src_fp: str, dest_fp: str, poam_id: str = "") -> bool:
    for row in ledger.get("fp_migrations") or []:
        if row.get("from") == src_fp and row.get("to") == dest_fp:
            if not poam_id or str(row.get("poam_id") or "") == poam_id:
                return True
    return False


def _record_fp_migration(
    ledger: dict[str, Any],
    *,
    src_fp: str,
    dest_fp: str,
    poam_id: str,
    odd: str,
    reason: str,
    alias_of: str = "",
) -> None:
    if _already_mapped(ledger, src_fp, dest_fp, poam_id):
        return
    row = {
        "from": src_fp,
        "to": dest_fp,
        "poam_id": poam_id,
        "original_detection_date": odd,
        "reason": reason,
    }
    if alias_of:
        row["alias_of"] = alias_of
    ledger.setdefault("fp_migrations", []).append(row)


def _legacy_alias_records(rec: dict[str, Any]) -> list[dict[str, Any]]:
    extras = extra_dict(rec)
    fakes: list[dict[str, Any]] = []
    for name in alias_display_names(rec) or [""]:
        fake = dict(rec)
        fake["assets"] = [name] if name else list(rec.get("assets") or [])
        if name:
            fake["name"] = name
        fake_extra = dict(extras)
        fake_extra.pop("asset_uid", None)
        fake["extra"] = fake_extra
        fakes.append(fake)
    return fakes


def _legacy_port_only_allowed(rec: dict[str, Any]) -> bool:
    """Port-only keys defaulted to TCP. Do not let UDP steal a TCP item."""
    extra = extra_dict(rec)
    proto = str(extra.get("protocol") or extra.get("proto") or "tcp").strip().lower()
    return proto == "tcp"


_NMAP_PORT_CHECK_RE = re.compile(r"^nmap-port-(\d+)/(tcp|udp|sctp)$", re.I)
_NMAP_DISPLAY_TITLES = {
    ("23", "tcp"): ("Telnet exposed",),
    ("21", "tcp"): ("FTP exposed",),
    ("445", "tcp"): ("SMB 445 exposed",),
    ("3389", "tcp"): ("RDP exposed",),
    ("22", "tcp"): ("SSH exposed",),
    ("80", "tcp"): ("HTTP exposed",),
    ("161", "udp"): ("SNMP 161/udp exposed", "Open port 161/snmp"),
    ("69", "udp"): ("TFTP 69/udp exposed", "Open port 69/tftp"),
}


def _nmap_legacy_title_records(rec: dict[str, Any]) -> list[dict[str, Any]]:
    """Pre-check_id nmap port rows keyed on display title (Metis §15 ID churn)."""
    extra = extra_dict(rec)
    if str(rec.get("source") or "") != "inventory-nmap":
        return []
    check = str(extra.get("check_id") or extra.get("id") or "").strip()
    matched = _NMAP_PORT_CHECK_RE.match(check)
    port = str(extra.get("port") or "").strip()
    proto = str(extra.get("protocol") or extra.get("proto") or "").strip().lower()
    if matched:
        port, proto = matched.group(1), matched.group(2).lower()
    elif check and not check.startswith("nmap-port-"):
        return []
    if not port or proto not in {"tcp", "udp", "sctp"}:
        return []
    svc = str(extra.get("service") or proto or "unknown")
    titles = [
        str(rec.get("name") or ""),
        f"Open port {port}/{svc}",
        f"Open port {port}/{proto}",
        f"Open port {port}/{svc or proto or 'unknown'}",
        f"Open UDP port {port}/{svc}",
        f"Open UDP port {port}/{proto}",
        f"UDP {port} open|filtered (not confirmed open)",
        *_NMAP_DISPLAY_TITLES.get((port, proto), ()),
    ]
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for title in titles:
        name = str(title or "").strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        fake = dict(rec)
        fake["name"] = name
        fake_extra = {
            k: v for k, v in extra.items() if k not in {"id", "rule", "check_id"}
        }
        fake["extra"] = fake_extra
        out.append(fake)
    return out


def _legacy_fps_for(rec: dict[str, Any]) -> list[tuple[str, str]]:
    """Prior fingerprint schemes (#131, pre-#140 port-only, pre-#131 name)."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    schemes: list[tuple[Any, str]] = [
        (legacy_name_asset_key, "name_to_ega"),
        (legacy_asset_id_port_key, "asset_id_port_to_ega"),
    ]
    if _legacy_port_only_allowed(rec):
        schemes.append((legacy_port_only_asset_key, "port_only_to_port_proto"))
    for fake in _legacy_alias_records(rec):
        for fn, reason in schemes:
            fp = fp_v1(fake, asset_key_fn=fn)
            if fp and fp not in seen:
                seen.add(fp)
                out.append((fp, reason))
    for fake in _nmap_legacy_title_records(rec):
        for fn, reason in (
            (asset_key, "nmap_title_to_check_id"),
            (legacy_asset_id_port_key, "nmap_title_to_check_id"),
            (legacy_name_asset_key, "nmap_title_to_check_id"),
        ):
            fp = fp_v1(fake, asset_key_fn=fn, weakness_key_fn=legacy_title_weakness_key)
            if fp and fp not in seen:
                seen.add(fp)
                out.append((fp, reason))
    # Any current row may have been keyed on the display title (Argus #5).
    for fn in (asset_key, legacy_asset_id_port_key, legacy_name_asset_key):
        fp = fp_v1(rec, asset_key_fn=fn, weakness_key_fn=legacy_title_weakness_key)
        if fp and fp not in seen:
            seen.add(fp)
            out.append((fp, "title_to_check_id"))
        stripped = dict(rec)
        stripped["name"] = strip_asset_from_title(rec)
        fp = fp_v1(stripped, asset_key_fn=fn, weakness_key_fn=legacy_title_weakness_key)
        if fp and fp not in seen:
            seen.add(fp)
            out.append((fp, "title_host_stripped"))
    # Current weakness_key before extra.check_id was stamped (B8 / Argus #5).
    extra_now = extra_dict(rec)
    if str(extra_now.get("check_id") or "").strip():
        pre = dict(rec)
        pre["extra"] = {k: v for k, v in extra_now.items() if k != "check_id"}
        for fn in (asset_key, legacy_asset_id_port_key, legacy_name_asset_key, legacy_master_asset_key):
            fp = fp_v1(pre, asset_key_fn=fn)
            if fp and fp not in seen:
                seen.add(fp)
                out.append((fp, "title_to_check_id"))
    extra = extra_dict(rec)
    svc = str(extra.get("service") or "").strip()
    if svc:
        fake = dict(rec)
        fake_extra = dict(extra)
        fake_extra["id"] = svc
        fake_extra.pop("check_id", None)
        fake_extra.pop("rule", None)
        fake["extra"] = fake_extra
        for fn in (asset_key, legacy_asset_id_port_key, legacy_name_asset_key, legacy_master_asset_key):
            fp = fp_v1(fake, asset_key_fn=fn, weakness_key_fn=lambda r: f"{_tool_tag(r)}:{svc}")
            if fp and fp not in seen:
                seen.add(fp)
                out.append((fp, "service_to_check_id"))
    # Pre-#161 master: extra.id|rule|check_id (or title) plus old/new asset keys.
    for fn, reason in (
        (asset_key, "master_key_current_ega"),
        (legacy_master_asset_key, "master_key_master_ega"),
        (legacy_asset_id_port_key, "master_key_asset_id"),
        (legacy_name_asset_key, "master_key_name"),
    ):
        fp = fp_v1(rec, asset_key_fn=fn, weakness_key_fn=legacy_master_weakness_key)
        if fp and fp not in seen:
            seen.add(fp)
            out.append((fp, reason))
    fp = fp_v1(rec, asset_key_fn=legacy_master_asset_key, weakness_key_fn=weakness_key)
    if fp and fp not in seen:
        seen.add(fp)
        out.append((fp, "current_key_master_ega"))
    fp = fp_v1(rec, asset_key_fn=legacy_master_asset_key, weakness_key_fn=legacy_title_weakness_key)
    if fp and fp not in seen:
        seen.add(fp)
        out.append((fp, "title_master_ega"))
    extra = extra_dict(rec)
    variants = [rec]
    if str(extra.get("check_id") or "").strip():
        pre = dict(rec)
        pre["extra"] = {k: v for k, v in extra.items() if k != "check_id"}
        variants.append(pre)
    wazuh_hostful = _tool_tag(rec) == "wazuh" and (
        extra.get("agent_status") not in (None, "")
        or extra.get("disk_encryption_enabled") not in (None, "")
    )
    # #172 host-less before #170 pre_location. Title→check_id is chained
    # through `variants` so a 7ebc697 / 29c4c3e title-keyed host-less row
    # rematches (Metis #177).
    if wazuh_hostful:
        for variant in variants:
            hostless = _weakness_key_core(variant)
            loc = ""
            if hostless and not hostless.startswith("cve:"):
                loc = _location_suffix(variant)
            hostless_loc = f"{hostless}:{loc}" if loc else hostless
            for key in (hostless_loc, hostless):
                if not key or key == weakness_key(rec):
                    continue
                for fn, reason in (
                    (asset_key, "wazuh_add_host"),
                    (legacy_master_asset_key, "wazuh_add_host"),
                    (legacy_asset_id_port_key, "wazuh_add_host"),
                    (legacy_name_asset_key, "wazuh_add_host"),
                ):
                    fp = fp_v1(variant, asset_key_fn=fn, weakness_key_fn=lambda _r, k=key: k)
                    if fp and fp not in seen:
                        seen.add(fp)
                        out.append((fp, reason))
    # Pre-location fallback (#161): same title on one asset, no path/url/file.
    # After wazuh_add_host so hosta's stored host-less fp is claimed before a
    # same-title sibling (KR-B / EGP-946F27C7C3). Also run on the pre-check_id
    # variant so #170 location rematch still sees the title-keyed family.
    for variant in variants:
        for fn, reason in (
            (asset_key, "pre_location_to_location"),
            (legacy_master_asset_key, "pre_location_master_ega"),
            (legacy_asset_id_port_key, "pre_location_asset_id"),
            (legacy_name_asset_key, "pre_location_name"),
        ):
            fp = fp_v1(
                variant, asset_key_fn=fn, weakness_key_fn=legacy_pre_location_weakness_key
            )
            if fp and fp not in seen:
                seen.add(fp)
                out.append((fp, reason))
            hosted = _attach_wazuh_host(variant, _weakness_key_core(variant))
            if hosted and hosted != legacy_pre_location_weakness_key(variant):
                fp = fp_v1(variant, asset_key_fn=fn, weakness_key_fn=lambda _r, k=hosted: k)
                if fp and fp not in seen:
                    seen.add(fp)
                    out.append((fp, reason))
    return out


def _legacy_asset_keys_for(rec: dict[str, Any]) -> set[str]:
    """#131 / pre-#140 / pre-#131 / pre-#161 asset_key strings a prior item may hold."""
    keys: set[str] = set()
    for fake in _legacy_alias_records(rec):
        keys.add(legacy_name_asset_key(fake))
        keys.add(legacy_asset_id_port_key(fake))
        keys.add(legacy_master_asset_key(fake))
        if _legacy_port_only_allowed(rec):
            keys.add(legacy_port_only_asset_key(fake))
    keys.add(legacy_master_asset_key(rec))
    return {k for k in keys if k}


def _item_sort_key(item: dict[str, Any]) -> tuple:
    detected = _to_date(item.get("original_detection_date"))
    first = str(item.get("first_seen") or "")
    pid = str(item.get("poam_id") or "")
    return (detected is None, detected or date.max, first, pid)


def _norm_loc_url(url: str) -> str:
    """Lowercase URL, strip trailing slash/punctuation. Host-only ≠ /login."""
    text = str(url or "").strip().lower().rstrip(_TRAILING_LOC)
    if not text:
        return ""
    while text.endswith("/") and text.count("/") > 2:
        text = text[:-1]
    return text.rstrip(_TRAILING_LOC)


def _urls_in_text(text: str) -> list[str]:
    return [_norm_loc_url(m.group(0)) for m in _URL_IN_TEXT.finditer(text or "") if _norm_loc_url(m.group(0))]


def _url_matches_hay(url: str, hay: str) -> bool:
    target = _norm_loc_url(url)
    if not target:
        return False
    return target in _urls_in_text(hay)


def _path_in_hay(path: str, hay: str) -> bool:
    raw = str(path or "").strip()
    if not raw or raw in {".", "/"}:
        return False
    if "://" in raw:
        return _url_matches_hay(raw, hay)
    norm = raw if raw.startswith("/") else f"/{raw}"
    norm = norm.rstrip("/") or "/"
    if norm == "/":
        return False
    for url in _urls_in_text(hay):
        rest = url.split("://", 1)[-1]
        url_path = "/" + rest.split("/", 1)[-1] if "/" in rest else "/"
        url_path = url_path.rstrip("/") or "/"
        if url_path == norm.lower():
            return True
    hay_l = hay.lower()
    needle = norm.lower()
    idx = 0
    while True:
        idx = hay_l.find(needle, idx)
        if idx < 0:
            return False
        after = hay_l[idx + len(needle) : idx + len(needle) + 1]
        if after in {"", " ", ".", ",", ")", "'", '"', ";", ":", "\n", "\t"}:
            return True
        idx += len(needle)


def _cmd_in_hay(cmd: str, hay: str) -> bool:
    text = str(cmd or "").strip()
    if len(text) < 3:
        return False
    if f"'{text}'" in hay or f'"{text}"' in hay:
        return True
    return text in hay


def _item_location_haystack(item: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("description", "url", "cmd", "command", "path", "file"):
        val = item.get(key)
        if val not in (None, ""):
            parts.append(str(val))
    return " ".join(parts)


def _haystack_has_location(hay: str) -> bool:
    if not str(hay or "").strip():
        return False
    if _urls_in_text(hay):
        return True
    lowered = hay.lower()
    if "observed command" in lowered:
        return True
    if re.search(r"presents\s+\S+", hay, re.I):
        return True
    if re.search(r"(?:^|[\s'\"])(/[A-Za-z0-9._-]+)", hay):
        return True
    return False


def _location_affinity(rec: dict[str, Any], item: dict[str, Any]) -> int:
    """>0 this rec's path/url/file/line/cmd matches the stored row; <0 contradicts; 0 unknown."""
    extra = extra_dict(rec)
    url = _extra_field(extra, "url")
    path = _extra_field(extra, "path")
    cmd = _extra_field(extra, "cmd") or _extra_field(extra, "command")
    file_name = _extra_field(extra, "file")
    line = _extra_field(extra, "line")
    user = _extra_field(extra, "user")
    if not any((url, path, cmd, file_name, user)):
        return 0
    hay = _item_location_haystack(item)
    hits = 0
    if url and _url_matches_hay(url, hay):
        hits += 1
    if path:
        if "://" in path:
            if _url_matches_hay(path, hay):
                hits += 1
        elif _path_in_hay(path, hay):
            hits += 1
    if cmd and _cmd_in_hay(cmd, hay):
        hits += 1
    if file_name and file_name.lower() in hay.lower():
        hits += 1
        if line and line in hay:
            hits += 1
    if user and not cmd and user.lower() in hay.lower():
        hits += 1
    if hits > 0:
        return hits
    if _haystack_has_location(hay):
        return -1
    return 0


def _legacy_fps_cached(
    rec: dict[str, Any], cache: dict[int, list[tuple[str, str]]]
) -> list[tuple[str, str]]:
    key = id(rec)
    hit = cache.get(key)
    if hit is None:
        hit = _legacy_fps_for(rec)
        cache[key] = hit
    return hit


def _may_claim_legacy_fp(
    rec: dict[str, Any],
    item: dict[str, Any],
    old_fp: str,
    instances: list[dict[str, Any]],
    legacy_cache: dict[int, list[tuple[str, str]]],
) -> bool:
    """Same-title siblings: location match wins; first in record order only if none match."""
    siblings = []
    for other in instances:
        reasons = [
            reason
            for fp, reason in _legacy_fps_cached(other, legacy_cache)
            if fp == old_fp
        ]
        if not reasons:
            continue
        if "wazuh_add_host" in reasons and not _wazuh_hostless_item_matches(other, item):
            continue
        siblings.append(other)
    if len(siblings) <= 1:
        return True
    if _location_affinity(rec, item) > 0:
        return True
    if any(other is not rec and _location_affinity(other, item) > 0 for other in siblings):
        return False
    return siblings[0] is rec


def _migrate_if_needed(
    rec: dict[str, Any],
    ledger: dict[str, Any],
    run_iso: str,
    *,
    instances: list[dict[str, Any]] | None = None,
    legacy_cache: dict[int, list[tuple[str, str]]] | None = None,
) -> str:
    """Map prior fps onto the current EGA- key. Never remint a surviving EGP- ID.

    Same weakness + two old asset keys → keep the older EGP- ID and earliest
    Original Detection Date; the other EGP- ID is recorded on ``fp_migrations``
    as an alias (not deleted). Different weaknesses stay separate items.

    Location split (Metis #170): when several current rows rematch the same
    stored title/location-family item, the sibling whose path/url/file/line/cmd
    matches the stored description/url/cmd keeps that EGP. Others mint new
    EGPs. Fall back to the first sibling in record order only if none match.
    """
    new_fp = fp_v1(rec)
    items: dict[str, Any] = ledger["items"]
    peers = instances or [rec]
    cache = legacy_cache if legacy_cache is not None else {}
    found: dict[str, tuple[dict[str, Any], str]] = {}
    for old_fp, reason in _legacy_fps_cached(rec, cache):
        if old_fp != new_fp and old_fp in items:
            item = items[old_fp]
            if reason == "wazuh_add_host" and not _wazuh_hostless_item_matches(rec, item):
                continue
            if not _may_claim_legacy_fp(rec, item, old_fp, peers, cache):
                continue
            found[old_fp] = (item, reason)
    if _tool_tag(rec) == "wazuh":
        for old_fp, item in _find_stored_wazuh_by_display(rec, items):
            if old_fp not in found:
                found[old_fp] = (item, "wazuh_add_host")
    if new_fp in items:
        found[new_fp] = (items[new_fp], "current")
    if not found or (len(found) == 1 and new_fp in found):
        return new_fp

    ranked = sorted(found.items(), key=lambda pair: _item_sort_key(pair[1][0]))
    aliases: list[str] = []
    surv_fp, (surv, surv_reason) = ranked[0]
    survivor = items.pop(surv_fp, None) or dict(surv)
    survivor["fp"] = new_fp
    survivor["asset_key"] = asset_key(rec)
    aliases.extend(str(x) for x in (survivor.get("aliased_poam_ids") or []) if x)
    items[new_fp] = survivor
    if surv_fp != new_fp:
        _record_fp_migration(
            ledger,
            src_fp=surv_fp,
            dest_fp=new_fp,
            poam_id=str(survivor.get("poam_id") or ""),
            odd=str(survivor.get("original_detection_date") or ""),
            reason=surv_reason,
        )
        ledger["events"].append(
            _event(run_iso, new_fp, str(survivor.get("poam_id") or ""), "migrated", {"from": surv_fp})
        )

    survivor_id = str(items[new_fp].get("poam_id") or "")
    for old_fp, (item, reason) in found.items():
        if old_fp == surv_fp:
            continue
        if old_fp != new_fp:
            items.pop(old_fp, None)
        alias_id = str(item.get("poam_id") or "")
        odd = str(item.get("original_detection_date") or "")
        d_alias = _to_date(odd)
        d_keep = _to_date(items[new_fp].get("original_detection_date"))
        if d_alias and (not d_keep or d_alias < d_keep):
            items[new_fp]["original_detection_date"] = odd
        if alias_id and alias_id != survivor_id and alias_id not in aliases:
            aliases.append(alias_id)
        _record_fp_migration(
            ledger,
            src_fp=old_fp,
            dest_fp=new_fp,
            poam_id=alias_id,
            odd=odd,
            reason=reason,
            alias_of=survivor_id,
        )
        ledger["events"].append(
            _event(
                run_iso,
                new_fp,
                survivor_id,
                "migrated_alias",
                {"from": old_fp, "alias_poam_id": alias_id},
            )
        )
    if aliases:
        items[new_fp]["aliased_poam_ids"] = aliases
    return new_fp


def build_coverage(instances: Iterable[dict[str, Any]]) -> dict[str, set[str]]:
    cov: dict[str, set[str]] = {}
    for rec in instances:
        fam = source_family(rec)
        bucket = cov.setdefault(fam, set())
        bucket.add(asset_key(rec))
        host = asset_host(rec)
        if host:
            bucket.add(host)
        # Pre-EGA keys so unobserved sibling weaknesses on a merged host
        # still count as covered (#131 pending_verification contract).
        for fake in _legacy_alias_records(rec):
            for key in (
                legacy_asset_id_port_key(fake),
                legacy_name_asset_key(fake),
                legacy_port_only_asset_key(fake),
                legacy_master_asset_key(fake),
                asset_id(fake),
            ):
                if key:
                    bucket.add(key)
        host_ega = legacy_master_asset_key(rec).split(":")[0]
        if host_ega:
            bucket.add(host_ega)
    return cov


def is_covered(item: dict[str, Any], coverage: dict[str, set[str]]) -> bool:
    fam = str(item.get("source_family") or "")
    if fam not in coverage:
        return False
    keys = coverage[fam]
    ak = str(item.get("asset_key") or "")
    host = ak.split(":")[0] if ak else ""
    return ak in keys or (host in keys if host else False)


def apply_ledger(
    findings: list[dict[str, Any]],
    *,
    catalog: KevCatalog,
    run_at: datetime | None = None,
    ledger_in: dict[str, Any] | None = None,
    overrides: dict[str, dict[str, str]] | None = None,
    prior_existed: bool = True,
) -> dict[str, Any]:
    """Apply one run to the ledger. Never auto-closes."""
    clock = run_at or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    from shared.poam_fields import utc_run_date

    run_date = utc_run_date(clock)
    run_iso = clock.strftime("%Y-%m-%dT%H:%M:%SZ")
    ledger = deepcopy(ledger_in) if ledger_in is not None else empty_ledger()
    ledger.setdefault("items", {})
    ledger.setdefault("closed", [])
    ledger.setdefault("events", [])
    ledger.setdefault("fp_migrations", [])
    prior_events_n = len(ledger["events"])
    # Reset each run. Prior LEDGER_LOST must not stick once a ledger is supplied.
    warnings: list[str] = []
    if not prior_existed:
        warnings.append(LEDGER_LOST)
    overrides = overrides or {}
    instances = fan_out_instances(findings)
    coverage = build_coverage(instances)
    seen: set[str] = set()
    included_fps: set[str] = set()
    excluded_by_fp: dict[str, str] = {}
    catalog_sha = catalog.sha256 if catalog.kev_evaluated else ""
    legacy_cache: dict[int, list[tuple[str, str]]] = {}

    for rec in instances:
        fp = _migrate_if_needed(
            rec, ledger, run_iso, instances=instances, legacy_cache=legacy_cache
        )
        seen.add(fp)
        reason = excluded_reason_for(rec)
        if reason:
            excluded_by_fp.setdefault(fp, reason)
        else:
            included_fps.add(fp)
        cves = collect_cves(rec)
        kev = join_kev(cves, catalog)
        used = _used_ids(ledger)
        item = ledger["items"].get(fp)
        if item is None:
            extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
            if is_egr_rollup(rec):
                policy = str(extra.get("check_id") or rec.get("name") or "")
                mint_fp = egr_key(policy, _egr_account(rec))
                poam_id = assign_poam_id(mint_fp, used, prefix="EGR-")
            else:
                poam_id = assign_poam_id(fp, used)
            used[poam_id] = fp
            item = _new_item(
                rec,
                fp=fp,
                poam_id=poam_id,
                run_date=run_date,
                run_iso=run_iso,
                kev=kev,
                catalog_sha=catalog_sha,
            )
            if not prior_existed:
                item["detection_date_basis"] = f"{item['detection_date_basis']}+ledger_lost"
            ledger["items"][fp] = item
            ledger["events"].append(_event(run_iso, fp, poam_id, "created"))
        else:
            status = str(item.get("status") or "open")
            if status == "closed":
                closed_copy = deepcopy(item)
                ledger["closed"].append(closed_copy)
                new_id = next_reopen_id(str(item.get("poam_id") or ""), _existing_id_set(ledger) | {closed_copy.get("poam_id", "")})
                detected, basis = detection_time(rec)
                fresh = _new_item(
                    rec,
                    fp=fp,
                    poam_id=new_id,
                    run_date=run_date,
                    run_iso=run_iso,
                    kev=kev,
                    catalog_sha=catalog_sha,
                )
                fresh["status"] = "reopened"
                fresh["prior_poam_id"] = str(item.get("poam_id") or "")
                fresh["original_detection_date"] = (
                    detected.isoformat() if detected is not None else NOT_RECORDED
                )
                fresh["detection_date_basis"] = basis if detected is not None else "not_recorded"
                fresh["kev_comments"] = list(fresh.get("kev_comments") or []) + [
                    f"Reopened from {item.get('poam_id')}; closed row remains on Closed."
                ]
                ledger["items"][fp] = fresh
                ledger["events"].append(
                    _event(run_iso, fp, new_id, "reopened", {"prior_poam_id": item.get("poam_id")})
                )
                item = fresh
            else:
                before = _tracked_snapshot(item)
                item["last_seen"] = run_iso
                item["missed_covered_runs"] = 0
                item["current_scanner_rating"] = ciso_finding_severity(rec.get("severity"))
                item["scanner_critical"] = item["current_scanner_rating"] == "critical"
                item["cves"] = list(kev.get("cves") or [])
                item["kev_cves"] = list(kev.get("kev_cves") or [])
                item["kev_due"] = kev["kev_due"].isoformat() if kev.get("kev_due") else ""
                item["kev_catalog_sha256"] = catalog_sha
                item["kev_tracking"] = kev.get("tracking") or ""
                item["kev_comments"] = list(kev.get("comments") or [])
                item["asset_key"] = asset_key(rec)
                item["display_asset"] = display_asset(rec)
                item["weakness_key"] = weakness_key(rec)
                if rec.get("ref_id"):
                    item["ref_id"] = str(rec.get("ref_id") or "")
                item["name"] = str(rec.get("name") or item.get("name") or "")
                item["description"] = str(rec.get("description") or item.get("description") or "")
                incoming, incoming_basis = detection_time(rec)
                item["original_detection_date"] = merge_detection(
                    str(item.get("original_detection_date") or NOT_RECORDED),
                    incoming,
                )
                if incoming is not None and item["original_detection_date"] != NOT_RECORDED:
                    if item.get("detection_date_basis") in {"", "not_recorded", "run", "collected_at"}:
                        item["detection_date_basis"] = incoming_basis
                detected = _to_date(item.get("original_detection_date"))
                if detected is not None:
                    tmpl = template_due_date(detected, rec.get("severity"))
                    item["template_due"] = tmpl.isoformat()
                    item["effective_due"] = (
                        effective_due(tmpl, kev.get("kev_due")) or tmpl
                    ).isoformat()
                else:
                    item["template_due"] = ""
                    item["effective_due"] = (
                        kev.get("kev_due").isoformat() if kev.get("kev_due") else ""
                    )
                item["kev_overdue_on_detection"] = kev_overdue_on_detection(
                    detected, kev.get("kev_due")
                )
                if status == "pending_verification":
                    item["status"] = "open"
                    item["status_date"] = run_date.isoformat()
                    ledger["events"].append(
                        _event(run_iso, fp, str(item.get("poam_id") or ""), "seen_from_pending")
                    )
                after = _tracked_snapshot(item)
                if after != before:
                    item["status_date"] = run_date.isoformat()
                    ledger["events"].append(
                        _event(
                            run_iso,
                            fp,
                            str(item.get("poam_id") or ""),
                            "field_changed",
                            {"before": before, "after": after},
                        )
                    )
                else:
                    ledger["events"].append(
                        _event(run_iso, fp, str(item.get("poam_id") or ""), "reobserved")
                    )

        ov = overrides.get(str(item.get("poam_id") or ""))
        before_vd = _vd_snapshot(item)
        closed_now = False
        if ov:
            changed, ov_warns = _apply_override(item, ov, run_date)
            warnings.extend(ov_warns)
            closing = (
                str(ov.get("status") or "").strip().lower() == "closed" and ov.get("evidence_ref")
            )
            if closing and canon_yes_no(item.get("vendor_dependency")) == VD_YES:
                warnings.append(f"{VD_NOT_CLOSED}:{item.get('poam_id')}")
            elif closing:
                closed_on = _to_date(ov.get("status_date") or ov.get("closed_date")) or run_date
                item["status"] = "closed"
                item["closed_date"] = closed_on.isoformat()
                item["status_date"] = closed_on.isoformat()
                ev = list(item.get("closure_evidence") or [])
                ev.append(ov.get("evidence_ref"))
                item["closure_evidence"] = ev
                closed_now = True
                ledger["events"].append(
                    _event(run_iso, fp, str(item["poam_id"]), "closed", {"evidence_ref": ov.get("evidence_ref")})
                )
            elif changed:
                non_vd = [c for c in changed if c not in VD_AUDIT_FIELDS]
                if non_vd:
                    item["status_date"] = run_date.isoformat()
                    ledger["events"].append(
                        _event(run_iso, fp, str(item["poam_id"]), "field_changed", {"override": non_vd})
                    )
        for flag in finalize_vendor_fields(item, rec, run_date=run_date, override=ov or None):
            warnings.append(f"{flag}:{item.get('poam_id')}")
        after_vd = _vd_snapshot(item)
        if (
            after_vd != before_vd
            and not closed_now
            and not _vd_is_schema_backfill(before_vd, after_vd)
        ):
            item["status_date"] = run_date.isoformat()
            ledger["events"].append(
                _event(
                    run_iso,
                    fp,
                    str(item.get("poam_id") or ""),
                    "field_changed",
                    {"before": before_vd, "after": after_vd},
                )
            )

    for fp, item in ledger["items"].items():
        if fp in included_fps:
            item["excluded_reason"] = ""
        elif fp in excluded_by_fp:
            item["excluded_reason"] = excluded_by_fp[fp]

    for fp, item in list(ledger["items"].items()):
        if fp in seen:
            continue
        if str(item.get("status") or "") == "closed":
            continue
        before_vd = _vd_snapshot(item)
        for flag in finalize_vendor_fields(item, None, run_date=run_date):
            warnings.append(f"{flag}:{item.get('poam_id')}")
        after_vd = _vd_snapshot(item)
        if after_vd != before_vd and not _vd_is_schema_backfill(before_vd, after_vd):
            item["status_date"] = run_date.isoformat()
            ledger["events"].append(
                _event(
                    run_iso,
                    fp,
                    str(item.get("poam_id") or ""),
                    "field_changed",
                    {"before": before_vd, "after": after_vd},
                )
            )
        if str(item.get("vendor_dependency") or "").strip().lower() == "yes":
            continue
        if str(item.get("operational_requirement") or "").strip().lower() in {"yes", "or"}:
            continue
        if not is_covered(item, coverage):
            ledger["events"].append(
                _event(run_iso, fp, str(item.get("poam_id") or ""), "not_observed_no_coverage")
            )
            continue
        missed = int(item.get("missed_covered_runs") or 0) + 1
        item["missed_covered_runs"] = missed
        dates = list(item.get("missed_dates") or [])
        dates.append(run_date.isoformat())
        item["missed_dates"] = dates
        if missed >= 2 and str(item.get("status") or "") != "pending_verification":
            item["status"] = "pending_verification"
            item["status_date"] = run_date.isoformat()
            ledger["events"].append(
                _event(run_iso, fp, str(item.get("poam_id") or ""), "pending_verification", {"dates": dates})
            )

    ledger["warnings"] = sorted(set(warnings + list(catalog.warnings)))
    ledger["run_at"] = run_iso
    ledger["prev_sha256"] = str((ledger_in or {}).get("sha256") or "")
    ledger["events_this_run"] = list(ledger["events"][prior_events_n:])
    ledger["sha256"] = payload_sha256(ledger)
    return ledger


def ledger_run_delta(
    ledger: dict[str, Any],
    *,
    plan_ids: set[str] | frozenset[str] | None = None,
) -> dict[str, int]:
    """Client-facing counts for this run: open / new / pending / reopened / closed.

    ``open`` is the operator plan (poam.csv) when ``plan_ids`` is supplied —
    excluded ledger items stay off that headline. ``ledger_open`` is every
    non-closed ledger item, including excluded, for a labeled secondary figure.

    Prefer ``events_this_run`` (the events ``apply_ledger`` appended). The
    timestamp filter is a fallback for older ledgers; second-resolution
    ``run_at`` can collide across back-to-back operator runs.
    """
    items = ledger.get("items") or {}
    if "events_this_run" in ledger:
        events = list(ledger.get("events_this_run") or [])
    else:
        run_iso = str(ledger.get("run_at") or "")
        events = [e for e in (ledger.get("events") or []) if str(e.get("at") or "") == run_iso]
    live = [
        item
        for item in items.values()
        if str(item.get("status") or "") != "closed"
    ]
    ledger_open_n = len(live)
    if plan_ids is None:
        open_n = ledger_open_n
    else:
        open_n = sum(1 for item in live if str(item.get("poam_id") or "") in plan_ids)
    return {
        "open": open_n,
        "ledger_open": ledger_open_n,
        "new": sum(1 for e in events if e.get("kind") == "created"),
        "pending_verification": sum(
            1 for item in items.values() if str(item.get("status") or "") == "pending_verification"
        ),
        "reopened": sum(1 for e in events if e.get("kind") == "reopened"),
        "closed": sum(1 for e in events if e.get("kind") == "closed"),
    }


def pending_comment(item: dict[str, Any]) -> str:
    dates = ", ".join(item.get("missed_dates") or [])
    return (
        f"pending_verification — not detected in rescans {dates}; "
        "closure requires evidence + 3PAO verification"
    )


def run_ledger(
    findings: list[dict[str, Any]],
    catalog: KevCatalog,
    *,
    run_at: datetime | None = None,
    in_root: Path | None = None,
    out_root: Path | None = None,
) -> dict[str, Any]:
    """Load in/poam/poam-ledger.json, apply, write out/poam/poam-ledger.json."""
    src = (in_root or in_dir()) / LEDGER_IN_REL
    existed = src.is_file()
    if not existed:
        fallback = (out_root or out_dir()) / LEDGER_OUT_REL
        if fallback.is_file():
            src = fallback
            existed = True
    prior, load_warnings = load_ledger_file(src)
    overrides = load_overrides((in_root or in_dir()) / OVERRIDES_REL)
    ledger = apply_ledger(
        findings,
        catalog=catalog,
        run_at=run_at,
        ledger_in=prior,
        overrides=overrides,
        prior_existed=existed,
    )
    if LEDGER_CHAIN_BROKEN in load_warnings:
        ledger["warnings"] = sorted(set(list(ledger.get("warnings") or []) + [LEDGER_CHAIN_BROKEN]))
    persist_ledger(ledger, out_root)
    return ledger
