"""Fold bare nmap-style port-open rows into a specific finding on the same host+port.

When nuclei / Nessus / testssl / NSE / similar already names a weakness on a
host+port, the inventory "port is open" row is supporting evidence, not a
second POA&M weakness.

Match: normalized host identity (asset, IP, hostname, URL host) + port.
Protocol is considered when both sides name one; a missing proto still matches.

Multiple specifics on the same host+port: pick one stable winner —
highest severity, then lowest EGP- id (then lowest ref_id). Documented here
so excluded.csv is deterministic.

Port-only rows with no specific peer stay on the POA&M (or keep their
existing exclude reason). Folded rows stay on the finding set so

    weaknesses_total == poam_included + excluded

holds. The folded row is excluded as ``superseded_by_specific`` with the
winner's EGP- id.
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from shared.finding_types import (
    SEV_RANK,
    TOOL_LABELS,
    extra_dict,
    normalize_asset_id,
)
from shared.poam_ledger import assign_poam_id, fp_v1
from shared.schema import ciso_finding_severity

SUPERSEDED_REASON = "superseded_by_specific"

# Scanner identities that make a finding "specific" (not just "port open").
_SPECIFIC_EXTRA = (
    "check_id",
    "nse_script",
    "template_id",
    "template-id",
    "plugin_id",
    "pluginID",
    "oid",
)
_SPECIFIC_LABELS = frozenset(
    {
        "nuclei",
        "nessus",
        "testssl",
        "nikto",
        "greenbone",
        "sslscan",
        "nse",
        "trivy",
        "sarif",
        "openvas",
    }
)
_SPECIFIC_CATEGORIES = frozenset({"vulnerability", "misconfiguration", "secrets", "sast"})
_PORT_SCAN_LABELS = frozenset(
    {
        "nmap",
        "inventory",
        "rustscan",
        "naabu",
        "masscan",
        "unicornscan",
        "zmap",
    }
)
_PORT_ONLY_SOURCES = frozenset(
    {
        "inventory-nmap",
        "evergreen-covey",
    }
)
_PORT_ONLY_NAME = re.compile(
    r"(open port\b|.+\bexposed\b|has open (?:tcp|udp)/)",
    re.I,
)
_SCHEME_DEFAULT_PORT = {"http": "80", "https": "443"}


def _labels(rec: dict[str, Any]) -> set[str]:
    return {str(x).strip().lower() for x in (rec.get("labels") or []) if str(x).strip()}


def _valid_port(token: str) -> str:
    """ASCII decimal 1..65535 only. Superscript / Arabic digits must not reach int()."""
    token = str(token or "").strip()
    if token.isascii() and token.isdigit() and 1 <= int(token) <= 65535:
        return token
    return ""


def _host_port_from_token(text: str) -> tuple[str, str]:
    """Parse host:port, [IPv6]:port, or a bare host. No urlsplit."""
    host = str(text or "").split("/", 1)[0]
    port = ""
    if host.startswith("[") and "]" in host:
        end = host.find("]")
        maybe = host[end + 1 :]
        host = host[1:end]
        if maybe.startswith(":"):
            port = _valid_port(maybe[1:])
    elif host.startswith("[") and "]" not in host:
        # Unclosed bracket — do not invent a host from the leftover token.
        return "", ""
    elif host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        parsed = _valid_port(right)
        if parsed:
            host, port = left, parsed
        elif right and not any(ch.isascii() and ch.isalpha() for ch in right):
            # Invalid digit-only port (99999 / ²) — keep the host, drop the port.
            host, port = left, ""
        # else image:tag / account:id — do not truncate.
    return host, port


def _url_has_explicit_port(raw: Any) -> bool:
    """True when the token named a port, including invalid :99999 / :abc / :0."""
    text = str(raw or "").strip()
    if not text:
        return False
    if "://" in text:
        rest = text.split("://", 1)[1]
    elif text.startswith("//"):
        rest = text[2:]
    else:
        rest = text
    rest = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in rest:
        rest = rest.rsplit("@", 1)[-1]
    if rest.startswith("["):
        if "]" not in rest:
            return False
        after = rest[rest.find("]") + 1 :]
        return after.startswith(":") and bool(after[1:].strip())
    if rest.count(":") != 1:
        return False
    return bool(rest.rsplit(":", 1)[-1].strip())


def _strip_host(raw: Any) -> tuple[str, str, str]:
    """Return (host, port, scheme) parsed from a URL, host:port, or bare host.

    Malformed IPv6 brackets (``https://[notanip]:6379``, unclosed
    ``https://[2001:4860:4860::8888``) must not raise. Same class as
    ``_host_from_url_or_token`` (#204). Unparseable tokens degrade to an
    empty host so a single bad ``extra.host`` / ``matched_at`` cannot abort
    the POA&M load. Valid bracketed IPv6 (with or without a port) still
    folds on the inner address.
    """
    text = str(raw or "").strip()
    if not text:
        return "", "", ""
    scheme = ""
    port = ""
    host = text
    if "://" in text or text.startswith("//"):
        try:
            parsed = urlsplit(text if "://" in text else f"http:{text}")
            scheme = (parsed.scheme or "").lower()
            host = parsed.hostname or parsed.path.split("/")[0] or ""
            try:
                if parsed.port:
                    port = str(parsed.port)
            except ValueError:
                netloc = parsed.netloc or ""
                if "@" in netloc:
                    netloc = netloc.rsplit("@", 1)[-1]
                if netloc.startswith("[") and "]" in netloc:
                    after = netloc[netloc.find("]") + 1 :]
                    raw_port = after[1:] if after.startswith(":") else ""
                elif netloc.count(":") == 1:
                    raw_port = netloc.rsplit(":", 1)[-1]
                else:
                    raw_port = ""
                port = _valid_port(raw_port)
        except ValueError:
            if "://" in text:
                scheme, rest = text.split("://", 1)
                scheme = scheme.lower()
            else:
                rest = text.lstrip("/")
            if "@" in rest:
                rest = rest.rsplit("@", 1)[-1]
            host, port = _host_port_from_token(rest)
    else:
        host, port = _host_port_from_token(text)
    host = normalize_asset_id(host)
    if host.startswith("www."):
        host = host[4:]
    return host, port, scheme


def finding_hosts(rec: dict[str, Any]) -> set[str]:
    """Normalized host identities used for host+port matching."""
    extra = extra_dict(rec)
    out: set[str] = set()
    candidates = list(rec.get("assets") or [])
    for key in ("ip", "host", "hostname", "addr", "address"):
        candidates.append(extra.get(key))
    for raw in candidates:
        host, _port, _scheme = _strip_host(raw)
        if host:
            out.add(host)
    return out


def finding_port(rec: dict[str, Any]) -> str:
    extra = extra_dict(rec)
    port = _valid_port(str(extra.get("port") or ""))
    if port:
        return str(int(port))
    for raw in list(rec.get("assets") or []) + [
        extra.get("host"),
        extra.get("matched-at"),
        extra.get("matched_at"),
        extra.get("url"),
    ]:
        host, parsed, scheme = _strip_host(raw)
        if parsed:
            return parsed
        if _url_has_explicit_port(raw):
            # Invalid :99999 / :abc / :0 — skip this candidate; do not invent 80/443.
            continue
        if scheme in _SCHEME_DEFAULT_PORT and host:
            return _SCHEME_DEFAULT_PORT[scheme]
    return ""


def finding_proto(rec: dict[str, Any]) -> str:
    extra = extra_dict(rec)
    proto = str(extra.get("protocol") or extra.get("proto") or "").strip().lower()
    if proto in {"tcp", "udp", "sctp"}:
        return proto
    return ""


def host_port_keys(rec: dict[str, Any]) -> set[tuple[str, str]]:
    """(host, port) keys. Empty if the row has no matchable port."""
    port = finding_port(rec)
    if not port:
        return set()
    return {(host, port) for host in finding_hosts(rec) if host}


def proto_compatible(left: dict[str, Any], right: dict[str, Any]) -> bool:
    a = finding_proto(left)
    b = finding_proto(right)
    return not a or not b or a == b


def _has_cve(rec: dict[str, Any]) -> bool:
    extra = extra_dict(rec)
    blobs = [extra.get("cve"), extra.get("cves"), rec.get("ref_id"), rec.get("name")]
    if isinstance(extra.get("cves"), list):
        blobs.extend(extra.get("cves") or [])
    for raw in blobs:
        text = str(raw or "").upper()
        if "CVE-" in text:
            return True
    return False


def _looks_open_port(rec: dict[str, Any]) -> bool:
    blob = f"{rec.get('name') or ''} {rec.get('description') or ''}"
    return bool(_PORT_ONLY_NAME.search(blob))


def is_specific_port_finding(rec: dict[str, Any]) -> bool:
    """A named weakness on a port (nuclei / Nessus / testssl / NSE / CVE / …).

    A pack_drop sslscan/httpx "Open TCP/443 observed" row is not specific
    just because the adapter label is sslscan — it is still port-only.
    """
    if rec.get("kind") != "finding":
        return False
    if not host_port_keys(rec):
        return False
    extra = extra_dict(rec)
    if any(
        str(extra.get(key) or "").strip()
        and not (
            key == "check_id"
            and str(extra.get(key) or "").startswith("nmap-port-")
        )
        for key in _SPECIFIC_EXTRA
    ):
        return True
    if _has_cve(rec):
        return True
    labels = _labels(rec)
    tool = str(extra.get("tool") or extra.get("scanner") or extra.get("adapter") or "").strip().lower()
    scanner_hit = bool(labels & _SPECIFIC_LABELS) or tool in _SPECIFIC_LABELS
    vid = str(extra.get("id") or "").strip()
    if vid and scanner_hit and not _looks_open_port(rec):
        return True
    if _looks_open_port(rec) and not any(
        str(extra.get(key) or "").strip() for key in _SPECIFIC_EXTRA
    ):
        return False
    category = str(rec.get("category") or "").strip().lower()
    if category in _SPECIFIC_CATEGORIES and scanner_hit:
        return True
    if scanner_hit and not _looks_open_port(rec):
        return True
    return False


def is_port_only_finding(rec: dict[str, Any]) -> bool:
    """Bare 'port open' / 'SERVICE exposed' observation, not a named vuln."""
    if rec.get("kind") != "finding":
        return False
    if not host_port_keys(rec):
        return False
    if is_specific_port_finding(rec):
        return False
    extra = extra_dict(rec)
    labels = _labels(rec)
    source = str(rec.get("source") or "").strip().lower()
    name = str(rec.get("name") or "")
    desc = str(rec.get("description") or "")
    looks_open = bool(_PORT_ONLY_NAME.search(name) or _PORT_ONLY_NAME.search(desc))
    from_port_scan = (
        source in _PORT_ONLY_SOURCES
        or bool(labels & _PORT_SCAN_LABELS)
        or str(extra.get("adapter") or "").strip().lower() in _PORT_SCAN_LABELS
    )
    category = str(rec.get("category") or "").strip().lower()
    if category and category not in {"exposure", "host", "service", ""}:
        return False
    return looks_open or from_port_scan


def egp_id_for(rec: dict[str, Any]) -> str:
    """Same EGP- assignment the ledger uses on a first-seen fingerprint."""
    return assign_poam_id(fp_v1(rec), {})


def pick_superseder(candidates: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Highest severity, then lowest EGP- id, then lowest ref_id."""
    rows = [rec for rec in candidates if rec]
    if not rows:
        raise ValueError("pick_superseder requires at least one finding")
    return min(
        rows,
        key=lambda rec: (
            -SEV_RANK.get(ciso_finding_severity(rec.get("severity")), 0),
            egp_id_for(rec),
            str(rec.get("ref_id") or ""),
        ),
    )


def port_only_superseders(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map port-only ref_id → the specific finding that supersedes it."""
    specifics = [rec for rec in findings if is_specific_port_finding(rec)]
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for rec in specifics:
        for key in host_port_keys(rec):
            buckets.setdefault(key, []).append(rec)
    mapping: dict[str, dict[str, Any]] = {}
    for rec in findings:
        if not is_port_only_finding(rec):
            continue
        ref = str(rec.get("ref_id") or "")
        if not ref:
            continue
        seen: set[int] = set()
        candidates: list[dict[str, Any]] = []
        for key in host_port_keys(rec):
            for other in buckets.get(key, []):
                oid = id(other)
                if oid in seen:
                    continue
                if not proto_compatible(rec, other):
                    continue
                seen.add(oid)
                candidates.append(other)
        if candidates:
            mapping[ref] = pick_superseder(candidates)
    return mapping


def _fold_evidence(winner: dict[str, Any], victim: dict[str, Any]) -> None:
    """Keep port-only source on the specific finding. Do not append alias assets.

    ``_merge_weakness`` also unions ``assets``, which fans the ledger out into
    a second EGP- row for the same host. Fold is same-host+port — labels,
    sources, tools, and provenance are the evidence.
    """
    extra = winner.setdefault("extra", {})
    if not isinstance(extra, dict):
        winner["extra"] = extra = {}
    sources = extra.setdefault("sources", [])
    if not isinstance(sources, list):
        extra["sources"] = sources = []
    for src in (winner.get("source"), victim.get("source")):
        token = str(src or "").strip()
        if token and token not in sources:
            sources.append(token)
    tools = extra.setdefault("tools", [])
    if not isinstance(tools, list):
        extra["tools"] = tools = []
    for token in ("nmap", *_labels(victim) & (_PORT_SCAN_LABELS | TOOL_LABELS)):
        if token and token not in tools:
            tools.append(token)
    labels = winner.setdefault("labels", [])
    if not isinstance(labels, list):
        winner["labels"] = labels = []
    for lab in victim.get("labels") or []:
        if lab and lab not in labels:
            labels.append(lab)
    also = extra.setdefault("also_ids", [])
    if not isinstance(also, list):
        extra["also_ids"] = also = []
    oid = str(victim.get("ref_id") or "")
    if oid and oid not in also and oid != str(winner.get("ref_id") or ""):
        also.append(oid)
    provenance = extra.setdefault("provenance", [])
    if not isinstance(provenance, list):
        extra["provenance"] = provenance = []
    if not provenance:
        provenance.append(
            {
                "source": winner.get("source"),
                "ref_id": winner.get("ref_id"),
                "name": winner.get("name"),
            }
        )
    provenance.append(
        {
            "source": victim.get("source"),
            "ref_id": victim.get("ref_id"),
            "name": victim.get("name"),
        }
    )
    folded = extra.setdefault("folded_port_only", [])
    if not isinstance(folded, list):
        extra["folded_port_only"] = folded = []
    if oid and oid not in folded:
        folded.append(oid)


def fold_port_only_into_specific(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Merge port-only evidence/labels/sources into the winner. Do not drop rows."""
    mapping = port_only_superseders(findings)
    by_ref = {str(rec.get("ref_id") or ""): rec for rec in findings if rec.get("ref_id")}
    for ref, winner in mapping.items():
        victim = by_ref.get(ref)
        if victim is None or victim is winner:
            continue
        _fold_evidence(winner, victim)
    return mapping
