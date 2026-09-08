"""Parse operator-dropped SPF/DKIM/DMARC/MX/cert snapshots.

Parse-only. Does not query DNS, open sockets, or run dig/openssl.
A TXT record is Seen (email_dns lane), not mailbox compromise and not a breach.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.io_util import iso_now, read_json, read_jsonl, read_text
from shared.schema import make_record, make_ref

SOURCE = "dns-email"
LABELS = ["dns-email", "email-dns", "seen"]
HONEST = (
    "This is a Seen DNS/TXT observation (email_dns lane), "
    "not mailbox compromise and not a breach."
)

_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
_DMARC_RE = re.compile(r"v\s*=\s*dmarc1", re.I)
_SPF_RE = re.compile(r"v\s*=\s*spf1\b", re.I)
_DKIM_RE = re.compile(r"v\s*=\s*dkim1", re.I)
_DIG_TXT = re.compile(
    r"(?P<name>[^\s;]+)\s+(?:\d+\s+)?IN\s+TXT\s+(?P<val>.+)",
    re.I,
)
_DIG_MX = re.compile(
    r"(?P<name>[^\s;]+)\s+(?:\d+\s+)?IN\s+MX\s+\d+\s+(?P<val>\S+)",
    re.I,
)
_DIG_NS = re.compile(
    r"(?P<name>[^\s;]+)\s+(?:\d+\s+)?IN\s+NS\s+(?P<val>\S+)",
    re.I,
)


def _now() -> str:
    return iso_now()


def _norm_domain(raw: Any) -> str:
    host = str(raw or "").strip().lower().rstrip(".")
    host = host.split("://")[-1].split("/")[0].split(":")[0]
    return host.strip(".")


def _strip_txt(raw: Any) -> str:
    text = str(raw or "").strip()
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        text = text[1:-1]
    return text.replace('" "', "").replace('""', "").strip()


def _as_list(raw: Any) -> list[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    return [raw]


def _unwrap(payload: Any) -> Any:
    if isinstance(payload, dict):
        for key in ("data", "results", "export", "dns_email", "checkdmarc"):
            inner = payload.get(key)
            if isinstance(inner, (dict, list)) and inner:
                return inner
    return payload


def _is_crtsh_row(row: dict[str, Any]) -> bool:
    keys = {k.lower() for k in row}
    return bool(
        keys & {"common_name", "name_value", "issuer_name", "not_after", "not_before"}
        and keys & {"id", "issuer_ca_id", "serial_number", "entry_timestamp", "min_cert_id"}
    ) or (
        "common_name" in row
        and ("issuer_name" in row or "not_after" in row)
        and "spf" not in keys
        and "dmarc" not in keys
    )


def _is_crtsh_payload(payload: Any) -> bool:
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return _is_crtsh_row(payload[0])
    if isinstance(payload, dict):
        rows = payload.get("results") or payload.get("certs") or payload.get("certificates")
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            return _is_crtsh_row(rows[0])
    return False


def _crtsh_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        raw = payload.get("results") or payload.get("certs") or payload.get("certificates") or []
        if isinstance(raw, list):
            return [r for r in raw if isinstance(r, dict)]
        if _is_crtsh_row(payload):
            return [payload]
    return []


def _parse_when(raw: Any) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    cleaned = text.replace("+00:00", "Z")
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%b %d %H:%M:%S %Y GMT",
        "%Y%m%d%H%M%SZ",
    ):
        try:
            parsed = datetime.strptime(cleaned, fmt)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _spf_policy(record: str) -> str:
    blob = (record or "").lower()
    if not _SPF_RE.search(blob):
        return "missing"
    if re.search(r"(?:^|\s)\+all\b", blob):
        return "pass_all"
    if re.search(r"(?:^|\s)-all\b", blob):
        return "fail"
    if re.search(r"(?:^|\s)~all\b", blob):
        return "softfail"
    if re.search(r"(?:^|\s)\?all\b", blob):
        return "neutral"
    return "present"


def _dmarc_policy(record: str) -> str:
    blob = (record or "").lower().replace(" ", "")
    if not record or not _DMARC_RE.search(record):
        return "missing"
    match = re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)", record, re.I)
    if not match:
        return "present"
    return match.group(1).lower()


def _record_from_block(block: Any) -> str:
    if block is None:
        return ""
    if isinstance(block, str):
        return _strip_txt(block)
    if isinstance(block, dict):
        for key in ("record", "txt", "value", "data", "raw"):
            if block.get(key):
                return _strip_txt(block.get(key))
        tags = block.get("tags")
        if isinstance(tags, dict) and tags.get("p"):
            pval = tags["p"]
            if isinstance(pval, dict):
                pval = pval.get("value") or pval.get("explicit") or ""
            return f"v=DMARC1; p={pval}"
    if isinstance(block, list) and block:
        return _record_from_block(block[0])
    return ""


def _mx_hosts(block: Any) -> list[str]:
    out: list[str] = []
    for item in _as_list(block):
        if isinstance(item, str):
            host = _norm_domain(item.split()[-1] if item.split() else item)
            if host:
                out.append(host)
        elif isinstance(item, dict):
            host = _norm_domain(
                item.get("hostname") or item.get("host") or item.get("exchange") or item.get("name")
            )
            if host:
                out.append(host)
    return list(dict.fromkeys(out))


def _dkim_rows(block: Any, selectors: list[str] | None = None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if isinstance(block, dict) and not any(k in block for k in ("selector", "record", "txt")):
        for sel, val in block.items():
            rec = _record_from_block(val)
            rows.append({"selector": str(sel), "record": rec})
        return rows
    for item in _as_list(block):
        if isinstance(item, str):
            rows.append({"selector": item, "record": ""})
        elif isinstance(item, dict):
            rows.append(
                {
                    "selector": str(item.get("selector") or item.get("name") or ""),
                    "record": _record_from_block(item),
                }
            )
    if selectors:
        have = {r["selector"] for r in rows if r.get("selector")}
        for sel in selectors:
            if sel and sel not in have:
                rows.append({"selector": sel, "record": ""})
    return rows


def _domain_rows(payload: Any) -> list[dict[str, Any]]:
    payload = _unwrap(payload)
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict) and _norm_domain(r.get("domain") or r.get("name") or r.get("host"))]
    if not isinstance(payload, dict):
        return []
    if payload.get("schema") in {"dns_email.v1", "dns-email.v1", "evergreen.dns_email.v1"}:
        raw = payload.get("domains") or payload.get("results") or []
        return [r for r in raw if isinstance(r, dict)] if isinstance(raw, list) else []
    if isinstance(payload.get("domains"), list):
        return [r for r in payload["domains"] if isinstance(r, dict)]
    domain = _norm_domain(payload.get("domain") or payload.get("base_domain") or payload.get("name"))
    if domain and (
        payload.get("spf") is not None
        or payload.get("dmarc") is not None
        or payload.get("dkim") is not None
        or payload.get("mx") is not None
        or payload.get("txt") is not None
    ):
        return [payload]
    return []


def _selectors_from_payload(payload: Any, row: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for src in (payload if isinstance(payload, dict) else {}, row):
        if not isinstance(src, dict):
            continue
        for key in ("dkim_selectors", "selectors"):
            for item in _as_list(src.get(key)):
                name = str(item or "").strip()
                if name:
                    out.append(name)
    return list(dict.fromkeys(out))


def _dig_inventory(text: str) -> dict[str, dict[str, Any]]:
    """Collect TXT/MX/NS from a dropped dig or nslookup transcript."""
    domains: dict[str, dict[str, Any]] = {}

    def bucket(name: str) -> dict[str, Any]:
        host = _norm_domain(name)
        if host.startswith("_dmarc."):
            host = host[7:]
        elif "._domainkey." in host:
            host = host.split("._domainkey.", 1)[-1]
        row = domains.setdefault(host, {"domain": host, "txt": [], "mx": [], "ns": [], "dkim": []})
        return row

    for match in _DIG_TXT.finditer(text):
        name = match.group("name")
        val = _strip_txt(match.group("val"))
        host = _norm_domain(name)
        row = bucket(name)
        if host.startswith("_dmarc."):
            row["dmarc"] = val
        elif "._domainkey." in host:
            selector = host.split("._domainkey.", 1)[0]
            row.setdefault("dkim", []).append({"selector": selector, "record": val})
        else:
            row.setdefault("txt", []).append(val)
            if _SPF_RE.search(val):
                row["spf"] = val
            if _DMARC_RE.search(val):
                row["dmarc"] = val
    for match in _DIG_MX.finditer(text):
        bucket(match.group("name")).setdefault("mx", []).append(match.group("val"))
    for match in _DIG_NS.finditer(text):
        bucket(match.group("name")).setdefault("ns", []).append(match.group("val"))

    # +short MX: "10 aspmx.l.google.com."
    if not domains:
        mx_short = re.findall(r"^\s*\d+\s+(\S+)\s*$", text, re.M)
        txt_short = [_strip_txt(x) for x in re.findall(r'"([^"]+)"', text)]
        if mx_short or any(_SPF_RE.search(t) or _DMARC_RE.search(t) for t in txt_short):
            row = domains.setdefault("unknown", {"domain": "unknown", "txt": txt_short, "mx": mx_short})
            for val in txt_short:
                if _SPF_RE.search(val):
                    row["spf"] = val
                if _DMARC_RE.search(val):
                    row["dmarc"] = val
    return domains


def _asset(now: str, name: str, category: str, extra: dict[str, Any] | None = None) -> dict:
    payload = {"asset_type": "PR", "sor": category}
    if extra:
        payload.update(extra)
    return make_record(
        kind="asset",
        source=SOURCE,
        ref_id=make_ref(SOURCE, f"asset-{name}"),
        name=name,
        description=f"{category} {name}",
        category=category,
        assets=[name],
        labels=list(LABELS),
        collected_at=now,
        extra=payload,
    )


def _finding(
    now: str,
    domain: str,
    key: str,
    name: str,
    description: str,
    severity: str,
    extra: dict[str, Any] | None = None,
) -> dict:
    payload = {"finding_id": key, "lane": "email_dns", "honesty": "seen_not_shown"}
    if extra:
        payload.update(extra)
    return make_record(
        kind="finding",
        source=SOURCE,
        ref_id=make_ref(SOURCE, f"{domain}-{key}"),
        name=name,
        description=f"{description} {HONEST}",
        severity=severity,
        category="control-gap",
        assets=[domain],
        labels=list(LABELS) + [key],
        collected_at=now,
        extra=payload,
    )


def _evidence(now: str, name: str, description: str, assets: list[str], extra: dict[str, Any] | None = None) -> dict:
    return make_record(
        kind="evidence",
        source=SOURCE,
        ref_id=make_ref(SOURCE, f"ev-{name}"),
        name=name,
        description=description,
        category="dns_txt",
        assets=assets,
        labels=list(LABELS) + ["evidence"],
        collected_at=now,
        extra=extra or {"lane": "email_dns"},
    )


def records_from_domain(now: str, row: dict[str, Any], selectors: list[str] | None = None) -> list[dict]:
    domain = _norm_domain(row.get("domain") or row.get("name") or row.get("host"))
    if not domain or domain == "unknown":
        return []
    records: list[dict] = [_asset(now, domain, "domain", {"dns_inventory": True})]
    spf = _record_from_block(row.get("spf"))
    if not spf:
        for txt in _as_list(row.get("txt") or row.get("TXT")):
            val = _strip_txt(txt)
            if _SPF_RE.search(val):
                spf = val
                break
    dmarc = _record_from_block(row.get("dmarc") or row.get("DMARC"))
    dkim_rows = _dkim_rows(row.get("dkim") or row.get("DKIM"), selectors)
    mx = _mx_hosts(row.get("mx") or row.get("MX"))
    ns = [_norm_domain(x) for x in _as_list(row.get("ns") or row.get("NS")) if _norm_domain(x)]

    snap = {
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim_rows,
        "mx": mx,
        "ns": ns,
    }
    records.append(
        _evidence(
            now,
            f"dns_txt {domain}",
            f"Published DNS snapshot for {domain}. {HONEST}",
            [domain],
            {"dns_txt": snap, "lane": "email_dns"},
        )
    )

    spf_pol = _spf_policy(spf)
    if spf_pol == "missing":
        records.append(
            _finding(
                now,
                domain,
                "spf_missing",
                f"SPF missing on {domain}",
                f"{domain} has no published v=spf1 TXT record. Control gap candidate.",
                "medium",
                {"spf": spf},
            )
        )
    elif spf_pol == "pass_all":
        records.append(
            _finding(
                now,
                domain,
                "spf_pass_all",
                f"SPF +all on {domain}",
                f"{domain} publishes SPF +all (any sender passes). Control gap candidate.",
                "high",
                {"spf": spf},
            )
        )
    elif spf_pol == "softfail":
        records.append(
            _finding(
                now,
                domain,
                "spf_softfail_only",
                f"SPF softfail-only on {domain}",
                f"{domain} publishes SPF ~all only. Control gap candidate, not a breach.",
                "low",
                {"spf": spf},
            )
        )

    dmarc_pol = _dmarc_policy(dmarc)
    if dmarc_pol == "missing":
        records.append(
            _finding(
                now,
                domain,
                "dmarc_missing",
                f"DMARC missing on {domain}",
                f"{domain} has no published _dmarc TXT policy. Control gap candidate.",
                "medium",
                {"dmarc": dmarc},
            )
        )
    elif dmarc_pol == "none":
        records.append(
            _finding(
                now,
                domain,
                "dmarc_monitor_only",
                f"DMARC p=none on {domain}",
                f"{domain} publishes DMARC p=none (monitor only). Control gap candidate.",
                "low",
                {"dmarc": dmarc},
            )
        )

    for item in dkim_rows:
        selector = str(item.get("selector") or "").strip()
        rec = str(item.get("record") or "")
        if not selector:
            continue
        if rec and _DKIM_RE.search(rec):
            continue
        records.append(
            _finding(
                now,
                domain,
                f"dkim_missing-{selector}",
                f"DKIM selector {selector} missing on {domain}",
                f"{domain} has no published DKIM TXT at {selector}._domainkey. Control gap candidate.",
                "medium",
                {"selector": selector, "dkim": rec},
            )
        )

    for host in mx:
        if host != domain:
            records.append(_asset(now, host, "mail_org", {"parent_domain": domain, "role": "mx"}))
    return records


def records_from_cert_row(now: str, row: dict[str, Any]) -> list[dict]:
    name = _norm_domain(
        row.get("common_name")
        or row.get("name_value")
        or row.get("cn")
        or row.get("subject")
        or ""
    )
    if not name:
        return []
    not_after = str(row.get("not_after") or row.get("notAfter") or row.get("valid_to") or "")
    issuer = str(row.get("issuer_name") or row.get("issuer") or "")
    records = [
        _asset(now, name, "domain", {"cert_seen": True, "issuer": issuer, "not_after": not_after}),
        _evidence(
            now,
            f"cert {name}",
            f"Operator-dropped certificate snapshot for {name}. {HONEST}",
            [name],
            {"lane": "email_dns", "cert": {"issuer": issuer, "not_after": not_after}},
        ),
    ]
    expiry = _parse_when(not_after)
    if expiry and expiry < datetime.now(timezone.utc):
        records.append(
            _finding(
                now,
                name,
                "cert_expired",
                f"Expired certificate on {name}",
                f"{name} presents an expired certificate in a dropped PEM/crt.sh snapshot (Seen, not a live TLS probe).",
                "medium",
                {"port": "443", "service": "https", "not_after": not_after, "issuer": issuer},
            )
        )
    return records


def _pem_cn(text: str) -> str:
    match = re.search(r"Subject:.*?\bCN\s*=\s*([^/\n,]+)", text, re.I)
    if match:
        return _norm_domain(match.group(1))
    match = re.search(r"DNS:([A-Za-z0-9_.-]+)", text)
    if match:
        return _norm_domain(match.group(1))
    return ""


def _pem_not_after(text: str) -> str:
    match = re.search(r"Not After\s*:\s*(.+)", text, re.I)
    return match.group(1).strip() if match else ""


def parse_payload(payload: Any, *, filename: str = "") -> list[dict]:
    now = _now()
    if _is_crtsh_payload(payload):
        records: list[dict] = []
        for row in _crtsh_rows(payload):
            records.extend(records_from_cert_row(now, row))
        return records
    rows = _domain_rows(payload)
    if not rows:
        return []
    records = []
    for row in rows:
        selectors = _selectors_from_payload(payload, row)
        records.extend(records_from_domain(now, row, selectors))
    return records


def parse_text(text: str, *, filename: str = "") -> list[dict]:
    now = _now()
    name_l = filename.lower()
    if _PEM_BEGIN in text or name_l.endswith(".pem") or name_l.endswith(".crt"):
        cn = _pem_cn(text) or "unknown-cert"
        not_after = _pem_not_after(text)
        row = {"common_name": cn, "not_after": not_after, "issuer_name": "operator-dropped-pem"}
        # Bare PEM without openssl -text is still a Seen snapshot (no expiry claim).
        if cn == "unknown-cert" and not not_after:
            return [
                _evidence(
                    now,
                    f"cert {filename or 'pem'}",
                    f"Operator-dropped PEM certificate snapshot. {HONEST}",
                    [],
                    {"lane": "email_dns", "file": filename, "pem": True},
                )
            ]
        return records_from_cert_row(now, row)
    inventory = _dig_inventory(text)
    records: list[dict] = []
    for row in inventory.values():
        records.extend(records_from_domain(now, row))
    return records


def parse_file(path: Path) -> list[dict]:
    """Return canonical records or []. Empty / unknown invent nothing."""
    suffix = path.suffix.lower()
    name = path.name
    if suffix in {".json", ".jsonl"}:
        try:
            payload = read_json(path)
        except (OSError, json.JSONDecodeError, ValueError):
            payload = None
        if payload is None:
            rows = [r for r in read_jsonl(path) if isinstance(r, (dict, list))]
            if not rows:
                return []
            payload = rows if len(rows) > 1 else rows[0]
        return parse_payload(payload, filename=name)
    text = read_text(path)
    if not text.strip():
        return []
    return parse_text(text, filename=name)
