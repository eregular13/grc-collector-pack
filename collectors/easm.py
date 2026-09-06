from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shared.io_util import discover_input_files, emit, load_structured
from shared.schema import asset, control_extra, evidence, finding

SOURCE = "easm"
PREFIX = "EASM-"

EXPOSED_HINTS = ("vpn.", "dev-api.", "staging.", "admin", "test.")


def _looks_like_url(text: str) -> bool:
    lowered = str(text or "").strip().lower()
    return lowered.startswith("http://") or lowered.startswith("https://")


def _field_text(value: Any) -> str:
    """First non-blank string; treats whitespace, null, and list-wrapped values as empty."""
    if isinstance(value, (list, tuple)):
        for part in value:
            text = _field_text(part)
            if text:
                return text
        return ""
    if value is None or isinstance(value, bool):
        return ""
    return str(value).strip().strip("\"'")


def _httpx_raw_target(item: dict[str, Any]) -> str:
    """Hostname source: non-blank host/hostname, else input, else url."""
    for key in ("host", "hostname"):
        text = _field_text(item.get(key))
        if text:
            return text
    for key in ("input", "url", "URL"):
        text = _field_text(item.get(key))
        if text:
            return text
    return ""


def normalize_host(raw: Any) -> str:
    """Hostname from a bare name or httpx URL-only string (`https://host[:port]/path`)."""
    text = str(raw or "").strip().strip("\"'")
    if not text or text.startswith("{") or text.startswith("["):
        return ""
    host = ""
    if "://" in text:
        parsed = urlparse(text)
        host = (parsed.hostname or "").strip()
        if not host:
            rest = text.split("://", 1)[-1]
            host = rest.split("/")[0]
            if "@" in host:
                host = host.rsplit("@", 1)[-1]
            host = host.strip("[]")
            if host.count(":") == 1:
                name, port = host.rsplit(":", 1)
                if port.isdigit():
                    host = name
    else:
        host = text.split("/")[0]
        if host.count(":") == 1:
            name, port = host.rsplit(":", 1)
            if port.isdigit():
                host = name
    host = host.strip().strip("[]").rstrip(".")
    if host.lower() in {"http", "https"}:
        return ""
    return host


def _host_asset(host: str) -> Any:
    atype = "PR" if host.startswith(("vpn.", "www.", "mail.")) else "SP"
    return asset(
        PREFIX,
        host,
        host,
        description=f"External hostname {host}",
        asset_type=atype,
        source=SOURCE,
        labels=["easm", "hostname"],
    )


def parse_httpx_item(item: Any) -> list:
    title = ""
    status = None
    from_input = False
    if isinstance(item, str):
        host = normalize_host(item)
    elif isinstance(item, dict):
        raw = _httpx_raw_target(item)
        host = normalize_host(raw)
        title = str(item.get("title") or "")
        status = item.get("status_code")
        host_field = _field_text(item.get("host")) or _field_text(item.get("hostname"))
        from_input = not host_field and bool(_field_text(item.get("input")))
    else:
        return []
    if not host:
        return []
    rec = _host_asset(host)
    if from_input:
        rec.labels = list(rec.labels or []) + ["httpx-input"]
    records = [rec]
    if any(host.lower().startswith(h) or h.strip(".") in host.lower() for h in EXPOSED_HINTS):
        sev = "high" if host.lower().startswith(("vpn.", "admin")) else "medium"
        bits = []
        if status is not None:
            bits.append(f"status={status}")
        if title:
            bits.append(f"title={title}")
        if isinstance(item, str) or (
            isinstance(item, dict)
            and not (_field_text(item.get("host")) or _field_text(item.get("hostname")))
            and (_field_text(item.get("url")) or _field_text(item.get("input")))
        ):
            bits.append("httpx-input" if from_input else "httpx-url")
        detail = f" ({', '.join(bits)})" if bits else ""
        records.append(
            finding(
                PREFIX,
                host,
                f"Exposed hostname {host}",
                description=f"{host} published on the internet{detail}.",
                severity=sev,
                source=SOURCE,
                related_assets=[host],
                labels=["easm", "exposed"] + (["httpx-input"] if from_input else []),
                extra=control_extra(
                    "CTL-EASM-EXPOSURE",
                    "Reduce internet-facing attack surface",
                    csf_function="identify",
                    priority="2",
                    category="technical",
                ),
            )
        )
    return records


def _is_amass_dict(item: dict[str, Any]) -> bool:
    """OWASP Amass JSON/JSONL objects use name/fqdn, not httpx or subfinder host."""
    if not isinstance(item, dict) or _is_httpx_dict(item):
        return False
    if item.get("host") or item.get("hostname"):
        return False
    if item.get("fqdn") or item.get("FQDN"):
        return True
    name = item.get("name")
    if not isinstance(name, str) or not name.strip() or _looks_like_url(name):
        return False
    if item.get("domain") or item.get("tag") or item.get("sources") or item.get("addresses"):
        return True
    return "." in name.strip().strip(".")


def _amass_name_lists(item: dict[str, Any]) -> bool:
    if not isinstance(item, dict) or _is_httpx_dict(item):
        return False
    for key in ("names", "subdomains", "domains"):
        blob = item.get(key)
        if isinstance(blob, list) and blob:
            return True
    return False


def parse_amass_name_lists(item: dict[str, Any]) -> list:
    """OWASP Amass JSON `names` / `subdomains` / `domains` arrays of hosts or {name}/{fqdn}."""
    records: list = []
    for key in ("names", "subdomains", "domains"):
        blob = item.get(key)
        if not isinstance(blob, list):
            continue
        for entry in blob:
            if isinstance(entry, str):
                text = entry.strip()
                if not text or text.startswith("#"):
                    continue
                records.extend(parse_amass_json_item({"name": text}))
            elif isinstance(entry, dict):
                records.extend(parse_amass_json_item(entry))
    return records


def parse_amass_json_item(item: dict[str, Any]) -> list:
    raw = item.get("fqdn") or item.get("FQDN") or item.get("name") or item.get("hostname") or ""
    if _looks_like_url(str(raw)):
        return parse_httpx_item(str(raw))
    host = normalize_host(raw)
    if not host:
        return []
    rec = _host_asset(host)
    rec.labels = list(rec.labels or []) + ["amass"]
    records: list = [rec]
    if any(tok in host.lower() for tok in ("vpn.", "dev-api.", "staging.", "admin")):
        records.append(
            finding(
                PREFIX,
                f"AMASS-{host}",
                f"Enumerated exposed name {host}",
                description=f"Amass JSON inventory contains {host}.",
                severity="medium",
                source=SOURCE,
                related_assets=[host],
                labels=["easm", "enum", "amass"],
                extra=control_extra(
                    "CTL-DNS-HYGIENE",
                    "DNS and subdomain hygiene",
                    csf_function="identify",
                    priority="3",
                ),
            )
        )
    return records


def parse_amass_text(path: Path) -> list:
    records: list = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if _looks_like_url(raw):
            records.extend(parse_httpx_item(raw))
            continue
        host = normalize_host(raw)
        if not host:
            continue
        records.append(_host_asset(host))
        if any(tok in host.lower() for tok in ("vpn.", "dev-api.", "staging.", "admin")):
            records.append(
                finding(
                    PREFIX,
                    f"AMASS-{host}",
                    f"Enumerated exposed name {host}",
                    description=f"Amass/subfinder demo inventory contains {host}.",
                    severity="medium",
                    source=SOURCE,
                    related_assets=[host],
                    labels=["easm", "enum"],
                    extra=control_extra(
                        "CTL-DNS-HYGIENE",
                        "DNS and subdomain hygiene",
                        csf_function="identify",
                        priority="3",
                    ),
                )
            )
    return records


def _dict_host(item: dict[str, Any]) -> str:
    for key in ("host", "hostname", "fqdn", "FQDN", "input", "url", "URL"):
        text = _field_text(item.get(key))
        if text:
            return text
    return ""


def _is_httpx_dict(item: dict[str, Any]) -> bool:
    if item.get("status_code") is not None or item.get("title") is not None:
        return True
    if item.get("tech") is not None or item.get("webserver") is not None:
        return True
    if item.get("content_length") is not None:
        return True
    host_field = _field_text(item.get("host")) or _field_text(item.get("hostname")) or _field_text(item.get("fqdn"))
    url_field = _field_text(item.get("url")) or _field_text(item.get("URL"))
    input_field = _field_text(item.get("input"))
    if url_field and not host_field:
        return True
    if _looks_like_url(url_field):
        return True
    if _looks_like_url(input_field) or _looks_like_url(host_field):
        return True
    return False


def parse_subfinder_host(host: str) -> list:
    if _looks_like_url(host):
        return parse_httpx_item(host)
    host = normalize_host(host)
    if not host:
        return []
    records = [_host_asset(host)]
    if any(tok in host.lower() for tok in ("vpn.", "dev-api.", "staging.", "admin")):
        records.append(
            finding(
                PREFIX,
                f"SUB-{host}",
                f"Subfinder enumerated {host}",
                description=f"Subfinder demo inventory contains {host}.",
                severity="medium",
                source=SOURCE,
                related_assets=[host],
                labels=["easm", "subfinder"],
                extra=control_extra(
                    "CTL-DNS-HYGIENE",
                    "DNS and subdomain hygiene",
                    csf_function="identify",
                    priority="3",
                ),
            )
        )
    return records


def _finding_host_kind(rec: Any) -> tuple[str, str] | None:
    if getattr(rec, "kind", None) != "finding":
        return None
    related = list(getattr(rec, "related_assets", None) or [])
    host = str(related[0] if related else getattr(rec, "name", "") or "").strip().lower().rstrip(".")
    if not host:
        return None
    labels = {str(x).lower() for x in (getattr(rec, "labels", None) or [])}
    kind = "exposed" if "exposed" in labels else "enum"
    return (host, kind)


def dedupe_findings_by_host_kind(records: list) -> list:
    """Keep one finding per (hostname, enum|exposed); merge labels on collision."""
    seen: dict[tuple[str, str], int] = {}
    out: list = []
    for rec in records:
        key = _finding_host_kind(rec)
        if key is None:
            out.append(rec)
            continue
        if key in seen:
            first = out[seen[key]]
            merged = list(dict.fromkeys(list(first.labels or []) + list(rec.labels or [])))
            first.labels = merged
            continue
        seen[key] = len(out)
        out.append(rec)
    return out


def parse_files(files: list[Path]) -> list:
    records: list = []
    for path in files:
        if path.suffix.lower() in {".txt", ".lst"}:
            records.extend(parse_amass_text(path))
            continue
        for item in load_structured(path):
            if isinstance(item, str):
                if _looks_like_url(item):
                    records.extend(parse_httpx_item(item))
                else:
                    records.extend(parse_subfinder_host(item))
            elif isinstance(item, dict) and _amass_name_lists(item):
                records.extend(parse_amass_name_lists(item))
            elif isinstance(item, dict) and _is_amass_dict(item):
                records.extend(parse_amass_json_item(item))
            elif isinstance(item, dict) and _dict_host(item):
                if _is_httpx_dict(item):
                    records.extend(parse_httpx_item(item))
                else:
                    records.extend(parse_subfinder_host(_dict_host(item)))
            else:
                records.extend(parse_httpx_item(item))
    return dedupe_findings_by_host_kind(records)


def main() -> None:
    files = discover_input_files("easm")
    records = parse_files(files)
    records.append(
        evidence(
            PREFIX,
            "EASM",
            "EASM demo parse",
            description="Parsed Amass txt, JSON {name}/{fqdn}, and names/subdomains arrays; Subfinder JSON/JSONL {host}; httpx including URL-only https://host lines and JSON input when host is empty. No live recon.",
            source=SOURCE,
        )
    )
    emit("easm", records, files)


if __name__ == "__main__":
    main()
