"""Optional live DNS TXT/MX for in-SCOPE domains only.

Default is offline. Collectors never import this module.
Requires --live plus a signed SCOPE domain allowlist. No RiskReady POST.
No sockets in collectors/. Uses PATH `dig` only when allowlisted.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from shared.dns_email import SOURCE, parse_payload
from shared.io_util import write_json


class LiveRefuse(SystemExit):
    """Live DNS refused. Exit non-zero."""

    def __init__(self, message: str) -> None:
        super().__init__(f"dns-email live: {message}")


def _default_selectors() -> list[str]:
    raw = os.environ.get("GRC_DKIM_SELECTORS", "selector1,google,default")
    return [p.strip() for p in raw.split(",") if p.strip()]


def _load_scope(scope_path: Path):
    from dropbox.scope import load_scope

    return load_scope(scope_path)


def _allowed_domains(scope) -> list[str]:
    names = []
    for item in list(scope.external_domains) + list(scope.external_hosts):
        host = str(item or "").strip().lower().rstrip(".")
        if host and "*" not in host and "?" not in host and "/" not in host:
            names.append(host)
    return list(dict.fromkeys(names))


def refuse_offscope(scope, domain: str) -> None:
    host = (domain or "").strip().lower().rstrip(".")
    if not host:
        raise LiveRefuse("empty domain")
    if "*" in host or "?" in host or "/" in host:
        raise LiveRefuse(f"refuses wildcard/CIDR {domain!r}")
    if not scope.allows_external_target(host):
        raise LiveRefuse(f"domain not in SCOPE allowlist: {domain}")


def _dig_short(exe: str, rtype: str, name: str, timeout: int) -> list[str]:
    try:
        proc = subprocess.run(
            [exe, "+short", rtype, name],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LiveRefuse(f"dig failed: {exc}") from exc
    lines = []
    for line in (proc.stdout or "").splitlines():
        token = line.strip().rstrip(".")
        if token:
            lines.append(token)
    return lines


def query_domain(domain: str, *, selectors: list[str], timeout: int = 8, dig: str | None = None) -> dict[str, Any]:
    exe = dig or shutil.which("dig")
    if not exe:
        raise LiveRefuse("dig not on PATH — stay file_drop / fixtures")
    txt = _dig_short(exe, "TXT", domain, timeout)
    mx = _dig_short(exe, "MX", domain, timeout)
    dmarc = _dig_short(exe, "TXT", f"_dmarc.{domain}", timeout)
    dkim = []
    for selector in selectors:
        recs = _dig_short(exe, "TXT", f"{selector}._domainkey.{domain}", timeout)
        dkim.append({"selector": selector, "record": recs[0] if recs else ""})
    spf = next((row for row in txt if "v=spf1" in row.lower()), "")
    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc[0] if dmarc else "",
        "dkim": dkim,
        "mx": mx,
        "txt": txt,
        "live": True,
    }


def run_live(
    *,
    scope_path: Path,
    domains: list[str] | None = None,
    selectors: list[str] | None = None,
    dest: Path | None = None,
    timeout: int = 8,
) -> dict[str, Any]:
    scope = _load_scope(scope_path)
    allow = _allowed_domains(scope)
    want = [d.strip().lower().rstrip(".") for d in (domains or allow) if d and d.strip()]
    if not want:
        raise LiveRefuse("no SCOPE external domains/hosts to query")
    sel = selectors or _default_selectors()
    rows = []
    for domain in want:
        refuse_offscope(scope, domain)
        rows.append(query_domain(domain, selectors=sel, timeout=timeout))
    payload = {
        "schema": "dns_email.v1",
        "lane": "email_dns",
        "live": True,
        "dkim_selectors": sel,
        "domains": rows,
    }
    if dest is not None:
        write_json(dest, payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Optional SCOPE-gated DNS TXT/MX (file_drop writer).")
    parser.add_argument("--live", action="store_true", help="Query DNS. Off by default.")
    parser.add_argument("--scope", help="Signed SCOPE.yaml (required with --live).")
    parser.add_argument("--domain", action="append", dest="domains", help="In-SCOPE domain (repeatable).")
    parser.add_argument("--selector", action="append", dest="selectors", help="DKIM selector (repeatable).")
    parser.add_argument("--out", help="Write checkdmarc-style JSON for in/dns_email/.")
    parser.add_argument("--timeout", type=int, default=8)
    args = parser.parse_args(argv)
    if not args.live:
        print("dns-email live: offline (default). Drop fixtures or operator JSON under in/dns_email/.", file=sys.stderr)
        return 0
    if not args.scope:
        raise LiveRefuse("--live requires --scope PATH")
    dest = Path(args.out) if args.out else None
    payload = run_live(
        scope_path=Path(args.scope),
        domains=args.domains,
        selectors=args.selectors,
        dest=dest,
        timeout=args.timeout,
    )
    records = parse_payload(payload)
    print(json.dumps({"wrote": str(dest) if dest else None, "domains": len(payload["domains"]), "records": len(records)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
