#!/usr/bin/env python3
"""Parse dropped SPF/DKIM/DMARC/MX/cert snapshots into canonical JSONL.

Parse-only. Does not run dig, openssl, checkdmarc, or any live DNS/TLS probe.
Operator live checks live in shared.dns_email_live behind --live + SCOPE.
"""

from __future__ import annotations

from pathlib import Path

from shared.dns_email import SOURCE, parse_file as parse_dns_email
from shared.io_util import run_collector

LABELS = ["dns-email", "email-dns"]


def parse_file(path: Path) -> list[dict]:
    return parse_dns_email(path)


def main() -> None:
    run_collector(SOURCE, (".json", ".jsonl", ".txt", ".pem", ".crt", ".cer"), parse_file)


if __name__ == "__main__":
    main()
