"""Uncovered collectors must not silent-zero on corrupt JSON or hostile text."""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.dns_email import parse_file as dns_parse
from shared.honeypot import parse_honeypot
import collectors.host_wazuh as host_wazuh
import collectors.identity_ad as identity_ad


def test_dns_email_truncated_json_loud(tmp_path: Path) -> None:
    dest = tmp_path / "crtsh.json"
    dest.write_text('{"domains":[{"domain":', encoding="utf-8")
    with pytest.raises(ValueError, match="refusing silent"):
        dns_parse(dest)


def test_dns_email_json_shaped_text_loud(tmp_path: Path) -> None:
    dest = tmp_path / "cert-openssl.txt"
    dest.write_text('{"not":"a-cert"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="JSON-shaped input"):
        dns_parse(dest)


def test_dns_email_truncated_cert_text_loud(tmp_path: Path) -> None:
    dest = tmp_path / "cert-openssl.txt"
    dest.write_text("Certificate:\n    Data:\n        Version: 3\n", encoding="utf-8")
    with pytest.raises(ValueError, match="certificate-shaped text"):
        dns_parse(dest)


def test_identity_ad_truncated_bloodhound_json_loud(tmp_path: Path) -> None:
    dest = tmp_path / "bloodhound.json"
    dest.write_text('{"nodes":[{"id":', encoding="utf-8")
    with pytest.raises(ValueError, match="refusing silent"):
        identity_ad.parse_file(dest)


def test_honeypot_truncated_json_loud(tmp_path: Path) -> None:
    dest = tmp_path / "meta.json"
    raw = '{"sensor":"cowrie","events":'
    with pytest.raises(ValueError, match="refusing silent empty"):
        parse_honeypot(dest, raw, now="2026-01-01T00:00:00Z")


def test_lynis_json_shaped_txt_loud(tmp_path: Path) -> None:
    dest = tmp_path / "lynis-report.txt"
    dest.write_text('{"not":"lynis"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="JSON-shaped input"):
        host_wazuh.parse_file(dest)


def test_lynis_truncated_report_loud(tmp_path: Path) -> None:
    dest = tmp_path / "lynis-report.txt"
    dest.write_text("Lynis 3.0\nHostname = demo\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Lynis-shaped report produced no rows"):
        host_wazuh.parse_file(dest)
