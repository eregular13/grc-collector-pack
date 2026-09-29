"""R5-9: certificate validity/issuance/trust stamps NIST 800-53 SC-17.

Protocol/cipher TLS stays SC-8 / SC-13. SAMPLE/DEMO != client KEEP.
No POST /api/risks.
"""

from __future__ import annotations

import pytest

from shared.control_map import is_pki_certificate_finding, map_finding
from shared.finding_types import finding_type
from shared.schema import make_record


def _rec(**kwargs):
    extra = dict(kwargs.pop("extra", {}) or {})
    labels = list(kwargs.pop("labels", []) or [])
    return make_record(
        kind="finding",
        source=kwargs.pop("source", "vuln-scan"),
        ref_id=kwargs.pop("ref_id", "R5-9"),
        name=kwargs.pop("name", "finding"),
        description=kwargs.pop("description", ""),
        severity=kwargs.pop("severity", "high"),
        category=kwargs.pop("category", "vulnerability"),
        assets=kwargs.pop("assets", ["vpn.example.com"]),
        labels=labels,
        extra=extra,
    )


def test_expired_cert_is_pki_and_carries_sc17() -> None:
    rec = _rec(
        name="cert_expirationStatus",
        description="Certificate expired (2020-01-01)",
        labels=["testssl"],
        extra={"id": "cert_expirationStatus"},
    )
    assert finding_type(rec) == "tls_cert_expiration"
    assert is_pki_certificate_finding(rec) is True
    n53 = set(map_finding(rec).get("nist_800_53") or [])
    assert "SC-17" in n53
    assert "SC-8" in n53


def test_wildcard_and_caa_issuance_gain_sc17() -> None:
    wildcard = _rec(
        name="Wildcard certificate trust is too broad",
        description="certificate trust includes a wildcard SAN",
        labels=["testssl"],
        extra={"id": "cert_trust_wildcard"},
    )
    caa = _rec(
        name="CAA DNS record is missing or invalid",
        description="DNS CAA record is missing",
        labels=["testssl"],
        extra={"id": "DNS_CAArecord"},
    )
    assert is_pki_certificate_finding(wildcard) is True
    assert is_pki_certificate_finding(caa) is True
    assert "SC-17" in set(map_finding(wildcard).get("nist_800_53") or [])
    assert "SC-17" in set(map_finding(caa).get("nist_800_53") or [])
    assert "nist80053_SC-17" in map_finding(wildcard)["framework_refs"]


def test_self_signed_and_untrusted_issuer_gain_sc17() -> None:
    rec = _rec(
        name="TLS certificate is self-signed",
        description="https listener presents an untrusted issuer chain",
        extra={"port": "443", "service": "https"},
    )
    assert is_pki_certificate_finding(rec) is True
    assert "SC-17" in set(map_finding(rec).get("nist_800_53") or [])


def test_tls_protocol_weakness_does_not_gain_sc17() -> None:
    proto = _rec(
        name="TLS 1.0 is offered",
        description="Deprecated TLS 1.0 on the listener",
        labels=["testssl"],
        extra={"id": "TLS1"},
    )
    cipher = _rec(
        name="Weak TLS cipher suites are offered",
        description="RC4 and 3DES are offered",
        extra={"check_id": "nse-tls-weak-cipher"},
    )
    heartbleed = _rec(
        name="Heartbleed",
        description="TLS stack is vulnerable to Heartbleed",
        extra={"id": "heartbleed"},
    )
    assert finding_type(proto) == "tls_1_0"
    assert is_pki_certificate_finding(proto) is False
    assert is_pki_certificate_finding(cipher) is False
    assert is_pki_certificate_finding(heartbleed) is False
    assert "SC-17" not in set(map_finding(proto).get("nist_800_53") or [])
    assert "SC-17" not in set(map_finding(cipher).get("nist_800_53") or [])
    assert "SC-17" not in set(map_finding(heartbleed).get("nist_800_53") or [])
    assert {"SC-8", "SC-13"} <= set(map_finding(proto).get("nist_800_53") or [])


def test_https_port_only_is_not_pki() -> None:
    rec = _rec(
        source="easm",
        name="HTTPS exposed",
        description="https listener on vpn.example.com",
        extra={"port": "443", "service": "https"},
    )
    assert is_pki_certificate_finding(rec) is False
    assert "SC-17" not in set(map_finding(rec).get("nist_800_53") or [])


@pytest.mark.parametrize(
    ("extra", "name", "description"),
    [
        ({"plugin_id": "51192"}, "SSL Certificate Cannot Be Trusted", "The server certificate cannot be trusted"),
        ({"plugin_id": "45411"}, "SSL Certificate with Wrong Hostname", "Certificate common name does not match the hostname"),
        ({"plugin_id": "15901"}, "SSL Certificate Expiry", "The certificate has already expired"),
        ({"id": "mismatched-ssl-certificate"}, "mismatched-ssl-certificate", "certificate hostname mismatch"),
        ({"template_id": "untrusted-root-certificate"}, "untrusted-root-certificate", "untrusted root certificate"),
        ({"id": "revoked-ssl-certificate"}, "revoked-ssl-certificate", "certificate revoked by the issuer"),
        ({"id": "cert_trust"}, "cert_trust", "hostname mismatch versus the presented SAN"),
    ],
)
def test_sc17_per_plugin_and_template_id(extra: dict, name: str, description: str) -> None:
    rec = _rec(name=name, description=description, extra=extra)
    assert is_pki_certificate_finding(rec) is True
    n53 = list(map_finding(rec).get("nist_800_53") or [])
    assert "SC-17" in n53


@pytest.mark.parametrize(
    ("extra", "name"),
    [
        ({"plugin_id": "35291"}, "SSL Certificate Signed Using Weak Hashing Algorithm"),
        ({"id": "cert_signatureAlgorithm"}, "cert_signatureAlgorithm"),
    ],
)
def test_weak_signature_sc13_primary_plus_sc17(extra: dict, name: str) -> None:
    rec = _rec(
        name=name,
        description="Certificate signed with SHA-1",
        extra=extra,
    )
    n53 = list(map_finding(rec).get("nist_800_53") or [])
    assert "SC-13" in n53
    assert "SC-17" in n53
    assert n53.index("SC-13") < n53.index("SC-17")


def test_caa_id_and_text_branch_gain_sc17() -> None:
    via_id = _rec(
        name="CAA DNS record is missing or invalid",
        description="DNS CAA record is missing",
        labels=["testssl"],
        extra={"id": "DNS_CAArecord"},
    )
    via_text = _rec(
        name="Missing CAA record",
        description="Authoritative DNS has no CAA record",
        extra={},
    )
    vacation = _rec(
        name="Vacation record",
        description="HR vacation record is missing",
        extra={},
    )
    assert is_pki_certificate_finding(via_id) is True
    assert is_pki_certificate_finding(via_text) is True
    assert is_pki_certificate_finding(vacation) is False
    assert "SC-17" in set(map_finding(via_id).get("nist_800_53") or [])
    assert "SC-17" in set(map_finding(via_text).get("nist_800_53") or [])
    assert "SC-17" not in set(map_finding(vacation).get("nist_800_53") or [])


def test_cipher_or_protocol_mentioning_self_signed_is_not_sc17() -> None:
    cipher = _rec(
        name="Weak TLS cipher suites are offered",
        description="RC4 offered; certificate issuer: Let's Encrypt; self-signed cert in the handshake dump",
        extra={"check_id": "nse-tls-weak-cipher"},
    )
    proto = _rec(
        name="TLS 1.0 is offered",
        description="Deprecated TLS 1.0; certificate issuer: self-signed",
        labels=["testssl"],
        extra={"id": "TLS1"},
    )
    assert is_pki_certificate_finding(cipher) is False
    assert is_pki_certificate_finding(proto) is False
    assert "SC-17" not in set(map_finding(cipher).get("nist_800_53") or [])
    assert "SC-17" not in set(map_finding(proto).get("nist_800_53") or [])
