"""R5-9: certificate validity/issuance/trust stamps NIST 800-53 SC-17.

Protocol/cipher TLS stays SC-8 / SC-13. SAMPLE/DEMO != client KEEP.
No POST /api/risks.
"""

from __future__ import annotations

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
