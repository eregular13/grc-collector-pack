from shared.io_util import redact


def test_redact_akia_and_pem() -> None:
    text = "key=AKIAIOSFODNN7EXAMPLE and -----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----"
    out = redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED]" in out
    assert "BEGIN RSA PRIVATE KEY" not in out


def test_redact_nested() -> None:
    payload = {"token": "secret=super-secret-demo-value", "ok": "public"}
    out = redact(payload)
    assert "super-secret-demo-value" not in str(out)
    assert out["ok"] == "public"
