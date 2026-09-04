from shared.schema import (
    canon_severity,
    ciso_finding_severity,
    ciso_vuln_severity,
    control_priority,
    csf_function,
    make_record,
    residual_level,
    rr_likelihood_impact,
    scenario_level,
)


def test_severity_aliases() -> None:
    assert canon_severity("CRITICAL") == "critical"
    assert canon_severity("informational") == "info"
    assert canon_severity("med") == "medium"
    assert canon_severity("nope") == "info"


def test_ciso_alphabets() -> None:
    assert ciso_finding_severity("info") == "low"
    assert ciso_finding_severity("HIGH") == "high"
    assert ciso_vuln_severity("info") == "Information"
    assert ciso_vuln_severity("critical") == "Critical"


def test_riskready_map() -> None:
    assert rr_likelihood_impact("info") == ("RARE", "NEGLIGIBLE")
    assert rr_likelihood_impact("low") == ("UNLIKELY", "MINOR")
    assert rr_likelihood_impact("medium") == ("POSSIBLE", "MODERATE")
    assert rr_likelihood_impact("high") == ("LIKELY", "MAJOR")
    assert rr_likelihood_impact("critical") == ("ALMOST_CERTAIN", "SEVERE")


def test_scenario_and_controls() -> None:
    assert scenario_level("critical") == "Very High"
    assert residual_level("Very High") == "High"
    assert residual_level("Low") == "Low"
    assert control_priority("critical") == 1
    assert csf_function("low") == "identify"


def test_make_record_rejects_bad_kind() -> None:
    try:
        make_record(kind="nope", source="x", ref_id="r", name="n")
    except ValueError:
        return
    raise AssertionError("expected ValueError")
