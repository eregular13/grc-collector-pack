from shared.schema import (
    canon_severity,
    ciso_finding_severity,
    ciso_vuln_severity,
    control_priority,
    csf_function,
    make_record,
    map_severity,
    residual_level,
    rr_likelihood_impact,
    scenario_level,
)


def test_severity_aliases() -> None:
    assert canon_severity("CRITICAL") == "critical"
    assert canon_severity("informational") == "info"
    assert canon_severity("med") == "medium"
    assert canon_severity("WARNING") == "medium"
    assert canon_severity("WARN") == "medium"
    assert canon_severity("ERROR") == "high"
    assert canon_severity("MODERATE") == "medium"
    assert canon_severity("IMPORTANT") == "high"
    assert canon_severity("danger") == "high"
    assert canon_severity("NOTICE") == "low"
    assert canon_severity("7.5") == "high"
    assert canon_severity("9.8") == "critical"
    assert canon_severity("3.9") == "low"
    assert canon_severity("0") == "info"


def test_unknown_severity_is_medium_and_flagged() -> None:
    sev, unmapped = map_severity("nope")
    assert sev == "medium"
    assert unmapped is True
    assert canon_severity("nope") == "medium"
    rec = make_record(
        kind="finding",
        source="code-secrets",
        ref_id="CODE-x",
        name="unknown band",
        severity="purple",
        extra={"rule": "x"},
    )
    assert rec["severity"] == "medium"
    assert rec["extra"]["severity_unmapped"] is True
    assert rec["extra"]["severity_raw"] == "purple"


def test_empty_severity_is_info_unmapped_not_high() -> None:
    sev, unmapped = map_severity(None)
    assert sev == "info"
    assert unmapped is True
    blank, blank_unmapped = map_severity("")
    assert blank == "info"
    assert blank_unmapped is True
    assert canon_severity(None) != "high"
    rec = make_record(kind="finding", source="x", ref_id="r", name="n", severity="")
    assert rec["severity"] == "info"
    assert rec["extra"].get("severity_unmapped") is True


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
