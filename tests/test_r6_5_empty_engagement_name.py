"""R6-5: empty / whitespace CLIENT name renders a clean exec-summary sentence.

No empty quotes, no dangling words. SAMPLE/DEMO != client KEEP.
No POST /api/risks.
"""

from __future__ import annotations

from shared.estate_pages import (
    LABEL_FOR_KIND,
    NOT_RECORDED,
    SENTENCE_FOR_KIND,
    EstateStamp,
    PageContext,
    build_executive_summary,
    engagement_name,
    exec_lede,
)


def _stamp(**kwargs) -> EstateStamp:
    kind = kwargs.pop("kind", "SAMPLE")
    label = kwargs.pop("label", LABEL_FOR_KIND.get(kind, "This assessment"))
    sentence = kwargs.pop("sentence", SENTENCE_FOR_KIND.get(kind, SENTENCE_FOR_KIND["SAMPLE"]))
    return EstateStamp(
        kind=kind,
        label=label,
        sentence=sentence,
        **kwargs,
    )


def _lede_line(stamp: EstateStamp) -> str:
    text = build_executive_summary(PageContext(stamp=stamp, records=[]))
    return next(line for line in text.splitlines() if "Assessment window" in line)


def test_engagement_name_empty_and_whitespace() -> None:
    assert engagement_name("") == ""
    assert engagement_name("   ") == ""
    assert engagement_name("\t\n") == ""
    assert engagement_name(None) == ""
    assert engagement_name(NOT_RECORDED) == ""
    assert engagement_name("n/a") == ""
    assert engagement_name("Acme Health") == "Acme Health"


def test_exec_lede_empty_whitespace_and_named() -> None:
    empty = exec_lede(
        _stamp(kind="CLIENT", label="CLIENT: ", client_name=""),
    )
    white = exec_lede(
        _stamp(kind="CLIENT", label="CLIENT:    ", client_name="   "),
    )
    named = exec_lede(
        _stamp(kind="CLIENT", label="CLIENT: Acme Health", client_name="Acme Health"),
    )
    sample = exec_lede(_stamp(kind="SAMPLE", client_name=""))
    assert empty == "**This assessment**."
    assert white == "**This assessment**."
    assert named == "**CLIENT: Acme Health**. Acme Health."
    assert sample == f"**{LABEL_FOR_KIND['SAMPLE']}**."
    assert '""' not in empty
    assert " ." not in empty
    assert empty.count("**") == 2


def test_exec_summary_empty_name_is_neutral_sentence() -> None:
    line = _lede_line(_stamp(kind="CLIENT", label="CLIENT: ", client_name=""))
    assert line.startswith("**This assessment**. Assessment window")
    assert '""' not in line
    assert "CLIENT:  " not in line
    assert ". ." not in line


def test_exec_summary_whitespace_name_is_neutral_sentence() -> None:
    line = _lede_line(_stamp(kind="CLIENT", label="CLIENT:    ", client_name=" \t "))
    assert line.startswith("**This assessment**. Assessment window")
    assert '""' not in line
    assert ". ." not in line


def test_exec_summary_named_client_keeps_name() -> None:
    line = _lede_line(
        _stamp(kind="CLIENT", label="CLIENT: Acme Health", client_name="Acme Health")
    )
    assert line.startswith("**CLIENT: Acme Health**. Acme Health. Assessment window")


def test_exec_summary_sample_omits_empty_org_slot() -> None:
    line = _lede_line(_stamp(kind="SAMPLE", client_name=""))
    assert line.startswith(f"**{LABEL_FOR_KIND['SAMPLE']}**. Assessment window")
    assert "not recorded." not in line.split("Assessment window")[0]
    assert '""' not in line
