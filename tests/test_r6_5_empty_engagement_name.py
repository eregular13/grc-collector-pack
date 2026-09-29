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


def test_engagement_name_strips_zwsp_and_bom() -> None:
    assert engagement_name("\ufeff") == ""
    assert engagement_name("\u200b") == ""
    assert engagement_name("\ufeff\u200b") == ""
    assert engagement_name("\ufeffAcme Health") == "Acme Health"
    assert engagement_name("Acme\u200b") == "Acme"


def test_engagement_name_strips_unicode_cf() -> None:
    # Cf-only → empty. Joiners in a real name stay in the displayed form.
    assert engagement_name("\u200c") == ""
    assert engagement_name("\u200d") == ""
    assert engagement_name("\u2060") == ""
    assert engagement_name("\u00ad") == ""
    assert engagement_name("\u200c\u200d\u2060\u00ad") == ""
    assert engagement_name("Ac\u200cme") == "Ac\u200cme"
    assert engagement_name("\u00adAcme\u2060") == "Acme"
    assert exec_lede(_stamp(kind="CLIENT", label="CLIENT: ", client_name="\u200c\u00ad")) == (
        "**This assessment**."
    )


def test_engagement_name_keeps_persian_and_hindi_joiners() -> None:
    persian = "\u0646\u0631\u0645\u200c\u0627\u0641\u0632\u0627\u0631"  # نرم‌افزار
    hindi = "\u0915\u094d\u200d\u0937"  # क्‍ष
    assert engagement_name(persian) == persian
    assert engagement_name(hindi) == hindi
    lede = exec_lede(
        _stamp(kind="CLIENT", label=f"CLIENT: {persian}", client_name=persian)
    )
    assert lede == f"**CLIENT: {persian}**. {persian}."
    assert persian in lede


def test_exec_lede_zwsp_and_bom_client_is_neutral() -> None:
    zwsp = exec_lede(_stamp(kind="CLIENT", label="CLIENT: ", client_name="\u200b"))
    bom = exec_lede(_stamp(kind="CLIENT", label="CLIENT: \ufeff", client_name="\ufeff"))
    assert zwsp == "**This assessment**."
    assert bom == "**This assessment**."
    assert "CLIENT:" not in zwsp
    assert ". ." not in zwsp


def test_banner_md_empty_client_is_this_assessment() -> None:
    stamp = _stamp(kind="CLIENT", label="CLIENT: ", client_name="\u200b")
    banner = stamp.banner_md()
    assert banner.startswith("> **This assessment**:")
    assert "CLIENT:" not in banner.splitlines()[0]


def test_banner_and_lede_non_client_keep_kind_name() -> None:
    sample = _stamp(kind="SAMPLE", client_name="")
    demo = _stamp(kind="DEMO", client_name="\ufeff")
    named = _stamp(kind="SAMPLE", client_name="Fixture Org")
    assert sample.banner_md().startswith(f"> **{LABEL_FOR_KIND['SAMPLE']}**:")
    assert demo.banner_md().startswith(f"> **{LABEL_FOR_KIND['DEMO']}**:")
    assert exec_lede(sample) == f"**{LABEL_FOR_KIND['SAMPLE']}**."
    assert exec_lede(demo) == f"**{LABEL_FOR_KIND['DEMO']}**."
    assert exec_lede(named) == f"**{LABEL_FOR_KIND['SAMPLE']}**. Fixture Org."
    assert "This assessment" not in exec_lede(sample)
    assert "not recorded." not in exec_lede(demo)
