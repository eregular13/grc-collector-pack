"""R6-5: empty / whitespace CLIENT name renders a clean exec-summary sentence.

No empty quotes, no dangling words. SAMPLE/DEMO != client KEEP.
No POST /api/risks.
"""

from __future__ import annotations

import re

from shared.estate_pages import (
    LABEL_FOR_KIND,
    NOT_RECORDED,
    SENTENCE_FOR_KIND,
    EstateStamp,
    PageContext,
    build_executive_summary,
    build_scope_and_trust,
    classify_estate,
    engagement_name,
    exec_lede,
    md_code_span,
    md_safe_text,
    md_table_code_span,
    write_csv_with_estate,
    write_estate_sidecar,
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


HOSTILE = "Acme**\n\n# PWNED [x](javascript:void(0)) <script>"


def test_md_safe_text_keeps_normal_names_readable() -> None:
    assert md_safe_text("Acme Health") == "Acme Health"
    assert md_safe_text("O'Reilly & Co-Santé") == "O'Reilly & Co-Santé"
    assert md_safe_text("Ac\u200cme") == "Ac\u200cme"
    assert md_safe_text("\ufeffAcme\u200b") == "Acme"
    assert engagement_name("O'Reilly & Co-Santé") == "O'Reilly & Co-Santé"


def test_exec_lede_and_banner_neutralize_markdown_injection() -> None:
    stamp = _stamp(
        kind="CLIENT",
        label=f"CLIENT: {HOSTILE}",
        client_name=HOSTILE,
    )
    lede = exec_lede(stamp)
    banner = stamp.banner_md()
    summary = build_executive_summary(PageContext(stamp=stamp, records=[]))
    trust = build_scope_and_trust(PageContext(stamp=stamp, records=[]))
    for blob in (lede, banner, summary, trust):
        assert not re.search(r"(?m)^# PWNED", blob)
        assert "[x](javascript:" not in blob
        assert "<script>" not in blob
        assert not re.search(r"(?<!\\)<script>", blob)
        assert "<img" not in blob
        assert "**\n" not in blob
    assert "Acme" in lede
    assert lede.count("\n") == 0
    assert banner.splitlines()[0].startswith("> **CLIENT: Acme")
    assert banner.splitlines()[0].count("**") == 2
    assert all(line.startswith(">") for line in banner.splitlines())
    assert "\\*" in lede
    assert "\\#" in lede
    assert "\\[x\\]" in lede
    assert "&lt;script&gt;" in lede


def test_csv_estate_column_keeps_raw_client_name(tmp_path) -> None:
    stamp = _stamp(
        kind="CLIENT",
        label=f"CLIENT: {HOSTILE}",
        client_name=HOSTILE,
    )
    path = tmp_path / "poam.csv"
    write_csv_with_estate(path, ["weakness", "estate"], [["x", ""]], stamp)
    text = path.read_text(encoding="utf-8")
    assert HOSTILE.splitlines()[0] in text or "Acme**" in text
    assert "<script>" in text


def test_authorizer_fields_are_escaped_on_scope_page(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GRC_AUTHORIZER", "Pat**\n\n# AUTH [x](javascript:void(0))")
    monkeypatch.setenv("GRC_AUTH_DATE", "2026-10-01**\n\n# DATE [x](javascript:void(0))")
    monkeypatch.setenv("GRC_SCOPE_REF", "SCOPE <script>")
    stamp = _stamp(kind="CLIENT", label="CLIENT: Acme", client_name="Acme")
    trust = build_scope_and_trust(PageContext(stamp=stamp, records=[], in_dir=tmp_path))
    assert not re.search(r"(?m)^# AUTH", trust)
    assert not re.search(r"(?m)^# DATE", trust)
    assert "[x](javascript:" not in trust
    assert "<script>" not in trust
    assert "Pat" in trust
    assert "2026-10-01" in trust
    assert "\\*" in trust
    assert "\\# DATE" in trust or "\\#" in trust
    assert "&lt;script&gt;" in trust


def test_md_safe_text_kills_backtick_cr_underscore_tilde_backslash() -> None:
    ticks = md_safe_text("a `b` c")
    assert "`" not in ticks.replace("\\`", "")
    assert "\\`" in ticks
    cr = md_safe_text("A\r- x")
    assert "\r" not in cr
    assert md_safe_text("_u_") == "\\_u\\_"
    assert md_safe_text("~~s~~") == "\\~\\~s\\~\\~"
    assert md_safe_text("\\*x\\*") == "\\\\\\*x\\\\\\*"


def test_exec_lede_mixed_escapes_client_name() -> None:
    lede = exec_lede(
        None,
        label="MIXED: REVIEW BEFORE USE",
        kind="MIXED",
        client_name="Acme**\n# x <script>",
    )
    assert "\\*" in lede
    assert "&lt;" in lede
    assert "\n# x" not in lede
    assert "<" not in lede
    assert ">" not in lede


def test_estate_txt_does_not_escape_fallback_underscores() -> None:
    stamp = classify_estate(
        [
            {"labels": ["demo"], "source": "fixtures/demo"},
            {"labels": ["nmap"], "source": "inventory-nmap"},
        ],
        fallback_files=["nmap/c4rtographer_udpConnect"],
    )
    assert stamp.kind == "MIXED"
    assert "c4rtographer_udpConnect" in stamp.sentence
    assert "\\_" not in stamp.sentence
    plain = stamp.banner_plain()
    assert "c4rtographer_udpConnect" in plain
    assert "\\_" not in plain
    assert "c4rtographer\\_udpConnect" in stamp.banner_md()


def test_banner_code_span_fences_inner_ticks() -> None:
    stamp = _stamp(
        kind="SAMPLE",
        run_id="r1` <img src=x onerror=alert(2)> `",
        pack_commit="dead`beef",
    )
    banner = stamp.banner_md()
    assert md_code_span(stamp.run_id) in banner
    assert md_code_span(stamp.pack_commit) in banner
    assert md_code_span(stamp.run_id).startswith("``")
    trust = build_scope_and_trust(PageContext(stamp=stamp, records=[]))
    assert md_code_span(stamp.run_id) in trust
    assert md_code_span(stamp.pack_commit) in trust


def test_exec_summary_escapes_scanner_hostnames() -> None:
    evil = "evil](http://evil.invalid)<img src=x onerror=alert(3)>|x|`t`.invalid"
    rec = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-evil",
        "name": "Open port <img src=x onerror=alert(1)>",
        "description": "hostile PTR",
        "severity": "high",
        "category": "exposure",
        "assets": [evil],
        "labels": ["nmap"],
        "extra": {"port": "21", "check_id": "nmap-port-21"},
    }
    text = build_executive_summary(
        PageContext(stamp=_stamp(kind="SAMPLE"), records=[rec], findings=[rec])
    )
    assert "<img" not in text
    assert "&lt;img" in text
    assert "|x|" not in text
    assert "\\|" in text
    assert "&lt;" in text


def test_write_probo_readme_escapes_client_name(tmp_path, monkeypatch) -> None:
    from exporters.model import PackEstate
    from exporters.probo import write_probo

    (tmp_path / "ciso-assistant").mkdir()
    (tmp_path / "ciso-assistant" / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n",
        encoding="utf-8",
    )
    stamp = _stamp(
        kind="CLIENT",
        label=f"CLIENT: {HOSTILE}",
        client_name=HOSTILE,
    )
    estate = PackEstate(sample=False, demo=False, lab=False)
    monkeypatch.setattr(estate, "estate_stamp", lambda: stamp)
    write_probo(tmp_path, estate=estate)
    readme = (tmp_path / "probo" / "README.md").read_text(encoding="utf-8")
    assert "[x](javascript:" not in readme
    assert "&lt;script&gt;" in readme
    assert "<script>" not in readme
    assert "\\*" in readme


def test_md_safe_text_autolink_uses_html_entities() -> None:
    """GFM autolinks swallow \\ before <; entities stay inert. See review B2."""
    payloads = (
        "http://x.invalid<img src=x onerror=alert&lpar;1&rpar;//>",
        "https://x.invalid/p<svg onload=alert&lpar;1&rpar;//>",
        "www.x.invalid<img src=x onerror=alert&lpar;1&rpar;//>",
    )
    for raw in payloads:
        escaped = md_safe_text(raw)
        assert "<" not in escaped
        assert ">" not in escaped
        assert "&lt;" in escaped
        assert "&gt;" in escaped
        assert "\\<" not in escaped
        assert "\\>" not in escaped


def test_estate_txt_client_metachar_stays_plain(tmp_path) -> None:
    """m62: ESTATE.txt is banner_plain — CLIENT metachars are not md_safe_text."""
    stamp = _stamp(
        kind="CLIENT",
        label="CLIENT: Acme**#x",
        client_name="Acme**#x",
    )
    path = write_estate_sidecar(tmp_path, stamp)
    text = path.read_text(encoding="utf-8")
    assert "Acme**#x" in text
    assert "\\*" not in text
    assert md_safe_text("Acme**#x") not in text


def test_exec_summary_pipe_in_ref_stays_one_cell() -> None:
    rec = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-A|B",
        "name": "Open port 21",
        "description": "x",
        "severity": "high",
        "category": "exposure",
        "assets": ["h"],
        "labels": ["nmap"],
        "extra": {"port": "21", "check_id": "nmap-port-21"},
    }
    text = build_executive_summary(
        PageContext(stamp=_stamp(kind="SAMPLE"), records=[rec], findings=[rec])
    )
    row = next(line for line in text.splitlines() if line.startswith("| 1 |"))
    assert row.count("|") == 7
    assert md_table_code_span("NMAP-A|B") in row
    assert "`NMAP-A|" not in row


def test_estate_txt_is_plain_via_banner_plain(tmp_path) -> None:
    stamp = _stamp(
        kind="SAMPLE",
        label="SAMPLE DATA: NOT A CLIENT",
        run_id="r1`tick",
        pack_commit="dead`beef",
        client_name="Acme_Health",
    )
    path = write_estate_sidecar(tmp_path, stamp)
    text = path.read_text(encoding="utf-8")
    assert stamp.banner_plain() in text
    assert "\\_" not in text
    assert "`r1" not in text
    assert "r1`tick" in text or "r1tick" in text
    assert "Run `" not in text
    assert "pack `" not in text
    md = stamp.banner_md()
    assert md_code_span(stamp.run_id) in md
    assert "`" in md


def test_md_code_span_collapses_newlines_and_keeps_ticks() -> None:
    assert "\n" not in md_code_span("r1\n# heading")
    assert md_code_span("a`b`c") == "``a`b`c``"
    assert md_code_span("") == f"`{NOT_RECORDED}`"
    assert md_code_span("``ab") == "``` ``ab ```"


def test_md_table_code_span_does_not_split_on_pipe() -> None:
    assert "|" not in md_table_code_span("A|B")
    assert md_table_code_span("A|B") == "`A/B`"


def test_exec_summary_code_spans_ref_id(tmp_path) -> None:
    rec = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-`evil`<img>",
        "name": "Open port 21",
        "description": "x",
        "severity": "high",
        "category": "exposure",
        "assets": ["h"],
        "labels": ["nmap"],
        "extra": {"port": "21", "check_id": "nmap-port-21"},
    }
    text = build_executive_summary(
        PageContext(stamp=_stamp(kind="SAMPLE"), records=[rec], findings=[rec])
    )
    assert md_code_span(rec["ref_id"]) in text
    assert rec["ref_id"] in md_code_span(rec["ref_id"])
    assert md_code_span(rec["ref_id"]).startswith("``")


def test_scope_env_fields_are_escaped(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GRC_COLLECTED_BY", "Pat**\n# WHO <script>")
    monkeypatch.setenv("GRC_REVIEWER", "Rev**\n# REV <img>")
    monkeypatch.setenv("GRC_VERIFY_COMMAND", "sha` <img src=x>")
    monkeypatch.setenv("GRC_CONTACT", "ops <script>@x.invalid")
    stamp = _stamp(kind="CLIENT", label="CLIENT: Acme", client_name="Acme")
    trust = build_scope_and_trust(PageContext(stamp=stamp, records=[], in_dir=tmp_path))
    assert not re.search(r"(?m)^# WHO", trust)
    assert not re.search(r"(?m)^# REV", trust)
    assert "<script>" not in trust
    assert "&lt;script&gt;" in trust
    assert md_code_span("sha` <img src=x>") in trust
    assert md_code_span("sha` <img src=x>").startswith("``")
