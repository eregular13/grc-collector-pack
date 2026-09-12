from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
FORBIDDEN_RUN = ("curl", "invoke-webrequest", "iwr ")


def _ok_mention(line: str) -> bool:
    lowered = line.lower()
    return any(
        token in lowered
        for token in ("never", "forbidden", "do not", "don't", "not ", "wrap_dead", "stay-out", "stay out")
    )


def test_import_ciso_doc_exists() -> None:
    path = DOCS / "IMPORT_CISO.md"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "CISO_PUSH" in text
    assert "assets.csv" in text
    assert "evidences.csv" in text
    assert "HITL" in text
    assert "FindingsAssessment" in text or "UUID" in text


def test_import_rr_doc_wrap_dead() -> None:
    path = DOCS / "IMPORT_RR.md"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "WRAP_DEAD" in text
    assert "LICENSE-LOCK" in text or "stay-out" in text.lower()


def test_import_probo_doc_exists() -> None:
    assert (DOCS / "IMPORT_PROBO.md").is_file()


def test_import_opengrc_and_real_scan_docs() -> None:
    assert (DOCS / "IMPORT_OPENGRC.md").is_file()
    assert (DOCS / "REAL_SCAN_DROP.md").is_file()


def test_import_docs_do_not_instruct_api_risks_post() -> None:
    for name in ("IMPORT_CISO.md", "IMPORT_RR.md", "IMPORT_PROBO.md", "IMPORT_OPENGRC.md", "REAL_SCAN_DROP.md"):
        text = (DOCS / name).read_text(encoding="utf-8")
        for line in text.splitlines():
            if "POST /api/risks" not in line and "/api/risks" not in line:
                continue
            assert _ok_mention(line), f"{name} looks like a run instruction: {line}"
            assert not any(cmd in line.lower() for cmd in FORBIDDEN_RUN)
