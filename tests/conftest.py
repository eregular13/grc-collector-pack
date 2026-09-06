"""Write clock-independent lab SCOPE files; rewrite expired inline test windows."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.scope_clock import EXPIRED_END, write_lab_scopes, with_open_window


@pytest.fixture(scope="session", autouse=True)
def _write_lab_scopes() -> None:
    write_lab_scopes()


@pytest.fixture(scope="session", autouse=True)
def _seed_pack_out_if_missing() -> None:
    """Clean clone has no out/ (gitignored). Factory tests need stub CSVs. Do not smash a real lab out."""
    root = Path(__file__).resolve().parents[1]
    ciso = root / "out" / "ciso-assistant"
    if not (ciso / "assets.csv").is_file():
        ciso.mkdir(parents=True, exist_ok=True)
        (ciso / "assets.csv").write_text(
            "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets\n",
            encoding="utf-8",
        )
    poam = root / "out" / "poam"
    if not (poam / "poam.csv").is_file():
        poam.mkdir(parents=True, exist_ok=True)
        (poam / "poam.csv").write_text(
            "weakness,asset,severity,control_refs,recommended_action,owner,milestone,status\n",
            encoding="utf-8",
        )
    quote = root / "out" / "quote"
    if not (quote / "quote.csv").is_file():
        quote.mkdir(parents=True, exist_ok=True)
        (quote / "quote.csv").write_text(
            "weakness,asset,severity,control_refs,recommended_action,hours,rate_usd,total_usd,status\n"
            ",,,,,,,draft\n",
            encoding="utf-8",
        )
    sr = root / "out" / "simplerisk"
    if not (sr / "risks_import.csv").is_file():
        sr.mkdir(parents=True, exist_ok=True)
        (sr / "risks_import.csv").write_text("Subject,Status,Category,Scoring,Mitigation,Regulation,Notes\n", encoding="utf-8")


@pytest.fixture(autouse=True)
def _inline_open_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    orig = Path.write_text

    def wrapped(self: Path, data: str | bytes, *args, **kwargs):
        if isinstance(data, str) and EXPIRED_END in data and "window_end" in data:
            data = with_open_window(data)
        return orig(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", wrapped)
