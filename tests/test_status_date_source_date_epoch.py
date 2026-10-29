"""status_date honors SOURCE_DATE_EPOCH (UTC civil day) when set."""
from __future__ import annotations

import csv
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PY = os.environ.get("PYTHON") or "python3"
SDE = "1700000000"
SDE_DATE = "2023-11-14"


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def _pack_env(**extra: str) -> dict:
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": f"{ROOT}/scripts:{ROOT}",
            "PYTHON": PY,
            "DRY_RUN": "1",
            "GRC_LIVE_SCAN": "0",
            "CISO_PUSH": "0",
            "RISKREADY_PUSH": "0",
            "DROPBOX_LIVE": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    env.pop("GRC_FIXSTACK", None)
    env.pop("FIXSTACK_OPT_IN", None)
    env.update(extra)
    return env


def _run_sample(work: Path, **env_extra: str) -> subprocess.CompletedProcess:
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    cmd = [str(ROOT / "scripts" / "sample_to_sor.sh"), "--work", str(work)]
    return subprocess.run(
        cmd, cwd=str(ROOT), env=_pack_env(**env_extra), text=True, capture_output=True, timeout=300
    )


def test_local_run_date_uses_source_date_epoch_utc_day(monkeypatch: pytest.MonkeyPatch) -> None:
    from shared.poam_fields import local_run_date

    monkeypatch.setenv("SOURCE_DATE_EPOCH", SDE)
    assert local_run_date().isoformat() == SDE_DATE


def test_sample_poam_status_date_under_source_date_epoch(tmp_path: Path) -> None:
    """Every SAMPLE poam.csv row status_date == UTC day of SOURCE_DATE_EPOCH."""
    work = tmp_path / "sample-sde"
    r = _run_sample(work, SOURCE_DATE_EPOCH=SDE)
    assert r.returncode == 0, ((r.stdout or "") + (r.stderr or ""))[-800:]
    poam = work / "out" / "poam" / "poam.csv"
    assert poam.is_file(), "missing poam.csv"
    rows = list(csv.DictReader(poam.open(encoding="utf-8", newline="")))
    assert rows, "empty poam"
    dates = sorted({(row.get("status_date") or "").strip() for row in rows})
    assert dates == [SDE_DATE], f"expected all status_date={SDE_DATE}, got {dates}"


def test_sample_poam_sha_stable_under_fixed_sde(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    ra = _run_sample(a, SOURCE_DATE_EPOCH=SDE)
    rb = _run_sample(b, SOURCE_DATE_EPOCH=SDE)
    assert ra.returncode == 0 and rb.returncode == 0
    pa = a / "out" / "poam" / "poam.csv"
    pb = b / "out" / "poam" / "poam.csv"
    assert pa.is_file() and pb.is_file()
    assert _sha(pa) == _sha(pb)
