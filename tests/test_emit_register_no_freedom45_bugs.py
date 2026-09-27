"""Regression: do not carry freedom45 emit_risk_register.py bugs.

Frozen emit_risk_register.py minted IDs with Python's salted builtin
hash() (different every process) and could put informational rows on the
POA&M. This pack uses make_ref / fp_v1 (stable) and excludes info.
"""

from __future__ import annotations

import ast
import csv
import subprocess
import sys
from pathlib import Path

import pytest

from collectors.grc_loader import load
from shared.control_map import poam_decision
from shared.io_util import out_dir, write_canonical
from shared.poam_ledger import fp_v1
from shared.schema import make_ref
from shared.web_tls import SOURCE, parse_file

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples" / "web_tls"
EMIT_PATHS = (
    ROOT / "shared" / "web_tls.py",
    ROOT / "shared" / "web_tls_live.py",
    ROOT / "collectors" / "web_tls.py",
    ROOT / "shared" / "schema.py",
    ROOT / "shared" / "poam_ledger.py",
    ROOT / "collectors" / "grc_loader.py",
)


def _builtin_hash_calls(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "hash":
            hits.append(f"{path.name}:{node.lineno}")
    return hits


def test_emit_paths_never_use_salted_builtin_hash() -> None:
    hits: list[str] = []
    for path in EMIT_PATHS:
        hits.extend(_builtin_hash_calls(path))
    assert hits == []
    src = (ROOT / "shared" / "web_tls.py").read_text(encoding="utf-8")
    assert "make_ref" in src
    assert "uuid4" not in src


def test_ref_ids_identical_across_python_processes() -> None:
    snippet = (
        "from pathlib import Path\n"
        "from shared.web_tls import parse_file\n"
        f"p = Path({str(SAMPLES / 'probe-cleartext-http.json')!r})\n"
        "print('\\n'.join(r['ref_id'] for r in parse_file(p)))\n"
    )
    runs = []
    for _ in range(2):
        proc = subprocess.run(
            [sys.executable, "-c", snippet],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        runs.append(proc.stdout)
    assert runs[0] == runs[1]
    ids = [ln for ln in runs[0].splitlines() if ln.strip()]
    assert ids
    assert len(ids) == len(set(ids))
    assert all(i.startswith("WEB-") for i in ids)
    assert make_ref("web-tls", "sense-tls-192-0-2-10-443") == "WEB-sense-tls-192-0-2-10-443"


def test_fp_v1_is_stable_not_salted_hash() -> None:
    recs = parse_file(SAMPLES / "probe-cleartext-http.json")
    high = next(r for r in recs if r["severity"] in {"high", "critical"})
    a = fp_v1(high)
    b = fp_v1(high)
    assert a == b
    assert len(a) == 64
    assert a.isalnum()


def test_info_findings_never_land_on_poam_csv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    recs = parse_file(SAMPLES / "probe-info-only.json")
    high = next(
        r
        for r in parse_file(SAMPLES / "probe-cleartext-http.json")
        if r["severity"] in {"high", "critical"}
    )
    write_canonical(SOURCE, recs + [high])
    summary = load()
    info_refs = {r["ref_id"] for r in recs if r["severity"] == "info"}
    assert info_refs
    for rec in recs:
        if rec["severity"] == "info":
            decision = poam_decision(rec)
            assert decision["include"] is False
            assert decision["reason"] in {"severity_info", "telemetry_info"}
    poam = out_dir() / "poam" / "poam.csv"
    with poam.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    poam_refs = {r.get("finding_ref_id") or r.get("Weakness Source Identifier") or "" for r in rows}
    assert info_refs.isdisjoint(poam_refs)
    assert high["ref_id"] in poam_refs
    excluded = out_dir() / "poam" / "excluded.csv"
    with excluded.open(encoding="utf-8", newline="") as fh:
        ex = list(csv.DictReader(fh))
    ex_refs = {r.get("finding_ref_id") or "" for r in ex}
    assert info_refs <= ex_refs
    assert summary["excluded"] >= len(info_refs)


def test_poam_ids_deterministic_across_two_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    recs = [
        r
        for r in parse_file(SAMPLES / "probe-cleartext-http.json")
        if r["severity"] != "info"
    ]
    assert recs

    def _ids(work: Path) -> list[str]:
        monkeypatch.setenv("OUT_DIR", str(work))
        write_canonical(SOURCE, recs)
        load()
        with (work / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        col = "poam_id" if "poam_id" in rows[0] else "POA&M ID"
        return sorted(r[col] for r in rows)

    first = _ids(tmp_path / "run-a")
    second = _ids(tmp_path / "run-b")
    assert first == second
    assert first
    assert all(i.startswith("EGP-") for i in first)
