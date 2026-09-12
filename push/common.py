"""Shared helpers for GRC importers. No RiskReady HTTP. No /api/risks."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PACK = Path(__file__).resolve().parents[1]


def gate_file(name: str) -> Path:
    return PACK / "push" / f"GATE_{name.upper()}"


def gate_present(name: str) -> bool:
    return gate_file(name).is_file()


def refuse_live_without_gate(name: str) -> None:
    """Missing gate → exit 2, no socket."""
    if not gate_present(name):
        raise SystemExit(2)


def canonical_dir() -> Path:
    return PACK / "out" / "canonical"


def load_canonical_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    folder = canonical_dir()
    if not folder.is_dir():
        return rows
    for path in sorted(folder.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                rec["_sensor"] = path.stem
                rows.append(rec)
    return rows


def split_canonical(rows: list[dict[str, Any]] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows = rows if rows is not None else load_canonical_rows()
    assets = [r for r in rows if r.get("kind") == "asset"]
    findings = [r for r in rows if r.get("kind") == "finding"]
    return assets, findings
