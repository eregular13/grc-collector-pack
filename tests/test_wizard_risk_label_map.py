"""prior-unit Item B: optional 5x5 label map with provenance (off by default)."""
from __future__ import annotations

import csv
import inspect
import tempfile
from pathlib import Path


def _write_semi_src(path: Path) -> None:
    rows = [
        {
            "ref_id": "RS-2",
            "assets": "db",
            "threat": "T2",
            "name": "Weak crypto",
            "description": "demo",
            "existing_applied_controls": "",
            "current_impact": "Moderate",
            "current_proba": "High",
            "current_risk": "Moderate",
            "additional_controls": "",
            "residual_impact": "Low",
            "residual_proba": "Moderate",
            "residual_risk": "Low",
            "treatment": "mitigate",
        }
    ]
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, delimiter=";", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


_LEVEL_COLS = (
    "current_impact",
    "current_proba",
    "current_risk",
    "residual_impact",
    "residual_proba",
    "residual_risk",
)

_FIVE_X5 = frozenset({"Very Low", "Low", "Medium", "High", "Very High"})


def test_label_map_off_by_default_keeps_moderate():
    from shared.ciso_wizard_map import map_risk_scenarios_for_wizard

    td = Path(tempfile.mkdtemp())
    src, dest = td / "in.csv", td / "out.csv"
    _write_semi_src(src)
    stats = map_risk_scenarios_for_wizard(src, dest, controls=[])
    # default path unchanged: Moderate still present
    text = dest.read_text(encoding="utf-8")
    # parse with whatever delimiter the writer used
    header = text.splitlines()[0]
    delim = ";" if header.count(";") >= header.count(",") else ","
    rows = list(csv.DictReader(text.splitlines(), delimiter=delim))
    assert rows[0]["current_impact"] == "Moderate"
    assert not stats.get("label_map_applied")
    assert not stats.get("label_map_renames")


def test_label_map_5x5_maps_moderate_with_provenance():
    from shared.ciso_wizard_map import map_risk_scenarios_for_wizard

    sig = inspect.signature(map_risk_scenarios_for_wizard)
    # must expose an explicit opt-in (matrix_profile or apply_5x5_label_map)
    assert (
        "matrix_profile" in sig.parameters or "apply_5x5_label_map" in sig.parameters
    ), f"no 5x5 opt-in on signature: {list(sig.parameters)}"

    td = Path(tempfile.mkdtemp())
    src, dest = td / "in.csv", td / "out.csv"
    _write_semi_src(src)
    kwargs = {"controls": []}
    if "matrix_profile" in sig.parameters:
        kwargs["matrix_profile"] = "critical_5x5"
    else:
        kwargs["apply_5x5_label_map"] = True
    stats = map_risk_scenarios_for_wizard(src, dest, **kwargs)
    header = dest.read_text(encoding="utf-8").splitlines()[0]
    delim = ";" if header.count(";") >= header.count(",") else ","
    rows = list(csv.DictReader(dest.read_text(encoding="utf-8").splitlines(), delimiter=delim))
    row = rows[0]
    for col in _LEVEL_COLS:
        val = (row.get(col) or "").strip()
        if val:
            assert val in _FIVE_X5, f"{col}={val!r} not in 5x5 set"
    assert row["current_impact"] == "Medium"
    assert row["residual_proba"] == "Medium"
    renames = stats.get("label_map_renames") or []
    assert renames, "provenance renames missing"
    # each rename records from->to
    joined = " ".join(str(x) for x in renames)
    assert "Moderate" in joined and "Medium" in joined
    assert stats.get("label_map_applied") is True
