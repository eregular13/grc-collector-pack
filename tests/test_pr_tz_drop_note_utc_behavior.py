"""Fail-before/pass-after: hermetic drop-fresh env forces TZ=UTC."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path


def _load_drop_fresh():
    root = Path(__file__).resolve().parents[1]
    path = root / "tests" / "test_product_lab_drop_fresh.py"
    assert path.is_file(), f"missing {path}"
    spec = importlib.util.spec_from_file_location("product_lab_drop_fresh_fbpa", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_hermetic_env_forces_utc_under_hostile_outer_tz(tmp_path: Path) -> None:
    """Tip entrypoint _hermetic_env must pin TZ=UTC (not inherit outer west TZ).

    Fail-before tz-drop unit: keep-list inherits TZ=Etc/GMT+12.
    Pass-after: env TZ is forced to UTC.
    """
    prev_tz = os.environ.get("TZ")
    try:
        os.environ["TZ"] = "Etc/GMT+12"
        mod = _load_drop_fresh()
        assert hasattr(mod, "_hermetic_env"), "_hermetic_env missing"
        env = mod._hermetic_env(tmp_path / "out", tmp_path / "in")
        assert env.get("TZ") == "UTC", env.get("TZ")
    finally:
        if prev_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = prev_tz
