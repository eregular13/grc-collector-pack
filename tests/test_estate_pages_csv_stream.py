"""Estate-page CSV canon streams without multi-copy blowups (synthetic)."""
from __future__ import annotations

import tracemalloc

from shared.estate_pages import _canonical_csv_forms, normalize_fixture_bytes


def _synthetic_csv(n: int) -> bytes:
    # Unique sorted body rows; TEST-NET style values only.
    lines = ["host,ip,finding"]
    for i in range(n):
        lines.append(
            f"host-{i}.example.test,203.0.113.{(i % 250) + 1},finding-{n - i}"
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def test_csv_canon_deterministic_and_sorted() -> None:
    raw = b"b,a\n2,1\n1,2\n"
    forms = _canonical_csv_forms(raw.decode("utf-8"))
    assert forms
    assert forms[0] == b"b,a\n1,2\n2,1\n"
    assert normalize_fixture_bytes(raw) == forms[0]


def test_csv_canon_traced_memory_stays_near_input() -> None:
    """Traced peak for CSV canon should stay well below the old ~16x slope."""
    data = _synthetic_csv(20000)
    input_mb = len(data) / (1024 * 1024)
    tracemalloc.start()
    before = tracemalloc.take_snapshot()
    forms = _canonical_csv_forms(data.decode("utf-8"))
    after = tracemalloc.take_snapshot()
    tracemalloc.stop()
    assert forms
    stats = after.compare_to(before, "filename")
    # Sum positive size diffs attributable to estate_pages / csv / io.
    growth = 0
    for stat in stats:
        if stat.size_diff > 0:
            growth += stat.size_diff
    growth_mb = growth / (1024 * 1024)
    # Pre-stream profiles sat near 16x input; require a clear reduction.
    assert growth_mb < input_mb * 10, (
        f"CSV canon traced growth {growth_mb:.1f} MB on {input_mb:.2f} MB input "
        f"({growth_mb / max(input_mb, 1e-9):.1f}x)"
    )
