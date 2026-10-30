"""Refuse near-miss schema keys that would otherwise silent-drop findings."""

from __future__ import annotations

from typing import Any


def is_one_edit(a: str, b: str) -> bool:
    """True when a and b differ by exactly one insert, delete, or substitution."""
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    if len(a) > len(b):
        a, b = b, a
    i = j = 0
    skipped = False
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        if skipped:
            return False
        skipped = True
        j += 1
    return True


def refuse_near_list_key(
    container: dict[str, Any],
    expected: str,
    *,
    label: str,
) -> None:
    """Raise when a list sits under a near-miss spelling of ``expected``.

    Catches single-byte inserts/flips that rename a required list key so the
    collector would otherwise return OK with zero (or wrong) rows. Exact
    ``expected`` present → no-op. Non-list values are ignored.
    """
    if expected in container:
        return
    exp_low = expected.lower()
    exp_norm = "".join(c for c in exp_low if c.isalnum())
    for key, val in container.items():
        if not isinstance(val, list):
            continue
        sk = str(key)
        low = sk.lower()
        norm = "".join(c for c in low if c.isalnum())
        near = low == exp_low or norm == exp_norm or is_one_edit(low, exp_low)
        if near:
            raise ValueError(
                f"{label}: unexpected list key {key!r} "
                f"(expected {expected}); refusing silent inventory drop"
            )


def refuse_near_list_keys(
    container: dict[str, Any],
    expected_keys: tuple[str, ...],
    *,
    label: str,
) -> None:
    """Refuse when any of ``expected_keys`` is missing but a near-miss list key exists."""
    for expected in expected_keys:
        if expected in container:
            return
    for expected in expected_keys:
        refuse_near_list_key(container, expected, label=label)
