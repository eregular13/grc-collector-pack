"""Thin farm adapters. PATH + SCOPE only. Never download or embed scanners."""

from farm.adapters.catalog import (
    LICENSE_CLASSES,
    invoke_slots,
    load_catalog,
    load_slots,
    slot_matrix,
    wired_slots,
)

__all__ = [
    "LICENSE_CLASSES",
    "load_catalog",
    "invoke_slots",
    "load_slots",
    "slot_matrix",
    "wired_slots",
]
