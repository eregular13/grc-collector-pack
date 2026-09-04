"""Thin farm adapters. PATH + SCOPE only. Never download or embed scanners."""

from farm.adapters.catalog import LICENSE_CLASSES, load_catalog, load_slots, slot_matrix, wired_slots
from farm.adapters.stubs import argv_for, run_slot

__all__ = [
    "LICENSE_CLASSES",
    "argv_for",
    "load_catalog",
    "load_slots",
    "run_slot",
    "slot_matrix",
    "wired_slots",
]
