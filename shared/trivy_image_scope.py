"""One-time ID map for the Trivy image-scoped Target rename (PR #250 / s7b).

Before s7b a container-image Result whose Target did not name the image
("Node.js", "Python", "usr/local/bin/gosu") was its own asset. s7b names it
"<image> :: <target>". That changes the asset UID, the per-finding VULN ref and
the package-rollup POA&M ID. This module derives the pre-s7b IDs from the new
names so a prior ledger can be carried across the upgrade as renames, not
remove+add. Nothing here runs unless a scoped name is present.
"""
from __future__ import annotations

import hashlib
from typing import Any, Iterable

SEP = " :: "
RENAME_REASON = "trivy_image_scope_rename"
RENAME_DISPOSITION = "renamed_image_scope"
MAP_FIELDS = ("kind", "old_id", "new_id", "reason")


def split_scoped(name: str) -> tuple[str, str] | None:
    """``"img :: target"`` -> ``("img", "target")``; anything else -> None."""
    text = str(name or "").strip()
    if SEP not in text:
        return None
    image, target = text.split(SEP, 1)
    image, target = image.strip(), target.strip()
    if not image or not target:
        return None
    return image, target


def legacy_target(name: str) -> str:
    got = split_scoped(name)
    return got[1] if got else ""


def legacy_asset_uid(name: str) -> str:
    """Pre-s7b asset UID: the bare Target was the image_ref anchor."""
    target = legacy_target(name)
    if not target:
        return ""
    from shared.asset_ledger import make_asset_uid

    return make_asset_uid("image_ref", target)


def legacy_pkg_poam_id(image_name: str, package: str) -> str:
    """Pre-s7b package-rollup parent ID (``trivy-pkg-v1|<target>|<pkg>``)."""
    target = legacy_target(image_name)
    if not target or not package:
        return ""
    payload = f"trivy-pkg-v1|{target}|{package}".encode("utf-8")
    return "EGP-" + hashlib.sha256(payload).hexdigest()[:10].upper()


def classify_drift(
    prior_ids: Iterable[str],
    current_ids: Iterable[str],
    id_map: Iterable[dict[str, str]] = (),
) -> dict[str, list[Any]]:
    """Snapshot drift with renames: ``{"added", "removed", "renamed"}``.

    A prior ID that maps to a current ID is a rename, not remove+add.
    """
    prior = set(prior_ids)
    current = set(current_ids)
    renamed: list[tuple[str, str]] = []
    claimed_old: set[str] = set()
    claimed_new: set[str] = set()
    for row in id_map:
        old = str(row.get("old_id") or "").strip()
        new = str(row.get("new_id") or "").strip()
        if old and new and old != new and old in prior and old not in current and new in current:
            renamed.append((old, new))
            claimed_old.add(old)
            claimed_new.add(new)
    return {
        "added": sorted(current - prior - claimed_new),
        "removed": sorted(prior - current - claimed_old),
        "renamed": sorted(set(renamed)),
    }
