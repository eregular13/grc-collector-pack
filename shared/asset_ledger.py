"""Offline file-based asset identity ledger (spec §5 + §6.3).

Public contract for the parallel POA&M fingerprint work:

    from shared.asset_ledger import asset_uid, resolve_asset_id, AssetLedger

    uid = asset_uid(record, ledger)          # EGA- + 10 hex
    uid = resolve_asset_id(record, ledger)   # stable alias of asset_uid

``asset_uid`` / ``resolve_asset_id`` share this signature and never
reach the network. ``ledger=None`` regenerates from the current
strongest alias (lost-ledger behavior) and does not persist.
"""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.asset_ids import (
    ASSET_NAMESPACE,
    ASSET_UID_PREFIX,
    CONTAINER_ORDER,
    LEASE_DAYS,
    MATCH_ORDER,
    STRENGTH,
    display_uai,
    extra_dict,
    fqdn_mac_fingerprint,
    id_values,
    ids_from_record,
    is_container,
    merge_ids,
    prefer_display_name,
    stamp_ids,
    strongest_anchor,
    values_overlap,
)
from shared.io_util import in_dir, iso_now, out_dir

LEDGER_SCHEMA = "evergreen.asset_ledger.v1"
IN_LEDGER_REL = Path("assets") / "asset-ledger.json"
OUT_LEDGER_REL = Path("assets") / "asset-ledger.json"
OVERRIDES_REL = Path("assets") / "assets-overrides.csv"

__all__ = [
    "ASSET_NAMESPACE",
    "ASSET_UID_PREFIX",
    "AssetLedger",
    "asset_uid",
    "resolve_asset_id",
    "ids_from_record",
    "stamp_ids",
]


def _parse_ts(raw: str | None) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _days_apart(newer: str, older: str) -> float | None:
    a = _parse_ts(newer)
    b = _parse_ts(older)
    if a is None or b is None:
        return None
    return abs((a - b).total_seconds()) / 86400.0


def make_asset_uid(anchor_type: str, anchor_value: str, *, width: int = 10) -> str:
    digest = hashlib.sha256(f"a1|{anchor_type}|{anchor_value}".encode("utf-8")).hexdigest().upper()
    return f"{ASSET_UID_PREFIX}{digest[:width]}"


def _sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _canonical_dump(payload: dict[str, Any]) -> bytes:
    body = {k: v for k, v in payload.items() if k != "sha256"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _empty_asset(uid: str, now: str, anchor: dict[str, str], ids: dict[str, Any]) -> dict[str, Any]:
    return {
        "asset_uid": uid,
        "created": now,
        "anchor": dict(anchor),
        "status": "active",
        "merged_into": "",
        "replaces": "",
        "ephemeral": False,
        "class_uid": "",
        "poam_status": "open",
        "absent_covered_runs": 0,
        "sources": [],
        "aliases": [],
        "iiw": {},
        "events": [],
        "uai": display_uai(ids),
    }


class AssetLedger:
    """Append-only, file-based asset ledger. No network calls."""

    def __init__(self) -> None:
        self.schema = LEDGER_SCHEMA
        self.prev_sha256 = ""
        self.sha256 = ""
        self.assets: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.collisions: list[dict[str, Any]] = []
        self.fp_migrations: list[dict[str, str]] = []
        self._observed: set[str] = set()
        self._uuid_sets: dict[str, set[tuple[str, frozenset[str]]]] = {}
        self._run_sources: set[str] = set()
        self.lost_ledger = False

    # ----- persistence -------------------------------------------------
    @classmethod
    def load(cls, path: Path | None = None) -> "AssetLedger":
        ledger = cls()
        dest = path if path is not None else in_dir() / IN_LEDGER_REL
        if dest is None or not Path(dest).is_file():
            return ledger
        try:
            payload = json.loads(Path(dest).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            ledger.warnings.append("LEDGER_UNREADABLE")
            return ledger
        if not isinstance(payload, dict):
            ledger.warnings.append("LEDGER_UNREADABLE")
            return ledger
        stored = str(payload.get("sha256") or "")
        calc = _sha256_bytes(_canonical_dump(payload))
        if stored and stored != calc:
            ledger.warnings.append("LEDGER_CHAIN_BROKEN")
        ledger.schema = str(payload.get("schema") or LEDGER_SCHEMA)
        ledger.prev_sha256 = str(payload.get("prev_sha256") or stored or "")
        ledger.sha256 = stored
        raw_assets = payload.get("assets") or {}
        if isinstance(raw_assets, dict):
            ledger.assets = {str(k): dict(v) for k, v in raw_assets.items() if isinstance(v, dict)}
        ledger.events = [e for e in (payload.get("events") or []) if isinstance(e, dict)]
        ledger.warnings.extend(str(w) for w in (payload.get("warnings") or []) if w)
        ledger.collisions = [c for c in (payload.get("collisions") or []) if isinstance(c, dict)]
        ledger.fp_migrations = [m for m in (payload.get("fp_migrations") or []) if isinstance(m, dict)]
        return ledger

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": self.schema,
            "prev_sha256": self.prev_sha256,
            "assets": self.assets,
            "events": self.events,
            "warnings": list(dict.fromkeys(self.warnings)),
            "collisions": self.collisions,
            "fp_migrations": self.fp_migrations,
        }
        payload["sha256"] = _sha256_bytes(_canonical_dump(payload))
        self.sha256 = str(payload["sha256"])
        return payload

    def save(self, path: Path | None = None) -> Path:
        dest = Path(path) if path is not None else out_dir() / OUT_LEDGER_REL
        dest.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_dict()
        dest.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return dest

    def apply_overrides(self, path: Path | None = None, *, now: str | None = None) -> None:
        dest = Path(path) if path is not None else in_dir() / OVERRIDES_REL
        if not dest.is_file():
            return
        stamp = now or iso_now()
        with dest.open(encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if not row:
                    continue
                action = str(row.get("action") or row.get("op") or "").strip().lower()
                uid = str(row.get("uid") or row.get("asset_uid") or "").strip()
                target = str(row.get("target") or row.get("uid_b") or row.get("merged_into") or "").strip()
                if action == "merge" and uid and target:
                    self.merge(uid, target, now=stamp, reason="operator")
                elif action == "split" and uid:
                    alias_type = str(row.get("alias_type") or "ip").strip()
                    alias_value = str(row.get("alias_value") or row.get("alias") or "").strip()
                    if alias_value:
                        self.split(uid, alias_type, alias_value, now=stamp, reason="operator")
                elif action == "replaces" and uid and target:
                    self.mark_replaces(uid, target, now=stamp)
                elif action == "pin_uai" and uid:
                    asset = self.assets.get(uid)
                    if asset:
                        asset["uai"] = str(row.get("pin_uai") or row.get("uai") or asset.get("uai") or "")
                        asset.setdefault("iiw", {})["pin_uai"] = asset["uai"]
                if uid and uid in self.assets:
                    iiw = self.assets[uid].setdefault("iiw", {})
                    for key in (
                        "virtual",
                        "public",
                        "os",
                        "asset_type",
                        "hw_model",
                        "location",
                        "vlan",
                        "owner_sys",
                        "owner_app",
                        "function",
                        "baseline",
                        "diagram_label",
                        "eol",
                    ):
                        val = str(row.get(key) or "").strip()
                        if val:
                            iiw[key] = val

    # ----- events / aliases --------------------------------------------
    def _log(self, kind: str, uid: str, now: str, **detail: Any) -> None:
        event = {"at": now, "kind": kind, "asset_uid": uid, **detail}
        self.events.append(event)
        asset = self.assets.get(uid)
        if asset is not None:
            asset.setdefault("events", []).append(event)

    def _alias_index(self, asset: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
        out: dict[tuple[str, str], dict[str, Any]] = {}
        for alias in asset.get("aliases") or []:
            if not isinstance(alias, dict):
                continue
            if alias.get("valid_to"):
                continue
            key = (str(alias.get("type") or ""), str(alias.get("value") or "").lower())
            out[key] = alias
        return out

    def _add_aliases(
        self,
        asset: dict[str, Any],
        ids: dict[str, Any],
        now: str,
        source: str,
        scope: str,
    ) -> None:
        existing = self._alias_index(asset)
        for typ in (
            "image_ref",
            "image_digest",
            "artifact_id",
            "image_id",
            "arn",
            "uuid",
            "bios_uuid",
            "agent",
            "mac",
            "netbios",
            "fqdn",
            "ip",
            "hostname",
            "name",
            "serial",
        ):
            for value in id_values(ids, typ):
                key = (typ, value.lower())
                if key in existing:
                    existing[key]["last_seen"] = now
                    srcs = existing[key].setdefault("sources", [])
                    if source and source not in srcs:
                        srcs.append(source)
                    continue
                asset.setdefault("aliases", []).append(
                    {
                        "type": typ,
                        "value": value,
                        "scope": scope,
                        "first_seen": now,
                        "last_seen": now,
                        "valid_to": "",
                        "sources": [source] if source else [],
                    }
                )

    def _active_assets(self) -> list[dict[str, Any]]:
        return [a for a in self.assets.values() if a.get("status") == "active"]

    def _note_uuid(self, ids: dict[str, Any]) -> None:
        for key in ("uuid", "bios_uuid"):
            val = str(ids.get(key) or "").strip().lower()
            if not val:
                continue
            fp = fqdn_mac_fingerprint(ids)
            if fp is None:
                continue
            bucket = self._uuid_sets.setdefault(val, set())
            bucket.add(fp)

    def _uuid_collided(self, value: str) -> bool:
        sets = self._uuid_sets.get(str(value or "").strip().lower()) or set()
        nonempty = {fp for fp in sets if fp[0] or fp[1]}
        return len(nonempty) >= 2

    def _flag_collisions(self, now: str) -> None:
        for key, sets in self._uuid_sets.items():
            nonempty = {fp for fp in sets if fp[0] or fp[1]}
            if len(nonempty) < 2:
                continue
            detail = {
                "kind": "uuid_collision",
                "value": key,
                "sets": [{"fqdn": f, "mac": sorted(m)} for f, m in sorted(nonempty)],
                "at": now,
            }
            if detail not in self.collisions:
                self.collisions.append(detail)
                self.warnings.append(f"uuid_collision:{key}")

    def _ids_of(self, asset: dict[str, Any]) -> dict[str, Any]:
        blob: dict[str, Any] = {}
        for alias in asset.get("aliases") or []:
            if not isinstance(alias, dict) or alias.get("valid_to"):
                continue
            typ = str(alias.get("type") or "")
            val = alias.get("value")
            if typ in {"mac", "ip", "image_digest"}:
                blob.setdefault(typ, []).append(val)
            else:
                blob[typ] = val
        return merge_ids(blob)

    def _scope_of(self, asset: dict[str, Any], typ: str, value: str) -> str:
        for alias in asset.get("aliases") or []:
            if (
                isinstance(alias, dict)
                and alias.get("type") == typ
                and str(alias.get("value") or "").lower() == value.lower()
                and not alias.get("valid_to")
            ):
                return str(alias.get("scope") or "")
        return ""

    def _last_seen(self, asset: dict[str, Any], typ: str, value: str) -> str:
        for alias in asset.get("aliases") or []:
            if (
                isinstance(alias, dict)
                and alias.get("type") == typ
                and str(alias.get("value") or "").lower() == value.lower()
                and not alias.get("valid_to")
            ):
                return str(alias.get("last_seen") or "")
        return ""

    def _expire_alias(self, asset: dict[str, Any], typ: str, value: str, now: str) -> None:
        for alias in asset.get("aliases") or []:
            if (
                isinstance(alias, dict)
                and alias.get("type") == typ
                and str(alias.get("value") or "").lower() == value.lower()
                and not alias.get("valid_to")
            ):
                alias["valid_to"] = now

    def _stronger_conflict(self, obs: dict[str, Any], cand: dict[str, Any], match_key: str) -> bool:
        rank = STRENGTH.get(match_key, 0)
        skip = set()
        if match_key == "image_ref":
            # Digests/IDs are aliases of the image class, not a conflict.
            skip.update({"image_digest", "artifact_id", "image_id"})
        for key, strength in STRENGTH.items():
            if strength <= rank or key in skip:
                continue
            if key in {"uuid", "bios_uuid"} and self._uuid_collided(str(obs.get(key) or cand.get(key) or "")):
                continue
            left = id_values(obs, key)
            right = id_values(cand, key)
            if not left or not right:
                continue
            if not values_overlap(left, right):
                return True
        return False

    def _match_key(self, obs: dict[str, Any], asset: dict[str, Any], key: str, now: str) -> bool:
        cand = self._ids_of(asset)
        left = id_values(obs, key)
        right = id_values(cand, key)
        if not left or not right:
            return False
        if key in {"uuid", "bios_uuid"} and (
            self._uuid_collided(left[0]) or self._uuid_collided(right[0])
        ):
            return False
        if key == "mac":
            if not values_overlap(left, right):
                return False
        elif key == "ip":
            if not values_overlap(left, right):
                return False
            scope = str(obs.get("scope") or "")
            for ip in left:
                if ip.lower() not in {x.lower() for x in right}:
                    continue
                cand_scope = self._scope_of(asset, "ip", ip)
                if scope and cand_scope and scope != cand_scope:
                    return False
                last = self._last_seen(asset, "ip", ip)
                gap = _days_apart(now, last) if last else 0.0
                if gap is not None and gap > LEASE_DAYS:
                    return False
        elif key == "netbios":
            if left[0].lower() != right[0].lower():
                return False
            od = str(obs.get("domain") or "")
            cd = str(cand.get("domain") or "")
            if od and cd and od.lower() != cd.lower():
                return False
        else:
            if left[0].lower() != right[0].lower():
                return False
        return not self._stronger_conflict(obs, cand, key)

    def _find_match(self, ids: dict[str, Any], now: str) -> dict[str, Any] | None:
        if is_container(ids):
            # Class first (image_ref), then content keys per §6.3.
            order = ("image_ref",) + CONTAINER_ORDER
            for key in order:
                if not id_values(ids, key):
                    continue
                for asset in self._active_assets():
                    if self._match_key(ids, asset, key, now):
                        return asset
            return None
        if id_values(ids, "arn"):
            for asset in self._active_assets():
                if self._match_key(ids, asset, "arn", now):
                    return asset
        for key in MATCH_ORDER:
            if not id_values(ids, key):
                continue
            for asset in self._active_assets():
                if self._match_key(ids, asset, key, now):
                    return asset
        return None

    def _new_uid(self, ids: dict[str, Any]) -> tuple[str, dict[str, str]]:
        skip = set()
        if ids.get("uuid") and self._uuid_collided(str(ids.get("uuid"))):
            skip.add("uuid")
        if ids.get("bios_uuid") and self._uuid_collided(str(ids.get("bios_uuid"))):
            skip.add("bios_uuid")
        typ, value = strongest_anchor(ids, skip=skip)
        width = 10
        uid = make_asset_uid(typ, value, width=width)
        while uid in self.assets:
            width += 2
            if width > 16:
                uid = make_asset_uid(typ, f"{value}|{len(self.assets)}", width=10)
                if uid not in self.assets:
                    break
                uid = make_asset_uid(typ, f"{value}|{len(self.assets)}|{width}", width=12)
                break
            uid = make_asset_uid(typ, value, width=width)
        return uid, {"type": typ, "value": value}

    def _same_l3(self, left: str, right: str) -> bool:
        """True when two IPs look like a DHCP renew (same v4 /24), not multi-homed."""
        try:
            import ipaddress

            a = ipaddress.ip_address(left)
            b = ipaddress.ip_address(right)
        except ValueError:
            return False
        if a.version != b.version:
            return False
        if a.version == 4:
            return a.packed[:3] == b.packed[:3]
        return a.packed[:8] == b.packed[:8]

    def _maybe_replace_single_ip(self, asset: dict[str, Any], ids: dict[str, Any], now: str) -> None:
        """DHCP renew: one observed IP replaces one recorded IP on the same L3.

        Different networks (or v4+v6) stay as extra aliases — multi-homed.
        """
        observed = [ip for ip in id_values(ids, "ip")]
        if len(observed) != 1:
            return
        current = [
            al
            for al in asset.get("aliases") or []
            if isinstance(al, dict) and al.get("type") == "ip" and not al.get("valid_to")
        ]
        if len(current) != 1:
            return
        old = str(current[0].get("value") or "")
        if old.lower() == observed[0].lower():
            return
        if not self._same_l3(old, observed[0]):
            return
        current[0]["valid_to"] = now
        self._log("ip_renewed", asset["asset_uid"], now, old=old, new=observed[0])

    def _maybe_replace_single_fqdn(self, asset: dict[str, Any], ids: dict[str, Any], now: str) -> None:
        observed = id_values(ids, "fqdn")
        if len(observed) != 1:
            return
        current = [
            al
            for al in asset.get("aliases") or []
            if isinstance(al, dict) and al.get("type") == "fqdn" and not al.get("valid_to")
        ]
        if len(current) != 1:
            return
        old = str(current[0].get("value") or "")
        if old.lower() == observed[0].lower():
            return
        current[0]["valid_to"] = now
        self._log("fqdn_renamed", asset["asset_uid"], now, old=old, new=observed[0])

    def _maybe_reassign_ip(self, asset: dict[str, Any], ids: dict[str, Any], now: str) -> None:
        for ip in id_values(ids, "ip"):
            for other in self._active_assets():
                if other.get("asset_uid") == asset.get("asset_uid"):
                    continue
                other_ids = self._ids_of(other)
                other_ips = {x.lower() for x in id_values(other_ids, "ip")}
                if ip.lower() not in other_ips:
                    continue
                # Reassign only when the other host has a conflicting stronger id
                # (DHCP reuse). An IP-only predecessor is a late-merge candidate.
                if not self._stronger_conflict(ids, other_ids, "ip"):
                    continue
                self._expire_alias(other, "ip", ip, now)
                self._log("ip_reassigned", other["asset_uid"], now, ip=ip, to=asset["asset_uid"])

    def _maybe_split(self, asset: dict[str, Any], ids: dict[str, Any], now: str) -> dict[str, Any] | None:
        """IP-only asset whose IP now answers with a different MAC or FQDN."""
        cand = self._ids_of(asset)
        strong_obs = any(id_values(ids, k) for k in ("uuid", "bios_uuid", "agent", "mac", "fqdn"))
        strong_cand = any(id_values(cand, k) for k in ("uuid", "bios_uuid", "agent", "mac", "fqdn"))
        if strong_cand:
            return None
        if not strong_obs or not id_values(ids, "ip"):
            return None
        if not values_overlap(id_values(ids, "ip"), id_values(cand, "ip")):
            return None
        # Different MAC or FQDN than recorded (recorded may be empty → split).
        obs_mac, cand_mac = id_values(ids, "mac"), id_values(cand, "mac")
        obs_fqdn, cand_fqdn = id_values(ids, "fqdn"), id_values(cand, "fqdn")
        mac_diff = bool(obs_mac and cand_mac and not values_overlap(obs_mac, cand_mac))
        fqdn_diff = bool(obs_fqdn and cand_fqdn and obs_fqdn[0].lower() != cand_fqdn[0].lower())
        if not (mac_diff or fqdn_diff):
            return None
        for ip in id_values(ids, "ip"):
            self._expire_alias(asset, "ip", ip, now)
        self._log("split", asset["asset_uid"], now, reason="ip_reuse")
        return None

    def observe(
        self,
        rec: dict[str, Any] | None = None,
        *,
        ids: dict[str, Any] | None = None,
        now: str | None = None,
        source: str = "",
        observe: bool = True,
    ) -> str:
        stamp = now or str((rec or {}).get("collected_at") or "") or iso_now()
        blob = merge_ids(ids or {}, ids_from_record(rec or {}))
        src = source or str((rec or {}).get("source") or "")
        if src:
            self._run_sources.add(src)
        self._note_uuid(blob)
        self._flag_collisions(stamp)
        if not observe:
            match = self._find_match(blob, stamp)
            return str(match["asset_uid"]) if match else ""

        # Split an IP-only predecessor before matching the new identity.
        for asset in list(self._active_assets()):
            self._maybe_split(asset, blob, stamp)

        match = self._find_match(blob, stamp)
        if match is None:
            uid, anchor = self._new_uid(blob)
            asset = _empty_asset(uid, stamp, anchor, blob)
            ephemeral = is_container(blob) or bool(extra_dict(rec).get("ephemeral"))
            if ephemeral:
                asset["ephemeral"] = True
                class_src = str(blob.get("image_ref") or extra_dict(rec).get("class_ref") or "")
                if class_src:
                    asset["class_uid"] = make_asset_uid("class", class_src)
            self.assets[uid] = asset
            self._log("created", uid, stamp, anchor=anchor)
            match = asset
        scope = str(blob.get("scope") or "")
        self._maybe_replace_single_ip(match, blob, stamp)
        self._maybe_replace_single_fqdn(match, blob, stamp)
        self._add_aliases(match, blob, stamp, src, scope)
        if src and src not in match.setdefault("sources", []):
            match["sources"].append(src)
        match["uai"] = display_uai(self._ids_of(match)) or match.get("uai") or ""
        match["absent_covered_runs"] = 0
        if match.get("poam_status") == "pending_verification":
            match["poam_status"] = "open"
            self._log("reopened_pending", match["asset_uid"], stamp)
        self._maybe_reassign_ip(match, blob, stamp)
        self._observed.add(str(match["asset_uid"]))
        if rec is not None:
            extra = rec.setdefault("extra", {})
            if not isinstance(extra, dict):
                rec["extra"] = extra = {}
            extra["asset_uid"] = match["asset_uid"]
            extra["uai"] = match.get("uai") or ""
            extra["ids"] = {k: v for k, v in blob.items() if v not in ("", [], None)}
        return str(match["asset_uid"])

    def merge(self, uid_a: str, uid_b: str, *, now: str, reason: str = "strong_alias") -> str:
        """Keep the older UID. The other becomes merged_into."""
        a = self.assets.get(uid_a)
        b = self.assets.get(uid_b)
        if not a or not b or uid_a == uid_b:
            return uid_a or uid_b
        keep, drop = (a, b) if str(a.get("created") or "") <= str(b.get("created") or "") else (b, a)
        keep_uid = str(keep["asset_uid"])
        drop_uid = str(drop["asset_uid"])
        for alias in drop.get("aliases") or []:
            if isinstance(alias, dict):
                keep.setdefault("aliases", []).append(dict(alias))
        for src in drop.get("sources") or []:
            if src not in keep.setdefault("sources", []):
                keep["sources"].append(src)
        drop["status"] = "merged"
        drop["merged_into"] = keep_uid
        self.fp_migrations.append({"from": drop_uid, "to": keep_uid, "reason": reason, "at": now})
        self._log("merged", drop_uid, now, merged_into=keep_uid, reason=reason)
        keep["uai"] = display_uai(self._ids_of(keep)) or keep.get("uai") or ""
        return keep_uid

    def split(self, uid: str, alias_type: str, alias_value: str, *, now: str, reason: str = "operator") -> str:
        asset = self.assets.get(uid)
        if not asset:
            return ""
        self._expire_alias(asset, alias_type, alias_value, now)
        ids = merge_ids({alias_type: alias_value})
        new_uid, anchor = self._new_uid(ids)
        created = _empty_asset(new_uid, now, anchor, ids)
        self.assets[new_uid] = created
        self._add_aliases(created, ids, now, "operator", "")
        self._log("split", uid, now, new=new_uid, alias=f"{alias_type}:{alias_value}", reason=reason)
        return new_uid

    def mark_replaces(self, new_uid: str, old_uid: str, *, now: str) -> None:
        new = self.assets.get(new_uid)
        old = self.assets.get(old_uid)
        if not new:
            return
        new["replaces"] = old_uid
        if old:
            old["status"] = "retired"
            self._log("retired", old_uid, now, reason="replaced", replacement=new_uid)
        self._log("replaces", new_uid, now, predecessor=old_uid)

    def inherit_poam_from(self, uid: str) -> str:
        """Predecessor UID whose POA&M ID/date a replacement should inherit."""
        asset = self.assets.get(uid) or {}
        return str(asset.get("replaces") or "")

    def close_run(self, *, now: str | None = None, source_families: set[str] | None = None) -> None:
        stamp = now or iso_now()
        families = source_families if source_families is not None else set(self._run_sources)
        for asset in self._active_assets():
            uid = str(asset.get("asset_uid") or "")
            if uid in self._observed:
                asset["absent_covered_runs"] = 0
                continue
            covered = bool(set(asset.get("sources") or []) & families) if families else False
            if not covered:
                self._log("not_observed_no_coverage", uid, stamp)
                continue
            asset["absent_covered_runs"] = int(asset.get("absent_covered_runs") or 0) + 1
            if asset["absent_covered_runs"] >= 2:
                asset["status"] = "retired"
                asset["poam_status"] = "pending_verification"
                self._log("retired", uid, stamp, reason="cm8_removal", poam="pending_verification")
        self._observed.clear()
        self._run_sources.clear()

    def late_merge_pass(self, *, now: str) -> None:
        """Merge actives that now share a strong alias (CM-8a.3)."""
        strong = ("image_ref", "image_digest", "artifact_id", "image_id", "arn", "uuid", "bios_uuid", "agent", "mac")
        changed = True
        while changed:
            changed = False
            actives = self._active_assets()
            for i, left in enumerate(actives):
                lids = self._ids_of(left)
                for right in actives[i + 1 :]:
                    rids = self._ids_of(right)
                    merged = False
                    for key in strong:
                        if key in {"uuid", "bios_uuid"} and (
                            self._uuid_collided(str(lids.get(key) or ""))
                            or self._uuid_collided(str(rids.get(key) or ""))
                        ):
                            continue
                        if values_overlap(id_values(lids, key), id_values(rids, key)):
                            self.merge(str(left["asset_uid"]), str(right["asset_uid"]), now=now, reason=key)
                            merged = True
                            break
                    if not merged and values_overlap(id_values(lids, "ip"), id_values(rids, "ip")):
                        if not self._stronger_conflict(lids, rids, "ip"):
                            self.merge(str(left["asset_uid"]), str(right["asset_uid"]), now=now, reason="ip")
                            merged = True
                    if merged:
                        changed = True
                        break
                if changed:
                    break


def asset_uid(
    record: dict[str, Any],
    ledger: AssetLedger | None = None,
    *,
    now: str | None = None,
    observe: bool = True,
) -> str:
    """Stable Evergreen asset UID (``EGA-`` + 10 hex).

    Parameters
    ----------
    record:
        Canonical asset or finding dict. Identifiers are read from
        ``extra.ids`` plus lifted ``extra`` fields and ``name``.
    ledger:
        Persistent ``AssetLedger``. ``None`` regenerates from the
        current strongest alias and emits no file I/O (lost-ledger
        regeneration; the UID may drift if a stronger alias arrived
        after the original creation).
    now:
        Observation timestamp (ISO-8601). Defaults to
        ``record['collected_at']`` or ``iso_now()``.
    observe:
        When a ledger is supplied, stamp aliases and create-on-miss.
        ``False`` is lookup-only.

    Returns
    -------
    str
        ``EGA-`` + 10 (or 12, on prefix collision) uppercase hex.
    """
    if ledger is None:
        ids = ids_from_record(record)
        typ, value = strongest_anchor(ids)
        uid = make_asset_uid(typ, value)
        extra = record.setdefault("extra", {})
        if isinstance(extra, dict):
            extra.setdefault("asset_uid", uid)
            extra.setdefault("uai", display_uai(ids))
            extra.setdefault("ids", {k: v for k, v in ids.items() if v not in ("", [], None)})
            extra.setdefault("ledger_warning", "lost_or_absent")
        return uid
    return ledger.observe(record, now=now, observe=observe)


def resolve_asset_id(
    record: dict[str, Any],
    ledger: AssetLedger | None = None,
    *,
    now: str | None = None,
    observe: bool = True,
) -> str:
    """Alias of ``asset_uid``. Stable signature for POA&M fingerprint callers."""
    return asset_uid(record, ledger, now=now, observe=observe)


def attach_asset_uids(
    records: list[dict[str, Any]],
    ledger: AssetLedger,
    *,
    now: str | None = None,
) -> list[dict[str, Any]]:
    """Resolve every record against the ledger and merge same-UID assets."""
    stamp = now or iso_now()
    for rec in records:
        if rec.get("kind") == "asset":
            ledger.observe(
                rec,
                now=str(rec.get("collected_at") or stamp),
                source=str(rec.get("source") or ""),
            )
    ledger.late_merge_pass(now=stamp)
    for rec in records:
        if rec.get("kind") == "asset":
            continue
        uid = ledger.observe(
            rec,
            now=str(rec.get("collected_at") or stamp),
            source=str(rec.get("source") or ""),
            observe=False,
        )
        extra = rec.setdefault("extra", extra_dict(rec))
        if uid and isinstance(extra, dict):
            extra["asset_uid"] = uid
            extra["uai"] = (ledger.assets.get(uid) or {}).get("uai") or extra.get("uai") or ""
    # Re-stamp merged-into UIDs.
    by_uid: dict[str, dict[str, Any]] = {}
    out: list[dict[str, Any]] = []
    leftover: list[dict[str, Any]] = []
    for rec in records:
        extra = extra_dict(rec)
        uid = str(extra.get("asset_uid") or "")
        asset = ledger.assets.get(uid)
        if asset and asset.get("status") == "merged" and asset.get("merged_into"):
            uid = str(asset["merged_into"])
            extra = rec.setdefault("extra", extra)
            if isinstance(extra, dict):
                extra["asset_uid"] = uid
                extra["uai"] = (ledger.assets.get(uid) or {}).get("uai") or extra.get("uai")
        if rec.get("kind") == "asset" and uid:
            kept = by_uid.get(uid)
            if kept is None:
                by_uid[uid] = rec
                extra = rec.setdefault("extra", {})
                if isinstance(extra, dict):
                    extra["asset_uid"] = uid
                    extra["uai"] = (ledger.assets.get(uid) or {}).get("uai") or extra.get("uai")
                    extra["ids"] = {
                        k: v
                        for k, v in ledger._ids_of(ledger.assets[uid]).items()
                        if v not in ("", [], None)
                    }
                out.append(rec)
            else:
                _merge_asset_records(kept, rec, ledger.assets.get(uid) or {})
            continue
        leftover.append(rec)
    return out + leftover


def _merge_asset_records(kept: dict[str, Any], other: dict[str, Any], asset: dict[str, Any]) -> None:
    extra = kept.setdefault("extra", {})
    if not isinstance(extra, dict):
        kept["extra"] = extra = {}
    other_extra = extra_dict(other)
    extra["ids"] = {
        k: v for k, v in merge_ids(extra.get("ids") if isinstance(extra.get("ids"), dict) else {}, other_extra.get("ids") if isinstance(other_extra.get("ids"), dict) else {}, ledger_ids(asset)).items()
        if v not in ("", [], None)
    }
    extra["asset_uid"] = asset.get("asset_uid") or extra.get("asset_uid")
    extra["uai"] = asset.get("uai") or extra.get("uai")
    kept["name"] = prefer_display_name(kept.get("name"), other.get("name"))
    labels = kept.setdefault("labels", [])
    if not isinstance(labels, list):
        kept["labels"] = labels = []
    for lab in other.get("labels") or []:
        if lab and lab not in labels:
            labels.append(lab)
    names = extra.setdefault("also_names", [])
    if not isinstance(names, list):
        extra["also_names"] = names = []
    other_name = str(other.get("name") or "")
    if other_name and other_name not in names and other_name != kept.get("name"):
        names.append(other_name)


def ledger_ids(asset: dict[str, Any]) -> dict[str, Any]:
    blob: dict[str, Any] = {}
    for alias in asset.get("aliases") or []:
        if not isinstance(alias, dict) or alias.get("valid_to"):
            continue
        typ = str(alias.get("type") or "")
        val = alias.get("value")
        if typ in {"mac", "ip", "image_digest"}:
            blob.setdefault(typ, []).append(val)
        elif typ:
            blob[typ] = val
    return blob
