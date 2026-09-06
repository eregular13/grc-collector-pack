"""Stage machine: plan → shard → discover → destroy → deepen(small) → destroy → ingest → grc_export."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dropbox.orchestrator import STAGES
from dropbox.orchestrator.adapters import (
    curl_byo,
    hardeningkitty_byo,
    lynis_byo,
    maester_byo,
    nessus_byo,
    nmap_byo,
    noop_discover,
    prowler_byo,
    ss_byo,
    testssl_byo,
)
from dropbox.orchestrator.plan import (
    build_plan,
    cidr_ip_shards,
    concurrent_waves,
    deepen_batches,
    runtime_over_budget,
)
from dropbox.orchestrator.poam import canonical_mapped_findings, export_poam, export_quote, export_simplerisk
from dropbox.orchestrator.scope import Scope, load_scope

PACK = Path(__file__).resolve().parents[2]
DROPBOX = PACK / "dropbox"


class BrakeError(SystemExit):
    """Integrity stop. Not a scanner failure."""


def out_dir(scope: Scope | None = None) -> Path:
    raw = os.environ.get("DROPBOX_OUT")
    dest = Path(raw).resolve() if raw else (DROPBOX / "out")
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "workers").mkdir(exist_ok=True)
    return dest


def _write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _destroy(stage: str, workers: list[str], dest: Path) -> dict[str, Any]:
    rec = {"stage": stage, "destroyed": workers, "note": "short-lived workers torn down"}
    _write(dest / f"destroy_{stage}.json", rec)
    for name in workers:
        marker = dest / "workers" / f"{name}.alive"
        try:
            if marker.exists():
                marker.unlink()
        except OSError:
            pass
    return rec


def _destroy_leftover_workers(dest: Path) -> list[str]:
    """Crash leftovers must not stay .alive into the next quiet/loud stage."""
    workers_dir = dest / "workers"
    if not workers_dir.is_dir():
        return []
    leftover: list[str] = []
    for marker in list(workers_dir.glob("*.alive")):
        leftover.append(marker.stem)
        try:
            marker.unlink()
        except OSError:
            pass
    return leftover


def _spawn(name: str, dest: Path) -> None:
    marker = dest / "workers" / f"{name}.alive"
    marker.write_text("alive\n", encoding="utf-8")


def stage_plan(scope: Scope, dest: Path) -> dict[str, Any]:
    plan = build_plan(scope)
    _write(dest / "plan.json", plan)
    return plan


def _discover_units(plan: dict[str, Any]) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    size = max(1, int((plan.get("brakes") or {}).get("discover_shard_size") or 32))
    for i, block in enumerate(plan.get("discover_cidr_shards") or []):
        cidr = str(block.get("cidr") or "")
        if not cidr:
            continue
        shards = cidr_ip_shards(cidr, size)
        for j, targets in enumerate(shards):
            units.append({"kind": "cidr", "name": f"discover-cidr-{i}-{j}", "targets": list(targets)})
    for i, shard in enumerate(plan.get("discover_host_shards") or []):
        units.append({"kind": "host", "name": f"discover-host-{i}", "targets": list(shard)})
    return units


def _in_scope_discovered(row: dict[str, Any], scope: Scope) -> bool:
    """Drop nmap hits that are not in named SCOPE (no neighbor spray)."""
    name = str(row.get("host") or "").strip()
    ip = str(row.get("ip") or "").strip()
    allowed = set(scope.discover_hosts())
    if name in allowed or ip in allowed:
        return True
    for token in (name, ip):
        if not token:
            continue
        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            continue
        for cidr in scope.discover_cidrs():
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    return False


def _filter_fixture_hosts(discover: dict[str, Any], scope: Scope) -> dict[str, Any]:
    allowed = set(scope.discover_hosts())
    rows = [row for row in (discover.get("hosts") or []) if isinstance(row, dict)]
    if not allowed:
        discover["hosts"] = []
        discover["filtered_to_scope"] = True
        return discover
    kept = []
    dropped = []
    for row in rows:
        name = str(row.get("host") or "").strip()
        if name in allowed:
            kept.append(row)
        else:
            dropped.append(name)
    discover["hosts"] = kept
    discover["dropped_out_of_scope"] = dropped
    discover["filtered_to_scope"] = True
    return discover


def stage_discover(scope: Scope, dest: Path) -> dict[str, Any]:
    _destroy_leftover_workers(dest)
    reason = scope.refuse_live()
    plan = build_plan(scope)
    units = _discover_units(plan)
    cap = max(1, scope.batch.max_concurrent_discover)
    waves = concurrent_waves(units, cap)
    workers: list[str] = []
    nmap_notes = []
    wave_names: list[list[str]] = []
    live_rows: list[dict[str, Any]] = []
    live_attempted = False
    dropped_out: list[str] = []
    for wave in waves:
        names = []
        for unit in wave:
            name = str(unit["name"])
            names.append(name)
            workers.append(name)
            _spawn(name, dest)
            targets = list(unit.get("targets") or [])
            desc = nmap_byo.describe(scope, targets)
            if desc.get("would_exec"):
                live_attempted = True
                desc = nmap_byo.execute(scope, targets, timeout=scope.integrity.timeouts_seconds)
                for row in desc.get("hosts") or []:
                    if not isinstance(row, dict):
                        continue
                    if _in_scope_discovered(row, scope):
                        live_rows.append(row)
                    else:
                        dropped_out.append(str(row.get("host") or row.get("ip") or ""))
            nmap_notes.append(desc)
        wave_names.append(names)
        for name in names:
            marker = dest / "workers" / f"{name}.alive"
            try:
                if marker.exists():
                    marker.unlink()
            except OSError:
                pass
    # Fixture discover for lab path (labeled). Live nmap runs only when brakes allow.
    if live_attempted:
        discover = {
            "label": "live-byo",
            "note": (
                "BYO nmap on the drop box. Pack does not embed Nmap. "
                "Not a client estate unless SCOPE is a signed authorization sheet."
            ),
            "hosts": live_rows,
            "dropped_out_of_scope": [x for x in dropped_out if x],
            "source": "nmap_byo",
        }
    else:
        discover = noop_discover.run(dest)
        discover = _filter_fixture_hosts(discover, scope)
    def _maybe_endpoint(adapter: Any, targets: list[str]) -> dict[str, Any]:
        desc = adapter.describe(scope, targets)
        if desc.get("would_exec"):
            return adapter.execute(scope, targets, timeout=min(120, int(scope.integrity.timeouts_seconds or 60)))
        return desc

    discover["nmap"] = nmap_notes
    discover["lynis"] = [_maybe_endpoint(lynis_byo, scope.internal_endpoints)]
    discover["ss"] = [_maybe_endpoint(ss_byo, scope.internal_hosts)]
    discover["hardeningkitty"] = [_maybe_endpoint(hardeningkitty_byo, scope.internal_endpoints)]
    discover["prowler"] = [_maybe_endpoint(prowler_byo, scope.cloud_accounts)]
    discover["maester"] = [_maybe_endpoint(maester_byo, scope.entra_tenants)]
    discover["workers"] = workers
    discover["waves"] = wave_names
    discover["max_concurrent"] = cap
    discover["refuse_live"] = reason
    discover["worker_timeout_seconds"] = scope.integrity.timeouts_seconds
    discover["max_runtime_seconds"] = scope.integrity.max_runtime_seconds
    discover["label"] = "live-byo" if live_attempted else "fixture"
    discover["client"] = scope.client_legal_name
    discover["scope"] = str(scope.path)
    discover["profile_isolation"] = {
        "uses_internal": scope.uses_internal(),
        "uses_external": scope.uses_external(),
    }
    if reason:
        discover["brake"] = reason
    _write(dest / "discover.json", discover)
    destroy = _destroy("discover", workers, dest)
    destroy["waves"] = len(wave_names)
    destroy["max_concurrent"] = cap
    _write(dest / "destroy_discover.json", destroy)
    return {"discover": discover, "destroy_discover_workers": destroy}


def _in_scope_external(row: dict[str, Any], scope: Scope) -> bool:
    host = str(row.get("host") or row.get("asset") or "").strip()
    if not host:
        return False
    if host in set(scope.external_hostnames) or host in set(scope.external_urls):
        return True
    for url in scope.external_urls:
        parsed = urlparse(url)
        if host == (parsed.hostname or ""):
            return True
    return False


def _live_hosts(discover: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    for row in discover.get("hosts") or []:
        if not isinstance(row, dict):
            continue
        if row.get("live") and row.get("in_scope", True):
            name = str(row.get("host") or "").strip()
            if name:
                hosts.append(name)
    return hosts


def _live_hosts_in_scope(discover: dict[str, Any], scope: Scope) -> list[str]:
    """Deepen only named SCOPE hosts/CIDRs. Leftover neighbor names do not unlock louder tools."""
    allowed = set(scope.discover_hosts())
    kept: list[str] = []
    for host in _live_hosts(discover):
        if host in allowed:
            kept.append(host)
            continue
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            continue
        for cidr in scope.discover_cidrs():
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    kept.append(host)
                    break
            except ValueError:
                continue
    return kept


def _discover_leftover_reason(discover: dict[str, Any], scope: Scope) -> str | None:
    """Leftover discover.json must be usable for this SCOPE before louder deepen."""
    label = str(discover.get("label") or "").strip()
    if discover.get("refused") is True or label == "plan-only":
        return "discover_refused"
    discover_client = str(discover.get("client") or "").strip()
    if not discover_client:
        return "discover_client_missing"
    if discover_client != scope.client_legal_name:
        return "discover_client_mismatch"
    if label == "live-byo" and not scope.integrity.allow_live_exec:
        return "live_exec_not_allowed"
    return None


def _stage_refuse_reason(blob: Any) -> str | None:
    """Nested stage refuse must surface as a top-level brake (CLI/MCP exit 2)."""
    if not isinstance(blob, dict):
        return None
    if blob.get("refused") is True:
        return str(blob.get("reason") or "deepen_refused")
    inner = blob.get("deepen")
    if isinstance(inner, dict) and inner.get("refused") is True:
        return str(inner.get("reason") or "deepen_refused")
    return None


def stage_deepen(scope: Scope, dest: Path) -> dict[str, Any]:
    _destroy_leftover_workers(dest)
    reason = scope.refuse_live()
    if reason:
        rec = {"refused": True, "reason": reason, "label": "plan-only"}
        _write(dest / "deepen.json", rec)
        return rec
    discover_path = dest / "discover.json"
    if not discover_path.is_file():
        raise BrakeError("deepen requires discover.json (run discover first)")
    try:
        discover = json.loads(discover_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BrakeError("discover.json unparseable") from exc
    if not isinstance(discover, dict):
        raise BrakeError("discover.json unparseable")
    leftover = _discover_leftover_reason(discover, scope)
    if leftover:
        rec = {
            "refused": True,
            "reason": leftover,
            "label": "plan-only",
            "leftover_client": str(discover.get("client") or ""),
            "leftover_label": str(discover.get("label") or ""),
            "scope_client": scope.client_legal_name,
        }
        _write(dest / "deepen.json", rec)
        return rec
    live = _live_hosts_in_scope(discover, scope)
    if not scope.uses_internal():
        live = [h for h in live if h in set(scope.external_hostnames)]
    batches = deepen_batches(live, scope.batch.deepen_batch_size)
    cap = max(1, scope.batch.max_concurrent_deepen)
    workers: list[str] = []
    planned = []
    wave_names: list[list[str]] = []
    live_set = set(live)
    jobs = [{"name": f"deepen-{i}", "batch": batch} for i, batch in enumerate(batches)]
    if scope.uses_external():
        ext = list(scope.external_urls or scope.external_hostnames)
        for i, batch in enumerate(deepen_batches(ext, scope.batch.deepen_batch_size)):
            jobs.append({"name": f"deepen-ext-{i}", "batch": batch, "adapter": "testssl"})
            jobs.append({"name": f"deepen-curl-{i}", "batch": batch, "adapter": "curl"})
    live_findings: list[dict[str, Any]] = []
    live_attempted = False
    for wave in concurrent_waves(jobs, cap):
        names = []
        for job in wave:
            name = str(job["name"])
            names.append(name)
            workers.append(name)
            _spawn(name, dest)
            batch = list(job.get("batch") or [])
            if job.get("adapter") == "testssl":
                desc = testssl_byo.describe(scope, batch)
                if desc.get("would_exec"):
                    live_attempted = True
                    desc = testssl_byo.execute(scope, batch, timeout=scope.integrity.timeouts_seconds)
                    for row in desc.get("findings") or []:
                        if isinstance(row, dict) and _in_scope_external(row, scope):
                            live_findings.append(row)
                planned.append(desc)
            elif job.get("adapter") == "curl":
                desc = curl_byo.describe(scope, batch)
                if desc.get("would_exec"):
                    live_attempted = True
                    desc = curl_byo.execute(scope, batch, timeout=min(30, scope.integrity.timeouts_seconds))
                    for row in desc.get("findings") or []:
                        if isinstance(row, dict) and _in_scope_external(row, scope):
                            live_findings.append(row)
                planned.append(desc)
            else:
                desc = nessus_byo.describe(scope, batch)
                if desc.get("would_exec"):
                    live_attempted = True
                    desc = nessus_byo.execute(scope, batch, timeout=scope.integrity.timeouts_seconds)
                    for row in desc.get("findings") or []:
                        if not isinstance(row, dict):
                            continue
                        host = str(row.get("host") or row.get("asset") or "").strip()
                        if host in live_set or host in set(scope.discover_hosts()):
                            live_findings.append(row)
                planned.append(desc)
        wave_names.append(names)
        for name in names:
            marker = dest / "workers" / f"{name}.alive"
            try:
                if marker.exists():
                    marker.unlink()
            except OSError:
                pass
    if live_attempted:
        findings = {
            "label": "live-byo",
            "note": (
                "BYO deepen adapters on the drop box. Pack does not embed scanners. "
                "Not a client estate unless SCOPE is a signed authorization sheet."
            ),
            "findings": live_findings,
            "source": "byo-deepen",
        }
    else:
        fixture = PACK / "dropbox" / "fixtures" / "deepen.json"
        if fixture.is_file():
            findings = json.loads(fixture.read_text(encoding="utf-8"))
        else:
            findings = {"label": "fixture", "findings": []}
        rows = findings.get("findings") or []
        if isinstance(rows, list):
            # Deepen only hosts discover marked live/in-scope. Empty live set is not a hail-mary.
            findings["findings"] = [
                row
                for row in rows
                if str(row.get("host") or row.get("asset") or "") in live_set
            ]
    findings["batches"] = batches
    findings["adapters"] = planned
    findings["nessus"] = [row for row in planned if row.get("adapter") == "nessus_byo"]
    findings["testssl"] = [row for row in planned if row.get("adapter") == "testssl_byo"]
    findings["curl"] = [row for row in planned if row.get("adapter") == "curl_byo"]
    findings["workers"] = workers
    findings["waves"] = wave_names
    findings["max_concurrent"] = cap
    findings["worker_timeout_seconds"] = scope.integrity.timeouts_seconds
    findings["max_runtime_seconds"] = scope.integrity.max_runtime_seconds
    findings["label"] = "live-byo" if live_attempted else "fixture"
    findings["client"] = scope.client_legal_name
    findings["scope"] = str(scope.path)
    _write(dest / "deepen.json", findings)
    destroy = _destroy("deepen", workers, dest)
    destroy["waves"] = len(wave_names)
    destroy["max_concurrent"] = cap
    _write(dest / "destroy_deepen.json", destroy)
    return {"deepen": findings, "destroy_deepen_workers": destroy}


def _golden_fixture_findings() -> list[Any]:
    golden = PACK / "dropbox" / "fixtures" / "smb_v1.json"
    if golden.is_file():
        blob = json.loads(golden.read_text(encoding="utf-8"))
        rows = blob.get("findings") if isinstance(blob, dict) else []
        return list(rows) if isinstance(rows, list) else []
    return []


def _finding_in_scope(row: dict[str, Any], scope: Scope) -> bool:
    """Drop leftover neighbor/internal hosts when current SCOPE is tighter."""
    host = str(row.get("host") or row.get("asset") or "").strip()
    if not host:
        return False
    if host in set(scope.discover_hosts()) or host in set(scope.external_urls):
        return True
    for url in scope.external_urls:
        parsed = urlparse(url)
        if host == (parsed.hostname or "") or host == url:
            return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if not scope.uses_internal():
        return False
    for cidr in scope.discover_cidrs():
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _deepen_leftover_reason(blob: dict[str, Any], scope: Scope) -> str | None:
    """Leftover deepen.json must match this SCOPE before ingest."""
    label = str(blob.get("label") or "").strip()
    if blob.get("refused") is True or label == "plan-only":
        return "deepen_refused"
    blob_client = str(blob.get("client") or "").strip()
    if not blob_client:
        return "deepen_client_missing"
    if blob_client != scope.client_legal_name:
        return "client_mismatch"
    if label == "live-byo":
        refuse = scope.refuse_live()
        if refuse:
            return refuse
        if not scope.integrity.allow_live_exec:
            return "live_exec_not_allowed"
    return None


def stage_ingest(scope: Scope, dest: Path) -> dict[str, Any]:
    deepen_path = dest / "deepen.json"
    deepen_label = "fixture"
    leftover_ignored = None
    blob_client = ""
    findings = _golden_fixture_findings()
    if deepen_path.is_file():
        try:
            blob = json.loads(deepen_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            blob = None
        if not isinstance(blob, dict):
            leftover_ignored = {"reason": "deepen_unparseable"}
        else:
            ignore_reason = _deepen_leftover_reason(blob, scope)
            blob_client = str(blob.get("client") or "")
            deepen_label = str(blob.get("label") or "fixture")
            if ignore_reason:
                leftover_ignored = {
                    "reason": ignore_reason,
                    "leftover_client": blob_client,
                    "leftover_label": deepen_label,
                }
                findings = _golden_fixture_findings()
                deepen_label = "fixture"
            else:
                findings = blob.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    findings = [row for row in findings if isinstance(row, dict) and _finding_in_scope(row, scope)]
    live = deepen_label == "live-byo"
    label = "live-byo" if live else "fixture"
    # Do not merge pack demo canonical rows into a live-byo ingest (fixture vs real).
    # Single-profile SCOPE must not inherit the other profile's pack demo
    # (external-only: no internal SMBv1; internal-only: no vpn/TLS pack rows).
    pack_mapped: list[dict[str, Any]] = []
    if not live:
        pack_mapped = canonical_mapped_findings(PACK / "out" / "canonical")
        if pack_mapped and not (scope.uses_internal() and scope.uses_external()):
            pack_mapped = [
                item
                for item in pack_mapped
                if isinstance(item, dict) and _finding_in_scope(item, scope)
            ]
        if pack_mapped:
            seen = {
                (str(item.get("weakness") or item.get("name") or ""), str(item.get("asset") or item.get("host") or ""))
                for item in findings
            }
            for item in pack_mapped:
                key = (str(item.get("weakness") or ""), str(item.get("asset") or ""))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(item)
    norm = dest / "normalized"
    norm.mkdir(exist_ok=True)
    _write(
        norm / "findings.json",
        {"label": label, "client": scope.client_legal_name, "findings": findings},
    )
    # Do not clobber pack in/ demo estate. Preview copy only, labeled.
    preview = dest / "in-preview"
    preview.mkdir(exist_ok=True)
    if live:
        readme = (
            "BYO live ingest preview (live-byo). Not a paying-day PASS. Not a client estate until HITL.\n"
            "Never mixed into in/nmap, in/vuln, or other sensor folders. Pack demo canonical was not merged.\n"
        )
    else:
        readme = (
            "Fixture ingest preview. Not a client estate. Copy into pack in/<sensor>/ only for a labeled demo.\n"
            "Never mixed into in/nmap, in/vuln, or other sensor folders.\n"
        )
    (preview / "README.md").write_text(readme, encoding="utf-8")
    shutil.copyfile(norm / "findings.json", preview / "findings.json")
    pack_preview = PACK / "in" / "_dropbox_preview"
    pack_preview.mkdir(parents=True, exist_ok=True)
    (pack_preview / "README.md").write_text(readme, encoding="utf-8")
    shutil.copyfile(norm / "findings.json", pack_preview / "findings.json")
    poam_csv = dest / "poam.csv"
    poam_json = dest / "control_map.json"
    rows = export_poam(findings, poam_csv, poam_json, label=label)
    pack_poam = PACK / "out" / "poam"
    pack_poam.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(poam_csv, pack_poam / "poam.csv")
    shutil.copyfile(poam_json, pack_poam / "control_map.json")
    manifest = _poam_manifest(pack_poam / "poam.csv", pack_poam / "control_map.json", len(rows), label)
    (pack_poam / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    shutil.copyfile(pack_poam / "MANIFEST.json", dest / "poam_MANIFEST.json")
    sr_csv = dest / "simplerisk_import.csv"
    export_simplerisk(rows, sr_csv)
    pack_sr = PACK / "out" / "simplerisk"
    pack_sr.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sr_csv, pack_sr / "risks_import.csv")
    quote_csv = dest / "quote.csv"
    export_quote(rows, quote_csv)
    pack_quote = PACK / "out" / "quote"
    pack_quote.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(quote_csv, pack_quote / "quote.csv")
    quote_manifest = {
        "kind": "remediation-quote-stub",
        "label": label,
        "copied_at": datetime.now(timezone.utc).isoformat(),
        "files": [_sha256_file(pack_quote / "quote.csv")],
        "rows": len(rows),
        "note": "Hours/rate/total blank on purpose. HITL fills numbers. Never invent a price.",
    }
    (pack_quote / "MANIFEST.json").write_text(json.dumps(quote_manifest, indent=2), encoding="utf-8")
    raw_drop = os.environ.get("PRODUCT_LAB_DROP")
    lab_drop = Path(raw_drop).resolve() if raw_drop else (PACK.parent / "product-lab" / "drop")
    drop_copied = False
    if (
        lab_drop.is_dir()
        and not scope.refuse_live()
        and label != "live-byo"
        and not scope.integrity.allow_live_exec
    ):
        poam_drop = lab_drop / "poam"
        poam_drop.mkdir(exist_ok=True)
        shutil.copyfile(pack_poam / "poam.csv", poam_drop / "poam.csv")
        shutil.copyfile(pack_poam / "control_map.json", poam_drop / "control_map.json")
        shutil.copyfile(pack_poam / "MANIFEST.json", poam_drop / "MANIFEST.json")
        manifest["ciso_drop"] = str(poam_drop)
        sr_drop = lab_drop / "simplerisk"
        sr_drop.mkdir(exist_ok=True)
        shutil.copyfile(pack_sr / "risks_import.csv", sr_drop / "risks_import.csv")
        (sr_drop / "README.md").write_text(
            "SimpleRisk Core leave-behind. Import risks_import.csv by hand. No API wrap. Fixture-labeled.\n",
            encoding="utf-8",
        )
        q_drop = lab_drop / "quote"
        q_drop.mkdir(exist_ok=True)
        shutil.copyfile(pack_quote / "quote.csv", q_drop / "quote.csv")
        shutil.copyfile(pack_quote / "MANIFEST.json", q_drop / "MANIFEST.json")
        drop_copied = True
    return {
        "findings": len(findings),
        "poam_rows": len(rows),
        "poam_csv": str(poam_csv),
        "poam_manifest": str(pack_poam / "MANIFEST.json"),
        "simplerisk_csv": str(pack_sr / "risks_import.csv"),
        "quote_csv": str(pack_quote / "quote.csv"),
        "pack_mapped": sum(1 for row in rows if row.get("mapped")),
        "pack_canonical_merged": 0 if live else len(pack_mapped),
        "in_preview": str(pack_preview),
        "drop_copied": drop_copied,
        "label": label,
        "deepen_label": deepen_label,
        "leftover_ignored": leftover_ignored,
    }


def _sha256_file(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {"file": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _poam_manifest(csv_path: Path, json_path: Path, rows: int, ingest_label: str = "fixture") -> dict[str, Any]:
    return {
        "kind": "poam-control-map",
        "label": ingest_label,
        "copied_at": datetime.now(timezone.utc).isoformat(),
        "files": [_sha256_file(csv_path), _sha256_file(json_path)],
        "rows": rows,
        "note": "POA&M-shaped export for the CISO drop. Not a native CISO Assistant CSV schema. Owner/milestone blank, status=open.",
    }


def hitl_state(dest: Path) -> dict[str, Any]:
    """Parse HITL.json. Readiness is decided in stage_grc_export (fixture is never a client estate)."""
    path = dest / "HITL.json"
    missing = {
        "attested": False,
        "client": "",
        "reviewer": "",
        "reason": "HITL.json missing or attested is not true; review required before client-facing send",
    }
    if not path.is_file():
        return missing
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {**missing, "reason": "HITL.json unparseable"}
    if not isinstance(blob, dict):
        return missing
    attested = blob.get("attested") is True
    return {
        "attested": attested,
        "client": str(blob.get("client") or blob.get("client_legal_name") or "").strip(),
        "reviewer": str(blob.get("reviewer") or ""),
        "timestamp": str(blob.get("timestamp") or ""),
        "slug": str(blob.get("slug") or ""),
        "evidence_label": str(blob.get("evidence_label") or "").strip(),
        "reason": None if attested else "HITL attested is not true",
    }


def _lab_sim_brake(scope: Scope | None, hitl: dict[str, Any]) -> bool:
    """Docker-sim / lab-sim HITL is a real workflow, not a paying client."""
    label = str(hitl.get("evidence_label") or "").strip().lower().replace("_", "-")
    if label in {"lab-sim", "docker-lab", "docker-sim"}:
        return True
    names = []
    if scope is not None:
        names.append(scope.client_legal_name or "")
    names.append(str(hitl.get("client") or ""))
    blob = " ".join(names).lower()
    return "docker estate" in blob


def _label_client(path: Path) -> tuple[str, str] | None:
    if not path.is_file():
        return None
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(blob, dict):
        return None
    label = str(blob.get("label") or "").strip()
    if not label:
        return None
    client = str(blob.get("client") or blob.get("client_legal_name") or "").strip()
    return label, client


def _artifact_meta(dest: Path) -> tuple[str, str, str | None]:
    """Ingest then deepen. Discover is inventory, not client-facing evidence.
    Leftover live-byo ingest cannot outrank a current fixture/plan-only deepen."""
    ingest = _label_client(dest / "normalized" / "findings.json")
    deepen = _label_client(dest / "deepen.json")
    if ingest and deepen:
        i_label, i_client = ingest
        d_label, d_client = deepen
        if (i_label == "live-byo") != (d_label == "live-byo"):
            return "fixture", i_client or d_client, "evidence_label_mismatch"
        if i_client and d_client and i_client != d_client:
            return i_label, i_client, "evidence_client_mismatch"
        return i_label, i_client or d_client, None
    if ingest:
        return ingest[0], ingest[1], None
    if deepen:
        return deepen[0], deepen[1], None
    return "fixture", "", None


def stage_grc_export(dest: Path, scope: Scope | None = None) -> dict[str, Any]:
    ciso = PACK / "out" / "ciso-assistant"
    hitl = hitl_state(dest)
    refuse = scope.refuse_live() if scope is not None else None
    label, evidence_client, artifact_mismatch = _artifact_meta(dest)
    hitl_client = str(hitl.get("client") or "").strip()
    blocked_by: str | None = None
    if refuse:
        blocked_by = refuse
    elif artifact_mismatch:
        blocked_by = artifact_mismatch
    elif label != "live-byo":
        blocked_by = "fixture_not_client_estate"
    elif not evidence_client:
        blocked_by = "evidence_client_missing"
    elif scope is not None and evidence_client != scope.client_legal_name:
        blocked_by = "evidence_client_mismatch"
    elif scope is not None and not scope.integrity.allow_live_exec:
        blocked_by = "live_exec_not_allowed"
    elif not hitl.get("attested"):
        blocked_by = "hitl_not_attested"
    elif not hitl_client:
        blocked_by = "hitl_client_missing"
    elif scope is not None and hitl_client != scope.client_legal_name:
        blocked_by = "hitl_client_mismatch"
    elif _lab_sim_brake(scope, hitl):
        blocked_by = "lab_sim_not_client_estate"
    ready = blocked_by is None
    if blocked_by:
        hitl = {
            **hitl,
            "client_facing_ready": False,
            "blocked_by": blocked_by,
            "reason": (
                f"SCOPE refuse_live={refuse}; leftover HITL cannot make unsigned/empty/window client-facing"
                if refuse
                else f"client_facing blocked_by={blocked_by}"
            ),
        }
    else:
        hitl = {**hitl, "client_facing_ready": True, "blocked_by": None, "reason": None}
    rec = {
        "ciso_dir": str(ciso),
        "ciso_present": ciso.is_dir(),
        "ciso_auto_push": "assets.csv + evidences.csv only (push_ciso.ps1). Findings/POA&M are HITL clica/UI.",
        "hitl_required": True,
        "hitl": hitl,
        "client_facing_ready": ready,
        "scope_refuse_live": refuse,
        "evidence_label": label,
        "evidence_client": evidence_client,
        "poam": str(dest / "poam.csv"),
        "quote": str(PACK / "out" / "quote" / "quote.csv"),
        "simplerisk": str(PACK / "out" / "simplerisk" / "risks_import.csv"),
        "simplerisk_note": "leave-behind CSV for SimpleRisk Core extras import; no live API wrap",
        "riskready": "review-only JSON if present; WRAP_DEAD no POST",
        "label": label if label == "live-byo" else "fixture-or-prior-lab",
    }
    _write(dest / "grc_export.json", rec)
    return rec


def write_evidence_trail(dest: Path, result: dict[str, Any]) -> None:
    """Stage evidence trail. Fixture-labeled. Not a paying-day PASS."""
    dest.mkdir(parents=True, exist_ok=True)
    plan = result.get("plan") if isinstance(result.get("plan"), dict) else {}
    brakes = plan.get("brakes") if isinstance(plan.get("brakes"), dict) else {}
    ingest = result.get("ingest") if isinstance(result.get("ingest"), dict) else {}
    lines = [
        "# Orchestrator evidence trail",
        "",
        "Label: fixture unless a signed live SCOPE produced host artifacts.",
        "Not a client estate. Not a paying-day PASS.",
        "",
        f"scope: {result.get('scope')}",
        f"stage: {result.get('stage')}",
        f"refused: {result.get('refused')}",
        f"deepen_batch_size: {brakes.get('deepen_batch_size')}",
        f"integrity_stop: {brakes.get('refuse_live')}",
        f"ingest_label: {ingest.get('label')}",
        f"leftover_ignored: {ingest.get('leftover_ignored')}",
        f"poam_rows: {ingest.get('poam_rows')}",
        f"client_facing_ready: {(result.get('grc_export') or {}).get('client_facing_ready') if isinstance(result.get('grc_export'), dict) else False}",
        "",
        "Stages: plan → shard → discover → destroy_discover_workers → deepen(small) → destroy_deepen_workers → ingest → grc_export",
        "",
    ]
    (dest / "EVIDENCE.md").write_text("\n".join(lines), encoding="utf-8")


def run(scope_path: Path, stage: str, dest: Path | None = None) -> dict[str, Any]:
    scope = load_scope(scope_path)
    dest = Path(dest).resolve() if dest is not None else out_dir(scope)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "workers").mkdir(exist_ok=True)
    stage = (stage or "plan").lower()
    result: dict[str, Any] = {"scope": str(scope.path), "stage": stage}
    refuse = scope.refuse_live() or runtime_over_budget(scope)

    def _done(payload: dict[str, Any]) -> dict[str, Any]:
        write_evidence_trail(dest, payload)
        return payload

    if stage in {"plan", "shard", "all"}:
        result["plan"] = stage_plan(scope, dest)
        if stage != "all":
            return _done(result)
    if stage in {"discover", "deepen"} and refuse:
        result["plan"] = stage_plan(scope, dest)
        result["refused"] = refuse
        return _done(result)
    if stage == "all" and refuse:
        result["refused"] = refuse
        result["ingest"] = stage_ingest(scope, dest)
        result["grc_export"] = stage_grc_export(dest, scope)
        return _done(result)
    if stage == "discover" or stage == "all":
        result.update(stage_discover(scope, dest))
        if stage != "all":
            return _done(result)
    if stage == "deepen" or stage == "all":
        result["deepen"] = stage_deepen(scope, dest)
        nested_refuse = _stage_refuse_reason(result["deepen"])
        if nested_refuse:
            result["refused"] = nested_refuse
        if stage != "all":
            return _done(result)
    if stage == "ingest" or stage == "all":
        result["ingest"] = stage_ingest(scope, dest)
        if stage != "all":
            return _done(result)
    if stage == "grc_export" or stage == "all":
        result["grc_export"] = stage_grc_export(dest, scope)
        return _done(result)
    if stage not in STAGES and stage != "all":
        raise BrakeError(f"unknown stage {stage}; known={STAGES}")
    return _done(result)
