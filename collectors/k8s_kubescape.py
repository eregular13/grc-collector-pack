#!/usr/bin/env python3
"""Parse Kubescape / kube-bench into cluster findings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.io_util import iso_now, read_json, read_jsonl, run_collector
from shared.schema import make_record, make_ref

SOURCE = "k8s-kubescape"
LABELS = ["k8s", "kubescape"]


def _sev_from_score(score: Any) -> str:
    try:
        n = float(score)
    except (TypeError, ValueError):
        return "medium"
    if n >= 8:
        return "critical"
    if n >= 6:
        return "high"
    if n >= 4:
        return "medium"
    return "low"


def _falco_events(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [e for e in payload if isinstance(e, dict) and (e.get("rule") or e.get("output"))]
    if isinstance(payload, dict):
        if payload.get("rule") or payload.get("output"):
            return [payload]
        events = payload.get("events") or payload.get("falco")
        if isinstance(events, list):
            return [e for e in events if isinstance(e, dict)]
    return []


def _kube_bench_rows(payload: Any) -> list[dict[str, Any]]:
    """Flatten aqua kube-bench Controls[].tests[].results[] or a flat FAIL list."""
    controls: list[Any] = []
    if isinstance(payload, dict):
        controls = payload.get("Controls") or payload.get("controls") or []
    elif isinstance(payload, list):
        controls = payload
    if not isinstance(controls, list):
        return []
    rows: list[dict[str, Any]] = []
    for ctrl in controls:
        if not isinstance(ctrl, dict):
            continue
        tests = ctrl.get("tests") if isinstance(ctrl.get("tests"), list) else []
        if tests:
            for test in tests:
                if not isinstance(test, dict):
                    continue
                results = test.get("results") or test.get("Results") or []
                if not isinstance(results, list):
                    continue
                for res in results:
                    if isinstance(res, dict):
                        rows.append(res)
            continue
        if str(ctrl.get("status") or "").upper() in {"FAIL", "FAILED", "WARN"}:
            rows.append(ctrl)
    return rows


def _kubescape_result_rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    results = payload.get("results") or payload.get("Results")
    if not isinstance(results, list):
        return []
    out: list[dict[str, Any]] = []
    for row in results:
        if not isinstance(row, dict):
            continue
        ctrls = row.get("controls") or row.get("Controls")
        if isinstance(ctrls, dict):
            for cid, ctrl in ctrls.items():
                if isinstance(ctrl, dict):
                    merged = dict(ctrl)
                    merged.setdefault("id", cid)
                    merged.setdefault("controlID", cid)
                    out.append(merged)
        elif row.get("controlID") or row.get("id"):
            out.append(row)
    return out


def _failed_status(raw: Any) -> bool:
    status = raw
    if isinstance(raw, dict):
        status = raw.get("status") or raw.get("Status") or ""
    s = str(status or "").lower()
    return s in {"fail", "failed", "warn", "warning"}


def _falco_severity(priority: Any) -> str:
    p = str(priority or "warning").lower()
    if p in {"emergency", "alert", "critical"}:
        return "critical"
    if p in {"error", "err"}:
        return "high"
    if p in {"warning", "warn"}:
        return "medium"
    return "low"


def parse_file(path: Path) -> list[dict]:
    try:
        payload = read_json(path)
    except Exception:
        payload = read_jsonl(path)
    now = iso_now()
    records: list[dict] = []
    falco = _falco_events(payload)
    if falco and not (isinstance(payload, dict) and (payload.get("summaryDetails") or payload.get("Controls"))):
        cluster = "cluster"
        for ev in falco:
            fields = ev.get("output_fields") if isinstance(ev.get("output_fields"), dict) else {}
            cluster = str(ev.get("hostname") or fields.get("k8s.cluster.name") or cluster)
            pod = str(fields.get("k8s.pod.name") or ev.get("rule") or "workload")
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{cluster}"),
                    name=cluster,
                    description=f"Kubernetes cluster {cluster}",
                    category="cluster",
                    assets=[cluster],
                    labels=LABELS + ["falco"],
                    collected_at=now,
                    extra={"asset_type": "PR"},
                )
            )
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, str(ev.get("rule") or ev.get("output") or "falco")),
                    name=str(ev.get("rule") or "Falco event"),
                    description=str(ev.get("output") or ev.get("rule")),
                    severity=_falco_severity(ev.get("priority")),
                    category="incident",
                    assets=[pod, cluster],
                    labels=LABELS + ["falco"],
                    collected_at=now,
                    extra={"pod": pod, "namespace": fields.get("k8s.ns.name")},
                )
            )
        return records
    cluster = "cluster"
    if isinstance(payload, dict):
        cluster = str(payload.get("clusterName") or payload.get("cluster") or "cluster")
    seen_assets: set[str] = set()
    seen_cids: set[str] = set()

    def add_cluster() -> None:
        key = cluster.lower()
        if key in seen_assets:
            return
        seen_assets.add(key)
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{cluster}"),
                name=cluster,
                description=f"Kubernetes cluster {cluster}",
                category="cluster",
                assets=[cluster],
                labels=LABELS,
                collected_at=now,
                extra={"asset_type": "PR"},
            )
        )

    def add_finding(
        cid: str,
        name: str,
        desc: str,
        sev: Any,
        labels: list[str],
    ) -> None:
        key = cid.lower() or name.lower()
        if not key or key in seen_cids:
            return
        seen_cids.add(key)
        add_cluster()
        try:
            sev = _sev_from_score(float(sev))
        except (TypeError, ValueError):
            sev = sev or "high"
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"{cid}-{cluster}"),
                name=name,
                description=desc,
                severity=sev,
                category="cloud-misconfiguration",
                assets=[cluster],
                labels=labels,
                collected_at=now,
                extra={"control": cid, "id": cid},
            )
        )

    add_cluster()
    if isinstance(payload, dict):
        summary = payload.get("summaryDetails") or {}
        controls = summary.get("controls") if isinstance(summary, dict) else {}
        if isinstance(controls, dict):
            for cid, ctrl in controls.items():
                if not isinstance(ctrl, dict):
                    continue
                if not _failed_status(ctrl.get("status")):
                    continue
                name = str(ctrl.get("name") or cid)
                add_finding(
                    str(cid),
                    name,
                    str(ctrl.get("description") or name),
                    _sev_from_score(ctrl.get("severityScore") or ctrl.get("severity")),
                    LABELS,
                )
        for row in _kubescape_result_rows(payload):
            status = row.get("status") or row.get("Status")
            if isinstance(status, dict):
                status = status.get("status")
            if not _failed_status(status):
                continue
            cid = str(row.get("controlID") or row.get("id") or row.get("name") or "ks")
            name = str(row.get("name") or row.get("text") or cid)
            sev = row.get("severityScore")
            if sev is None and isinstance(row.get("severity"), dict):
                sev = row["severity"].get("score")
            if sev is None:
                sev = row.get("severity") or "high"
            add_finding(cid, name, str(row.get("description") or row.get("remediation") or name), sev, LABELS)
        for res in payload.get("resources") or []:
            if not isinstance(res, dict):
                continue
            rname = str(res.get("name") or "workload")
            key = rname.lower()
            if key in seen_assets:
                continue
            seen_assets.add(key)
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{rname}"),
                    name=rname,
                    description=f"{res.get('kind', 'Workload')} {rname}",
                    category="workload",
                    assets=[rname],
                    labels=LABELS,
                    collected_at=now,
                    extra={"asset_type": "PR", "namespace": res.get("namespace")},
                )
            )
    for row in _kube_bench_rows(payload):
        if not _failed_status(row.get("status") or row.get("State")):
            continue
        cid = str(row.get("test_number") or row.get("id") or row.get("text") or "cis")
        name = str(row.get("test_desc") or row.get("text") or cid)
        add_finding(
            cid,
            name,
            str(row.get("reason") or row.get("remediation") or name),
            row.get("severity") or "high",
            LABELS + ["kube-bench"],
        )
    return records


def main() -> None:
    run_collector(SOURCE, (".json", ".jsonl"), parse_file)


if __name__ == "__main__":
    main()
