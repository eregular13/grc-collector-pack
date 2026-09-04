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
    if isinstance(payload, dict):
        summary = payload.get("summaryDetails") or {}
        controls = summary.get("controls") if isinstance(summary, dict) else {}
        if isinstance(controls, dict):
            for cid, ctrl in controls.items():
                if not isinstance(ctrl, dict):
                    continue
                status = str(ctrl.get("status") or "").lower()
                if status in {"passed", "pass", "skipped"}:
                    continue
                name = str(ctrl.get("name") or cid)
                records.append(
                    make_record(
                        kind="finding",
                        source=SOURCE,
                        ref_id=make_ref(SOURCE, str(cid)),
                        name=name,
                        description=str(ctrl.get("description") or name),
                        severity=_sev_from_score(ctrl.get("severityScore")),
                        category="cloud-misconfiguration",
                        assets=[cluster],
                        labels=LABELS,
                        collected_at=now,
                        extra={"control": cid},
                    )
                )
        for res in payload.get("resources") or []:
            if not isinstance(res, dict):
                continue
            rname = str(res.get("name") or "workload")
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
        for ctrl in payload.get("Controls") or []:
            if not isinstance(ctrl, dict):
                continue
            if str(ctrl.get("status") or "").upper() not in {"FAIL", "FAILED"}:
                continue
            cid = str(ctrl.get("id") or ctrl.get("text") or "cis")
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, cid),
                    name=str(ctrl.get("text") or cid),
                    description=str(ctrl.get("text") or cid),
                    severity=ctrl.get("severity") or "high",
                    category="cloud-misconfiguration",
                    assets=[cluster],
                    labels=LABELS + ["kube-bench"],
                    collected_at=now,
                    extra={"control": cid},
                )
            )
    return records


def main() -> None:
    run_collector(SOURCE, (".json", ".jsonl"), parse_file)


if __name__ == "__main__":
    main()
