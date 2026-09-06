from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.io_util import discover_input_files, emit, load_structured
from shared.schema import asset, control_extra, evidence, finding, normalize_severity

SOURCE = "k8s_kubescape"
PREFIX = "K8S-"


def _ks_control_status(ctrl: Any) -> str:
    if isinstance(ctrl, dict):
        status = ctrl.get("status")
        if isinstance(status, dict):
            return str(status.get("status") or "").lower()
        return str(status or "").lower()
    return ""


def _ks_severity(ctrl: dict[str, Any]) -> str:
    raw = ctrl.get("severity") or ctrl.get("level")
    if raw:
        mapped = normalize_severity(raw)
        if mapped != "info" or str(raw).strip().lower() in {"info", "informational"}:
            return mapped
    try:
        factor = float(ctrl.get("scoreFactor") or ctrl.get("score_factor") or 0)
    except (TypeError, ValueError):
        factor = 0.0
    if factor >= 9:
        return "critical"
    if factor >= 7:
        return "high"
    if factor >= 4:
        return "medium"
    if factor > 0:
        return "low"
    return "medium"


def _ks_severity_counts(blob: Any) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    if not isinstance(blob, dict):
        return counts
    aliases = {
        "critical": "critical",
        "criticalseverity": "critical",
        "high": "high",
        "highseverity": "high",
        "medium": "medium",
        "mediumseverity": "medium",
        "low": "low",
        "lowseverity": "low",
    }
    for key, value in blob.items():
        bucket = aliases.get(str(key).lower().replace("_", "").replace(" ", ""))
        if not bucket:
            continue
        if isinstance(value, dict):
            raw = value.get("workloadCount") or value.get("count") or value.get("resources") or 0
        else:
            raw = value
        try:
            counts[bucket] += int(raw or 0)
        except (TypeError, ValueError):
            continue
    return counts


def _ks_cluster(doc: dict[str, Any]) -> str:
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    for blob in (doc, meta):
        if not isinstance(blob, dict):
            continue
        for key in ("cluster", "clusterName", "cluster_name", "ClusterName"):
            val = blob.get(key)
            if val:
                return str(val)
    return "kubernetes"


def _ks_failed_control(
    cluster: str,
    cid: str,
    ctrl: dict[str, Any],
    resource: str,
    *,
    implicit_fail: bool = False,
) -> list:
    status = _ks_control_status(ctrl)
    if status in {"passed", "pass", "skipped", "excluded", "irrelevant", "ignore"}:
        return []
    try:
        failed_n = int(ctrl.get("failedResources") or 0)
    except (TypeError, ValueError):
        failed_n = 0
    if status not in {"failed", "fail"} and failed_n <= 0 and not implicit_fail:
        return []
    name = str(ctrl.get("name") or cid)
    desc = str(ctrl.get("description") or ctrl.get("remediation") or name)
    labels = ["k8s", "kubescape", cid]
    if implicit_fail:
        labels.append("failedcontrols")
    related = [resource or cluster]
    if cluster and cluster not in related:
        related.append(cluster)
    return [
        finding(
            PREFIX,
            cid,
            name,
            description=desc,
            severity=_ks_severity(ctrl),
            source=SOURCE,
            related_assets=related,
            labels=labels,
            extra=control_extra(
                "CTL-K8S-CIS",
                "CIS Kubernetes benchmark remediation",
                csf_function="protect",
                priority="2",
            ),
        )
    ]


def _ks_control_id(ctrl: dict[str, Any], fallback: str = "") -> str:
    for key in ("controlID", "controlId", "control_id", "id", "ID", "name"):
        val = ctrl.get(key)
        if val:
            return str(val)
    return str(fallback or "")


def _iter_failed_controls(blob: Any) -> list[tuple[str, dict[str, Any]]]:
    """Kubescape failedControls list/dict: controlID, no resources array required."""
    items: list[tuple[str, dict[str, Any]]] = []
    if isinstance(blob, dict):
        for key, val in blob.items():
            if isinstance(val, dict):
                cid = _ks_control_id(val, str(key))
                if cid:
                    items.append((cid, val))
                continue
            cid = str(key).strip()
            if cid:
                items.append((cid, {"controlID": cid}))
        return items
    if not isinstance(blob, list):
        return items
    for entry in blob:
        if isinstance(entry, str):
            cid = entry.strip()
            if cid:
                items.append((cid, {"controlID": cid}))
            continue
        if isinstance(entry, dict):
            cid = _ks_control_id(entry)
            if cid:
                items.append((cid, entry))
    return items


def _failed_control_blobs(doc: dict[str, Any], summary: dict[str, Any]) -> list[Any]:
    blobs: list[Any] = []
    for src in (doc, summary):
        if not isinstance(src, dict):
            continue
        for key in ("failedControls", "failed_controls"):
            if key in src and src[key] is not None:
                blobs.append(src[key])
    return blobs


def parse_kubescape(doc: dict[str, Any]) -> list:
    records: list = []
    cluster = _ks_cluster(doc)
    records.append(
        asset(
            PREFIX,
            cluster,
            cluster,
            description=f"Kubernetes cluster {cluster}",
            asset_type="PR",
            source=SOURCE,
            labels=["k8s", "cluster"],
        )
    )
    for res in doc.get("resources") or []:
        if not isinstance(res, dict):
            continue
        obj = res.get("object") or {}
        name = str(obj.get("name") or res.get("resourceID") or "workload")
        kind = str(obj.get("kind") or "Resource")
        records.append(
            asset(
                PREFIX,
                name,
                f"{kind}/{name}",
                description=f"{kind} {obj.get('namespace', '')}/{name}",
                asset_type="SP",
                source=SOURCE,
                labels=["k8s", kind.lower()],
                extra={"privileged": obj.get("privileged")},
            )
        )
        if obj.get("privileged"):
            records.append(
                finding(
                    PREFIX,
                    f"PRIV-{name}",
                    f"Privileged pod {name}",
                    description=f"Workload {name} is privileged.",
                    severity="high",
                    source=SOURCE,
                    related_assets=[name, cluster],
                    labels=["k8s", "privileged"],
                    extra=control_extra(
                        "CTL-K8S-PSS",
                        "Enforce Pod Security Restricted",
                        csf_function="protect",
                        priority="1",
                    ),
                )
            )
    summary = doc.get("summaryDetails") or doc.get("summary_details") or {}
    if isinstance(summary, dict):
        rs = summary.get("resourcesSeverity") or summary.get("resourceSeverity") or {}
        counts = _ks_severity_counts(rs)
        if counts["critical"] or counts["high"]:
            records.append(
                finding(
                    PREFIX,
                    f"RES-SEV-{cluster}",
                    f"Kubescape resourcesSeverity on {cluster}",
                    description=(
                        f"summaryDetails.resourcesSeverity critical={counts['critical']} "
                        f"high={counts['high']} medium={counts['medium']} low={counts['low']} "
                        f"score={summary.get('score')}"
                    ),
                    severity="critical" if counts["critical"] else "high",
                    source=SOURCE,
                    related_assets=[cluster],
                    labels=["k8s", "kubescape", "resourcesseverity"],
                    extra=control_extra(
                        "CTL-K8S-PSS",
                        "Enforce Pod Security Restricted",
                        csf_function="protect",
                        priority="1",
                    ),
                )
            )
        controls = summary.get("controls") or {}
        if isinstance(controls, dict):
            for cid, ctrl in controls.items():
                if isinstance(ctrl, dict):
                    records.extend(_ks_failed_control(cluster, str(ctrl.get("controlID") or cid), ctrl, cluster))
        elif isinstance(controls, list):
            for ctrl in controls:
                if isinstance(ctrl, dict):
                    cid = str(ctrl.get("controlID") or ctrl.get("id") or ctrl.get("name") or "ctrl")
                    records.extend(_ks_failed_control(cluster, cid, ctrl, cluster))
    for blob in _failed_control_blobs(doc, summary if isinstance(summary, dict) else {}):
        for cid, ctrl in _iter_failed_controls(blob):
            records.extend(
                _ks_failed_control(cluster, cid, ctrl, cluster, implicit_fail=True)
            )
    for result in doc.get("results") or []:
        if not isinstance(result, dict):
            continue
        resource = str(result.get("resource") or result.get("resourceID") or cluster)
        nested = result.get("controls")
        if isinstance(nested, dict):
            for cid, ctrl in nested.items():
                if isinstance(ctrl, dict):
                    records.extend(_ks_failed_control(cluster, str(ctrl.get("controlID") or cid), ctrl, resource))
            continue
        if isinstance(nested, list):
            for ctrl in nested:
                if isinstance(ctrl, dict):
                    cid = str(ctrl.get("controlID") or ctrl.get("name") or "ctrl")
                    records.extend(_ks_failed_control(cluster, cid, ctrl, resource))
            continue
        if str(result.get("status") or "").lower() not in {"failed", "fail"}:
            continue
        cid = str(result.get("controlID") or result.get("name"))
        records.append(
            finding(
                PREFIX,
                cid,
                str(result.get("name") or cid),
                description=str(result.get("description") or result.get("name") or cid),
                severity=str(result.get("severity") or "medium"),
                source=SOURCE,
                related_assets=[str(result.get("resource") or cluster), cluster],
                labels=["k8s", "kubescape", cid],
                extra=control_extra(
                    "CTL-K8S-CIS",
                    "CIS Kubernetes benchmark remediation",
                    csf_function="protect",
                    priority="2",
                ),
            )
        )
    return records


def _kb_get(result: dict[str, Any], *names: str) -> Any:
    """kube-bench result field: underscored, hyphenated, or case-folded keys."""
    for name in names:
        if name in result and result[name] not in (None, ""):
            return result[name]
    folded = {str(k).lower().replace("-", "_"): v for k, v in result.items()}
    for name in names:
        key = str(name).lower().replace("-", "_")
        val = folded.get(key)
        if val not in (None, ""):
            return val
    return ""


def _kube_bench_status(result: dict[str, Any]) -> str:
    raw = _kb_get(
        result,
        "status",
        "test_result",
        "test-result",
        "testStatus",
        "test-status",
        "State",
        "state",
    )
    return str(raw or "").strip().upper().replace(" ", "_")


def _kube_bench_severity(status: str, desc: str) -> str | None:
    st = str(status or "").strip().upper().replace(" ", "_")
    if st in {"FAIL", "FAILED", "FAILURE"} or st.startswith("FAIL"):
        return "high" if "anonymous" in desc.lower() else "medium"
    if st in {"WARN", "WARNING", "WARNED"} or st.startswith("WARN"):
        return "medium"
    return None


def _kb_tests_blob(control: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten kube-bench tests/Tests into result dicts (nested results or bare rows)."""
    tests = control.get("tests") if control.get("tests") is not None else control.get("Tests")
    if isinstance(tests, dict):
        tests = [tests]
    if not isinstance(tests, list):
        return []
    out: list[dict[str, Any]] = []
    for test in tests:
        if not isinstance(test, dict):
            continue
        nested = None
        if "results" in test:
            nested = test.get("results")
        elif "Results" in test:
            nested = test.get("Results")
        if nested is None:
            out.append(test)
            continue
        if isinstance(nested, list):
            out.extend(item for item in nested if isinstance(item, dict))
        elif isinstance(nested, dict):
            out.append(nested)
    return out


def _looks_like_kube_bench_tests(tests: Any) -> bool:
    rows = _kb_tests_blob({"tests": tests})
    for row in rows:
        if _kb_get(row, "test_number", "test-number", "testNumber", "TestNumber"):
            return True
        if _kube_bench_status(row):
            return True
    return False


def _kb_controls(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """kube-bench Controls array, or a single control with top-level tests (no wrapping Controls)."""
    for key in ("Controls", "controls"):
        if key not in doc:
            continue
        blob = doc.get(key)
        if isinstance(blob, list):
            return [item for item in blob if isinstance(item, dict)]
        if isinstance(blob, dict) and (
            blob.get("tests") is not None or blob.get("Tests") is not None or blob.get("id")
        ):
            return [blob]
        return []
    tests = doc.get("tests") if doc.get("tests") is not None else doc.get("Tests")
    if _looks_like_kube_bench_tests(tests):
        return [doc]
    return []


def parse_kube_bench(doc: dict[str, Any]) -> list:
    records: list = []
    wrapped = "Controls" in doc or "controls" in doc
    for control in _kb_controls(doc):
        for result in _kb_tests_blob(control):
            num = str(
                _kb_get(result, "test_number", "test-number", "testNumber", "TestNumber") or "kb"
            )
            desc = str(
                _kb_get(result, "test_desc", "test-desc", "testDesc", "TestDesc") or num
            )
            st = _kube_bench_status(result)
            sev = _kube_bench_severity(st, desc)
            if not sev:
                continue
            labels = ["k8s", "kube-bench", st.lower() or "unknown"]
            if any("-" in str(k) for k in result.keys()):
                labels.append("hyphen")
            if not wrapped:
                labels.append("root-tests")
            records.append(
                finding(
                    PREFIX,
                    f"KB-{num}",
                    desc,
                    description=desc,
                    severity=sev,
                    source=SOURCE,
                    related_assets=["prod-eks"],
                    labels=labels,
                    extra=control_extra(
                        "CTL-K8S-APISERVER",
                        "Harden kube-apiserver flags",
                        csf_function="protect",
                        priority="1",
                    ),
                )
            )
    return records


def parse_files(files: list[Path]) -> list:
    records: list = []
    for path in files:
        for doc in load_structured(path):
            if not isinstance(doc, dict):
                continue
            if (
                "results" in doc
                or "resources" in doc
                or "summaryDetails" in doc
                or "summary_details" in doc
                or "failedControls" in doc
                or "failed_controls" in doc
            ):
                records.extend(parse_kubescape(doc))
            if _kb_controls(doc):
                records.extend(parse_kube_bench(doc))
    return records


def main() -> None:
    files = discover_input_files("k8s")
    records = parse_files(files)
    records.append(
        evidence(
            PREFIX,
            "K8S",
            "Kubescape/kube-bench demo parse",
            description="Parsed Kubescape resources/results, summaryDetails.resourcesSeverity, failedControls, and kube-bench (including hyphenated test-number/test-result and top-level tests with no wrapping Controls). Cluster was not contacted.",
            source=SOURCE,
        )
    )
    emit("k8s", records, files)


if __name__ == "__main__":
    main()
