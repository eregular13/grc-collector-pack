"""Estate banner + one-page executive summary + SCOPE_AND_TRUST.md.

Argus drafts (2026-09-25) are the spec. Exactly one allowed label. Fail
closed to the most restrictive when unsure. SAMPLE/DEMO/LAB and any
product-lab/drop fallback cannot be suppressed and cannot become CLIENT.
Missing values print "not recorded". Human narrative slots stay marked
placeholders. No cycle/CoS/adapter-list/agent notes on client pages.
"""

from __future__ import annotations

import csv
import hashlib
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

NOT_RECORDED = "not recorded"

# Most restrictive first. Unsure → SAMPLE (never CLIENT).
KIND_ORDER = ("MIXED", "SAMPLE", "DEMO", "LAB", "CLIENT")

LABEL_FOR_KIND = {
    "SAMPLE": "SAMPLE DATA: NOT A CLIENT",
    "DEMO": "DEMO: NOT A CLIENT",
    "LAB": "LAB: TEST ENVIRONMENT",
    "MIXED": "MIXED: REVIEW BEFORE USE",
}

SENTENCE_FOR_KIND = {
    "SAMPLE": (
        "Every finding below comes from bundled example files. "
        "None describes any real organization."
    ),
    "DEMO": (
        "Built from demo fixtures because no scanner output was supplied. "
        "None describes any real organization."
    ),
    "LAB": (
        "From scans of an Evergreen-controlled test environment. "
        "It does not describe your organization."
    ),
    "CLIENT": "From scanner output collected under the scope below.",
    "MIXED": (
        "Some outputs came from bundled sample files ({fallback_files}). "
        "Do not forward until they are removed."
    ),
}

# Human-written slots — never generated prose.
REVIEWER_WHAT_WE_FOUND = (
    "[reviewer: one to three plain sentences — not generated]"
)
REVIEWER_WHY_IT_MATTERS = (
    "[reviewer: one-sentence business impact — not generated]"
)
REVIEWER_NEXT_STEP = "[reviewer: one sentence — not generated]"
REVIEWER_NOT_REVIEWED = "not human-reviewed"

SAMPLE_AUTH = "No client authorization applies. No client systems were touched."

CLIENT_PAGE_FORBIDDEN = (
    "cycle ",
    "CoS #",
    "COS4",
    "COS48",
    "adapter list",
    "agent process",
    "overnight",
    "pytest",
    "E2E_PROVEN",
)

COLLECTOR_AREAS = {
    "cloud": "Cloud configuration",
    "cloud-prowler": "Cloud configuration",
    "nmap": "Host / network exposure",
    "inventory-nmap": "Host / network exposure",
    "vuln": "Vulnerability scan",
    "vuln-scan": "Vulnerability scan",
    "wazuh": "Host coverage",
    "host-wazuh": "Host coverage",
    "mdm": "MDM inventory",
    "identity": "Identity",
    "identity-ad": "Identity",
    "easm": "External exposure",
    "k8s": "Kubernetes",
    "k8s-kubescape": "Kubernetes",
    "code": "Code secrets",
    "code-secrets": "Code secrets",
    "saas": "SaaS / identity",
    "saas-idp": "SaaS / identity",
    "honeypot": "Deception sensors",
    "dns_email": "DNS / email",
    "dns-email": "DNS / email",
}

AREA_HINTS = (
    ("identity", ("identity", "saas", "idp", "ad", "entra", "okta")),
    ("external exposure", ("easm", "nmap", "exposure", "honeypot", "dns")),
    ("cloud configuration", ("cloud", "prowler", "k8s", "kubescape")),
    ("code secrets", ("code", "secret", "gitleaks", "truffle", "sast")),
)

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_TABLE = ("critical", "high", "medium", "low")

MAX_EXEC_BODY_ROWS = {
    "top_n": 5,
    "areas": 4,
    "scope": 8,
}
# One printed page: keep banner + limits; cut table rows if needed.
MAX_PAGE_LINES = 58

EXPORT_CSV_REL = (
    "poam/poam.csv",
    "ciso-assistant/assets.csv",
    "ciso-assistant/applied_controls.csv",
    "ciso-assistant/evidences.csv",
    "ciso-assistant/findings.csv",
    "ciso-assistant/vulnerabilities.csv",
    "ciso-assistant/risk_scenarios.csv",
    "opengrc/risks.csv",
    "opengrc/assets.csv",
    "opengrc/implementations.csv",
)
EXPORT_MD_REL = (
    "EXECUTIVE_SUMMARY.md",
    "SCOPE_AND_TRUST.md",
    "poam/poam.md",
    "poam/ESTATE.txt",
    "ciso-assistant/ESTATE.txt",
    "opengrc/ESTATE.txt",
    "opengrc/README.md",
    "probo/ESTATE.txt",
    "probo/README.md",
)
EXPORT_OTHER_REL = (
    "import_preview/probo.json",
)


def recorded(value: Any) -> str:
    """Fill a placeholder from run data. Missing → 'not recorded'. Never invent."""
    if value is None:
        return NOT_RECORDED
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value).strip()
    if not text:
        return NOT_RECORDED
    if text.lower() in {"none", "null", "unknown", "n/a", "na", "-"}:
        return NOT_RECORDED
    return text


def most_restrictive(*kinds: str) -> str:
    present = {k for k in kinds if k in KIND_ORDER}
    if not present:
        return "SAMPLE"
    for kind in KIND_ORDER:
        if kind in present:
            return kind
    return "SAMPLE"


def _env(env: dict[str, str] | None, key: str, default: str = "") -> str:
    src = env if env is not None else os.environ
    return str(src.get(key) or default).strip()


def _looks_non_client_name(name: str) -> bool:
    blob = name.strip().lower()
    if not blob:
        return True
    return any(tok in blob for tok in ("demo", "sample", "lab", "example", "not a client"))


def _client_name_from_scope() -> str:
    raw = _env(None, "GRC_CLIENT_NAME")
    if raw and not _looks_non_client_name(raw):
        return raw
    scope_path = _env(None, "GRC_SCOPE_PATH")
    candidates = []
    if scope_path:
        candidates.append(Path(scope_path))
    try:
        from shared.io_util import root_dir

        candidates.append(root_dir() / "dropbox" / "SCOPE.yaml")
    except Exception:
        pass
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            if line.strip().startswith("name:"):
                name = line.split(":", 1)[1].strip().strip("\"'")
                if name and not _looks_non_client_name(name):
                    return name
                return ""
    return ""


def pack_commit() -> str:
    raw = _env(None, "PACK_COMMIT") or _env(None, "GRC_PACK_COMMIT")
    if raw:
        return raw
    try:
        from shared.io_util import root_dir

        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(root_dir()),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return NOT_RECORDED
    out = (proc.stdout or "").strip()
    return out or NOT_RECORDED


def generated_at_local(iso_utc: str | None = None) -> str:
    raw = (iso_utc or "").strip()
    if raw:
        try:
            stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            local = stamp.astimezone()
            return local.strftime("%Y-%m-%d %H:%M %Z")
        except ValueError:
            pass
    now = datetime.now().astimezone()
    return now.strftime("%Y-%m-%d %H:%M %Z")


def run_id_from_records(records: list[dict] | None) -> str:
    raw = _env(None, "GRC_RUN_ID")
    if raw:
        return raw
    for rec in records or []:
        extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
        for key in ("run_id", "runId"):
            val = extra.get(key) or rec.get(key)
            if val:
                return str(val).strip()
    return NOT_RECORDED


def _marker_in(folder: Path | None, name: str) -> bool:
    if folder is None or not folder.is_dir():
        return False
    if (folder / name).is_file():
        return True
    try:
        return any(folder.rglob(name))
    except OSError:
        return False


def _fallback_from_records(records: list[dict]) -> list[str]:
    names: list[str] = []
    for rec in records:
        labels = [str(x).strip().lower() for x in (rec.get("labels") or [])]
        if "demo" not in labels and "sample" not in labels:
            continue
        src = str(rec.get("source") or "fixtures/demo").strip() or "fixtures/demo"
        if src not in names:
            names.append(src)
    return names


@dataclass
class EstateStamp:
    kind: str
    label: str
    sentence: str
    run_id: str = NOT_RECORDED
    generated_at_local: str = NOT_RECORDED
    pack_commit: str = NOT_RECORDED
    fallback_files: tuple[str, ...] = ()
    client_name: str = NOT_RECORDED

    def banner_md(self) -> str:
        return (
            f"> **{self.label}**: {self.sentence}\n"
            f"> Run `{self.run_id}` · generated {self.generated_at_local} · pack `{self.pack_commit}`"
        )

    def banner_lines(self) -> list[str]:
        return self.banner_md().splitlines()

    def banner_csv_comments(self) -> str:
        out = []
        for line in self.banner_lines():
            body = line[2:] if line.startswith("> ") else line.lstrip(">").strip()
            out.append(f"# {body}")
        return "\n".join(out) + "\n"

    def banner_oneline(self) -> str:
        return f"{self.label}: {self.sentence}"

    def token(self) -> str:
        return f"estate_{self.kind.lower()}"


def classify_estate(
    records: list[dict] | None = None,
    *,
    in_dir: Path | None = None,
    fallback_files: Iterable[str] | None = None,
    env: dict[str, str] | None = None,
    client_name: str | None = None,
    generated_at: str | None = None,
    run_id: str | None = None,
    commit: str | None = None,
) -> EstateStamp:
    """Pick exactly one allowed label. Fail closed. Banner is never suppressible."""
    records = list(records or [])
    env = env if env is not None else {k: str(v) for k, v in os.environ.items()}
    # Suppression knobs are ignored on purpose.
    for banned in (
        "GRC_HIDE_ESTATE",
        "GRC_SUPPRESS_ESTATE",
        "GRC_ESTATE_OFF",
        "HIDE_ESTATE_BANNER",
    ):
        env.pop(banned, None)

    raw_label = str(env.get("GRC_ESTATE_LABEL") or "").strip().upper()
    signals: list[str] = []

    fb = [str(x).strip() for x in (fallback_files or []) if str(x).strip()]
    rec_fb = _fallback_from_records(records)
    for name in rec_fb:
        if name not in fb:
            fb.append(name)
    drop_fb = [x for x in fb if "product-lab/drop" in x.replace("\\", "/")]

    def _finding_like(rec: dict) -> bool:
        kind = str(rec.get("kind") or "").strip().lower()
        return kind in {"", "finding", "vulnerability", "observation"}

    scored = [rec for rec in records if _finding_like(rec)] or list(records)
    n_records = len(scored)
    n_demo = sum(
        1
        for rec in scored
        if "demo" in [str(x).strip().lower() for x in (rec.get("labels") or [])]
        or "sample" in [str(x).strip().lower() for x in (rec.get("labels") or [])]
    )
    mixed_records = n_records > 0 and 0 < n_demo < n_records

    in_path = in_dir
    if in_path is None:
        raw_in = str(env.get("IN_DIR") or "").strip()
        in_path = Path(raw_in) if raw_in else None

    lab_marker = _marker_in(in_path, "LAB.txt")
    # DROPBOX_DEMO=1 is the prove dry-run flag. It is SAMPLE only when the
    # run is not already labeled LAB (LAB.txt / GRC_ESTATE_LABEL=LAB).
    dropbox_demo = str(env.get("DROPBOX_DEMO") or "") == "1"
    sample_marker = _marker_in(in_path, "SAMPLE.txt")
    if dropbox_demo and raw_label not in {"LAB", "DEMO"} and not lab_marker:
        sample_marker = True

    if drop_fb and (mixed_records or n_demo < n_records or lab_marker):
        signals.append("MIXED")
    elif drop_fb:
        signals.append("SAMPLE")
    elif mixed_records:
        signals.append("MIXED")

    if sample_marker:
        signals.append("SAMPLE")
    if lab_marker:
        if mixed_records or drop_fb or (n_demo and n_demo < n_records):
            signals.append("MIXED")
        else:
            signals.append("LAB")

    if raw_label in {"SAMPLE", "DEMO", "LAB"}:
        signals.append(raw_label)

    if n_demo == n_records and n_records > 0:
        signals.append("DEMO" if raw_label != "SAMPLE" and not sample_marker else "SAMPLE")
    elif n_demo and not mixed_records:
        signals.append("DEMO")

    name = (client_name or "").strip() or _client_name_from_scope()
    if name and _looks_non_client_name(name):
        name = ""

    kind = most_restrictive(*signals) if signals else "SAMPLE"

    client_ok = (
        raw_label == "CLIENT"
        and bool(name)
        and not drop_fb
        and n_demo == 0
        and not lab_marker
        and not sample_marker
        and "SAMPLE" not in signals
        and "DEMO" not in signals
        and "LAB" not in signals
        and "MIXED" not in signals
    )
    if client_ok:
        kind = "CLIENT"
    else:
        kind = most_restrictive(*signals) if signals else "SAMPLE"

    if kind == "CLIENT" and (
        n_demo or drop_fb or lab_marker or sample_marker or raw_label in {"SAMPLE", "DEMO", "LAB"}
    ):
        kind = most_restrictive("SAMPLE", *signals)

    fb_display = ", ".join(fb) if fb else NOT_RECORDED
    if kind == "CLIENT":
        label = f"CLIENT: {name}"
        sentence = SENTENCE_FOR_KIND["CLIENT"]
        client_out = name
    else:
        label = LABEL_FOR_KIND[kind]
        sentence = SENTENCE_FOR_KIND[kind].format(fallback_files=fb_display)
        client_out = name or NOT_RECORDED

    return EstateStamp(
        kind=kind,
        label=label,
        sentence=sentence,
        run_id=recorded(run_id or run_id_from_records(records)),
        generated_at_local=recorded(generated_at_local(generated_at)),
        pack_commit=recorded(commit or pack_commit()),
        fallback_files=tuple(fb),
        client_name=client_out,
    )


def write_csv_with_estate(
    path: Path,
    header: list[str],
    rows: list[list[Any]],
    stamp: EstateStamp,
    *,
    delimiter: str = ",",
) -> None:
    """Exact importer header first. No # preamble. estate column only if listed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = list(header)
    estate_idx = cols.index("estate") if "estate" in cols else None
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter=delimiter, lineterminator="\n")
        writer.writerow(cols)
        for row in rows:
            cells = list(row)
            if len(cells) < len(cols):
                cells.extend([""] * (len(cols) - len(cells)))
            elif len(cells) > len(cols):
                cells = cells[: len(cols)]
            if estate_idx is not None:
                cells[estate_idx] = stamp.label
            writer.writerow(cells)


def write_estate_sidecar(sink_dir: Path, stamp: EstateStamp, *, note: str = "") -> Path:
    """Human-readable estate banner next to a CSV sink. Not suppressible."""
    dest = Path(sink_dir)
    dest.mkdir(parents=True, exist_ok=True)
    extra = (
        note.strip()
        if note.strip()
        else (
            "Machine-imported CSVs in this directory start with the importer "
            "header (no # preamble). SAMPLE/DEMO/LAB cannot be suppressed and "
            "is never client KEEP."
        )
    )
    path = dest / "ESTATE.txt"
    path.write_text(stamp.banner_md() + "\n\n" + extra + "\n", encoding="utf-8")
    return path


def prepend_banner_md(body: str, stamp: EstateStamp) -> str:
    banner = stamp.banner_md()
    text = body.lstrip("\n")
    heads = text.splitlines()[:3]
    if text.startswith("> **") and any(line.startswith("> Run `") for line in heads):
        rest = "\n".join(text.splitlines()[2:]).lstrip("\n")
        return banner + "\n\n" + rest
    if text.startswith(banner):
        return text if text.endswith("\n") else text + "\n"
    return banner + "\n\n" + text


def assert_banner_present(text: str, stamp: EstateStamp | None = None) -> None:
    blob = text
    if stamp is not None:
        if stamp.label not in blob:
            raise AssertionError(f"estate banner label missing: {stamp.label}")
        if stamp.sentence.split(".")[0] not in blob and stamp.sentence not in blob:
            raise AssertionError("estate banner sentence missing")
        return
    labels = list(LABEL_FOR_KIND.values()) + ["CLIENT:"]
    if not any(label in blob for label in labels):
        raise AssertionError("no allowed estate banner label in file")


def _sev(rec: dict) -> str:
    raw = str(rec.get("severity") or "").strip().lower()
    if raw in SEV_RANK:
        return "low" if raw == "info" else raw
    return "low"


def _area_for(rec: dict) -> str:
    blob = " ".join(
        str(x or "")
        for x in (
            rec.get("category"),
            rec.get("source"),
            rec.get("name"),
        )
    ).lower()
    for area, hints in AREA_HINTS:
        if any(h in blob for h in hints):
            return area
    cat = str(rec.get("category") or rec.get("source") or "").strip()
    return COLLECTOR_AREAS.get(cat, cat or "other")


def _count_severities(items: Iterable[dict], key: str = "severity") -> dict[str, int]:
    out = {s: 0 for s in SEV_TABLE}
    for item in items:
        sev = str(item.get(key) or "").strip().lower()
        if sev == "info":
            sev = "low"
        if sev in out:
            out[sev] += 1
    return out


def _dedupe_merged(before: int | None, after: int) -> str:
    if before is None:
        return NOT_RECORDED
    merged = max(0, int(before) - int(after))
    return str(merged)


def _risk_key(rec: dict, mapped: dict | None) -> tuple[int, int, int, str]:
    sev = _sev(rec)
    # Risk, not scanner severity alone: mapped POA&M inclusion + control refs.
    mapped = mapped or {}
    poam = 1 if mapped.get("include_poam") else 0
    refs = 1 if mapped.get("framework_refs") else 0
    return (SEV_RANK.get(sev, 9), -poam, -refs, str(rec.get("ref_id") or ""))


def _frameworks_used(mapped_by_ref: dict[str, dict]) -> str:
    names: list[str] = []
    blob = " ".join(
        str((m or {}).get("framework_refs") or "") for m in mapped_by_ref.values()
    )
    if "cpg_" in blob:
        names.append("CISA CPG")
    if "csf_" in blob:
        names.append("NIST CSF")
    if "nist80053_" in blob or "800-53" in blob:
        names.append("NIST SP 800-53")
    if "cis_" in blob:
        names.append("CIS Controls")
    return ", ".join(names) if names else NOT_RECORDED


def _uncovered_folders(in_dir: Path | None, records: list[dict]) -> list[str]:
    folders = (
        "cloud",
        "nmap",
        "vuln",
        "wazuh",
        "identity",
        "easm",
        "k8s",
        "code",
        "saas",
        "honeypot",
        "dns_email",
    )
    sources = {str(r.get("source") or "") for r in records}
    demo_sources = {
        str(r.get("source") or "")
        for r in records
        if "demo" in [str(x).strip().lower() for x in (r.get("labels") or [])]
    }
    missing: list[str] = []
    for folder in folders:
        area = COLLECTOR_AREAS.get(folder, folder)
        has_live = False
        if in_dir is not None and in_dir.is_dir():
            slot = in_dir / folder
            if slot.is_dir():
                for path in slot.rglob("*"):
                    if path.is_file() and path.name not in {".gitkeep", ".DS_Store", "LAB.txt", "SAMPLE.txt", "README.md"}:
                        # Fixture fallback still counts as "no client data".
                        if folder in demo_sources or any(folder in s for s in demo_sources):
                            has_live = False
                        else:
                            has_live = True
                        break
        else:
            has_live = any(folder in s or COLLECTOR_AREAS.get(s) == area for s in sources - demo_sources)
        if not has_live:
            if area not in missing:
                missing.append(area if area != folder else folder)
    return missing


def _scope_rows(
    records: list[dict],
    in_dir: Path | None,
    stamp: EstateStamp,
) -> list[dict[str, str]]:
    by_source: dict[str, list[dict]] = {}
    for rec in records:
        src = str(rec.get("source") or "").strip() or NOT_RECORDED
        by_source.setdefault(src, []).append(rec)
    rows: list[dict[str, str]] = []
    for src, recs in sorted(by_source.items()):
        extra0 = recs[0].get("extra") if isinstance(recs[0].get("extra"), dict) else {}
        tool = recorded(extra0.get("tool") or extra0.get("scanner") or src)
        version = recorded(extra0.get("version") or extra0.get("tool_version"))
        collected = recorded(
            extra0.get("collected_at")
            or recs[0].get("collected_at")
            or extra0.get("scan_time")
        )
        labels = [str(x).strip().lower() for x in (recs[0].get("labels") or [])]
        if "demo" in labels or "sample" in labels:
            targets = "bundled sample / fixture"
        else:
            targets = recorded(extra0.get("target") or extra0.get("targets") or "file supplied by client")
        rows.append(
            {
                "area": COLLECTOR_AREAS.get(src, src),
                "targets": targets,
                "tool": tool,
                "version": version,
                "collected": collected,
                "records": str(len(recs)),
            }
        )
    return rows[: MAX_EXEC_BODY_ROWS["scope"]]


def _reconcile(
    findings_n: int,
    poam_n: int,
    risk_n: int,
    *,
    vuln_n: int = 0,
    excluded_poam: int = 0,
    merged: str = NOT_RECORDED,
) -> str | None:
    if findings_n == poam_n == risk_n:
        return None
    reasons: list[str] = []
    if vuln_n and findings_n + vuln_n == risk_n:
        reasons.append(
            f"{vuln_n} vulnerability-class rows are counted on the risk register "
            "but not in findings.csv"
        )
    if excluded_poam:
        reasons.append(f"{excluded_poam} findings were not included in the POA&M")
    if merged not in {NOT_RECORDED, "0"} and merged.isdigit() and int(merged) > 0:
        reasons.append(f"{merged} duplicates were merged")
    if findings_n != poam_n and not excluded_poam:
        pass
    if reasons:
        return (
            f"{findings_n} findings produced {poam_n} POA&M rows and {risk_n} "
            f"risk-register entries because {'; '.join(reasons)}."
        )
    return "counts not reconciled"


def _engagement_window(records: list[dict]) -> tuple[str, str]:
    start = _env(None, "GRC_SCAN_START")
    end = _env(None, "GRC_SCAN_END")
    if start or end:
        return recorded(start), recorded(end)
    try:
        from shared.io_util import root_dir

        scope = root_dir() / "dropbox" / "SCOPE.yaml"
        if scope.is_file():
            text = scope.read_text(encoding="utf-8")
            for line in text.splitlines():
                if line.strip().startswith("start:"):
                    start = start or line.split(":", 1)[1].strip().strip("\"'")
                if line.strip().startswith("end:"):
                    end = end or line.split(":", 1)[1].strip().strip("\"'")
    except OSError:
        pass
    times: list[str] = []
    for rec in records:
        extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
        for key in ("collected_at", "scan_time", "first_seen"):
            val = extra.get(key) or rec.get(key)
            if val:
                times.append(str(val))
    if times:
        return recorded(min(times)), recorded(max(times))
    return recorded(start), recorded(end)


@dataclass
class PageContext:
    stamp: EstateStamp
    records: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    poam_rows: list[dict] = field(default_factory=list)
    mapped_by_ref: dict[str, dict] = field(default_factory=dict)
    findings_csv_n: int = 0
    vuln_n: int = 0
    risk_n: int = 0
    poam_n: int = 0
    merged: str = NOT_RECORDED
    excluded_poam: int = 0
    in_dir: Path | None = None
    generated_at: str = ""


def build_executive_summary(ctx: PageContext) -> str:
    stamp = ctx.stamp
    org = (
        stamp.client_name
        if stamp.kind == "CLIENT" and stamp.client_name != NOT_RECORDED
        else recorded(stamp.client_name if stamp.client_name != NOT_RECORDED else None)
    )
    scan_start, scan_end = _engagement_window(ctx.records)
    find_sev = _count_severities(ctx.findings)
    poam_sev = _count_severities(ctx.poam_rows)
    # Duplicates merged are recorded only when the loader supplied a count.
    merged_total = ctx.merged
    merged_by = {s: merged_total if s == "critical" else NOT_RECORDED for s in SEV_TABLE}
    # Per-severity merge is not tracked; print not recorded rather than invent 0.
    merged_by = {s: NOT_RECORDED for s in SEV_TABLE}

    lines = [
        stamp.banner_md(),
        "",
        f"**{stamp.label}**. {org}. Assessment window {scan_start} to {scan_end}.",
        "",
        "### What we found",
        REVIEWER_WHAT_WE_FOUND,
        "",
        "| Severity | Findings | In POA&M | Duplicates merged |",
        "|---|---|---|---|",
    ]
    tot_f = tot_p = 0
    for sev in SEV_TABLE:
        n_f = find_sev[sev]
        n_p = poam_sev[sev]
        tot_f += n_f
        tot_p += n_p
        lines.append(f"| {sev.title()} | {n_f} | {n_p} | {merged_by[sev]} |")
    lines.append(f"| **Total** | {tot_f} | {tot_p} | {merged_total} |")
    lines.append("")
    recon = _reconcile(
        tot_f,
        ctx.poam_n or tot_p,
        ctx.risk_n or tot_f,
        vuln_n=ctx.vuln_n,
        excluded_poam=ctx.excluded_poam,
        merged=ctx.merged,
    )
    if recon:
        lines.append(recon)
        lines.append("")

    ranked = sorted(
        ctx.findings,
        key=lambda rec: _risk_key(rec, ctx.mapped_by_ref.get(str(rec.get("ref_id")))),
    )[: MAX_EXEC_BODY_ROWS["top_n"]]
    lines.extend(
        [
            "### Fix these first (top 5 by risk, not by scanner severity alone)",
            "| # | Weakness | Affected | Why it matters | Recommended action | Finding ref |",
            "|---|---|---|---|---|---|",
        ]
    )
    for i, rec in enumerate(ranked, 1):
        mapped = ctx.mapped_by_ref.get(str(rec.get("ref_id"))) or {}
        weakness = recorded(rec.get("name") or rec.get("ref_id"))
        assets = rec.get("assets") or []
        affected = recorded("|".join(str(a) for a in assets) if assets else None)
        action = recorded(mapped.get("recommended_fix"))
        ref = recorded(rec.get("ref_id"))
        lines.append(
            f"| {i} | {weakness} | {affected} | {REVIEWER_WHY_IT_MATTERS} | {action} | `{ref}` |"
        )
    if not ranked:
        lines.append(
            f"| 1 | {NOT_RECORDED} | {NOT_RECORDED} | {REVIEWER_WHY_IT_MATTERS} | {NOT_RECORDED} | `{NOT_RECORDED}` |"
        )
    lines.append("")

    area_counts: dict[str, list[dict]] = {}
    for rec in ctx.findings:
        area_counts.setdefault(_area_for(rec), []).append(rec)
    top_areas = sorted(area_counts.items(), key=lambda kv: (-len(kv[1]), kv[0]))[
        : MAX_EXEC_BODY_ROWS["areas"]
    ]
    lines.append("### Where the risk concentrates")
    if not top_areas:
        lines.append(f"{NOT_RECORDED}: {NOT_RECORDED} findings, mapped to {NOT_RECORDED}.")
    else:
        for area, recs in top_areas:
            refs: list[str] = []
            for rec in recs:
                mapped = ctx.mapped_by_ref.get(str(rec.get("ref_id"))) or {}
                raw = str(mapped.get("framework_refs") or "").strip()
                for tok in raw.replace(";", ",").split(","):
                    tok = tok.strip()
                    if tok and tok not in refs:
                        refs.append(tok)
            ref_s = ", ".join(refs[:8]) if refs else NOT_RECORDED
            lines.append(f"{area}: {len(recs)} findings, mapped to {ref_s}.")
    lines.append("")

    uncovered = _uncovered_folders(ctx.in_dir, ctx.records)
    uncovered_s = ", ".join(uncovered) if uncovered else NOT_RECORDED
    owner_who = (
        "the client"
        if stamp.kind == "CLIENT"
        else "the operator"
    )
    lines.extend(
        [
            "### What this does not tell you",
            f"- {uncovered_s}. These areas were out of scope or had no scanner output. See the scope statement.",
            "- This is a point-in-time review of scanner artifacts. It is not a penetration test and not continuous monitoring.",
            f"- Owners and due dates in the POA&M are blank until {owner_who} assigns them.",
            "",
            "### Next step",
            REVIEWER_NEXT_STEP,
            "",
            "Companion files: `poam.csv`, `risk_register` (`ciso/risk_scenarios.csv`), the scope and trust statement, and `MANIFEST` (hashes).",
            "",
        ]
    )
    return _fit_one_page("\n".join(lines), keep_tails=("### What this does not tell you", "### Next step", "Companion files:"))


def build_scope_and_trust(ctx: PageContext) -> str:
    stamp = ctx.stamp
    lines = [
        stamp.banner_md(),
        "",
        f"**{stamp.label}**. Run `{stamp.run_id}`, pack `{stamp.pack_commit}`, generated {stamp.generated_at_local}.",
        "",
        "### Authorization",
    ]
    if stamp.kind in {"SAMPLE", "DEMO", "LAB", "MIXED"}:
        lines.append(f"- {SAMPLE_AUTH}")
    else:
        authorizer = recorded(_env(None, "GRC_AUTHORIZER"))
        auth_date = recorded(_env(None, "GRC_AUTH_DATE"))
        scope_ref = recorded(_env(None, "GRC_SCOPE_REF"))
        lines.append(
            f"- Authorized by: {authorizer} on {auth_date}. Reference: {scope_ref}."
        )
    lines.extend(
        [
            "",
            "### What was in scope",
            "| Area | Targets / source | Scanner or export used | Version | Collected (date/time) | Records |",
            "|---|---|---|---|---|---|",
        ]
    )
    scope_rows = _scope_rows(ctx.records, ctx.in_dir, stamp)
    if not scope_rows:
        lines.append(
            f"| {NOT_RECORDED} | {NOT_RECORDED} | {NOT_RECORDED} | {NOT_RECORDED} | {NOT_RECORDED} | {NOT_RECORDED} |"
        )
    else:
        for row in scope_rows:
            lines.append(
                f"| {row['area']} | {row['targets']} | {row['tool']} | {row['version']} | {row['collected']} | {row['records']} |"
            )
    uncovered = _uncovered_folders(ctx.in_dir, ctx.records)
    lines.append("")
    lines.append(
        "Out of scope, or no data supplied: "
        + (", ".join(uncovered) if uncovered else NOT_RECORDED)
        + ". List every collector folder that was empty or fell back to fixtures, by name."
    )
    lines.append("")
    who = recorded(_env(None, "GRC_COLLECTED_BY"))
    merged = recorded(ctx.merged if ctx.merged != "0" else ctx.merged)
    frameworks = _frameworks_used(ctx.mapped_by_ref)
    reviewer = recorded(_env(None, "GRC_REVIEWER"))
    if reviewer == NOT_RECORDED:
        reviewer = REVIEWER_NOT_REVIEWED
    lines.extend(
        [
            "### Method",
            f"1. Scanner output was supplied as files, or collected by {who} under the authorization above. The pack parses files only. It does not run exploits, log in to client systems, or call client APIs.",
            f"2. Each result is normalized, and duplicates are merged ({merged} merged).",
            f"3. Each finding is mapped to controls ({frameworks}) using a per-finding rule table (`per-finding control mapping table`), not by severity.",
            "4. Severity is taken from the source tool and adjusted only where noted in the finding's `severity_rationale`.",
            f"5. A human reviewer ({reviewer}) checked the top findings and the recommended actions before release. If no one did, print \"not human-reviewed\".",
            "",
            "### What the labels mean",
            "- **CLIENT**: derived only from scanner output collected under the authorization above.",
            "- **LAB**: derived from an Evergreen-controlled test environment. It proves the pipeline works, not anything about your organization.",
            "- **SAMPLE / DEMO**: bundled example data used to show the output format. Any hostnames, accounts, or findings in it are fictional.",
            "- **MIXED**: some outputs fell back to bundled sample files. Treat the whole package as not client-ready.",
            "",
            "### Limits (read before relying on this)",
            "- The review covers only what the listed scanners could see, at the collection time shown. A clean area means no data or no detection, not proof of safety.",
            "- No exploitation or verification testing was performed unless a row says otherwise.",
            "- Control mappings are advisory. They show which control would most directly address each weakness, not an audit opinion or a compliance attestation.",
            "- Secrets found in code are redacted in every output. Rotation must be confirmed by the client.",
            "- Nothing was uploaded to any GRC platform. The OpenGRC, Probo, and CISO Assistant files are for the client to import.",
            "",
            "### Integrity and traceability",
            "- Every POA&M row carries a `ref_id` that links to its finding and to the raw artifact under `evidence/`.",
            f"- SHA-256 hashes for every exported file are in `MANIFEST`. Verify with `{recorded(_env(None, 'GRC_VERIFY_COMMAND') or 'sha256sum -c MANIFEST')}`.",
            f"- Contact for questions or corrections: {recorded(_env(None, 'GRC_CONTACT'))}.",
            "",
        ]
    )
    return _fit_one_page(
        "\n".join(lines),
        keep_tails=("### Limits (read before relying on this)", "### Integrity and traceability", "### What the labels mean"),
    )


def _fit_one_page(text: str, *, keep_tails: tuple[str, ...]) -> str:
    lines = text.splitlines()
    if len(lines) <= MAX_PAGE_LINES:
        return text if text.endswith("\n") else text + "\n"
    keep_idx = []
    for needle in keep_tails:
        for i, line in enumerate(lines):
            if line.startswith(needle):
                keep_idx.append(i)
                break
    # Drop extra table rows (lines starting with '| ' that are not the header/sep), never the banner.
    body: list[str] = []
    table_rows_kept = 0
    banner_done = False
    for i, line in enumerate(lines):
        if line.startswith("> **") or (line.startswith("> Run `")):
            body.append(line)
            banner_done = True
            continue
        if line.startswith("| ") and not line.startswith("|---") and "Severity" not in line and "Weakness" not in line and "Area |" not in line:
            # data row
            if table_rows_kept >= 12 and i not in keep_idx:
                continue
            table_rows_kept += 1
        body.append(line)
        if len(body) >= MAX_PAGE_LINES:
            # Ensure tails still present.
            rest = lines[i + 1 :]
            for needle in keep_tails:
                if any(x.startswith(needle) for x in body):
                    continue
                for j, extra in enumerate(rest):
                    if extra.startswith(needle):
                        body.extend(rest[j : j + 8])
                        break
            break
    out = "\n".join(body)
    return out if out.endswith("\n") else out + "\n"


def write_client_pages(out: Path, ctx: PageContext) -> dict[str, str]:
    dest = Path(out)
    dest.mkdir(parents=True, exist_ok=True)
    exec_text = build_executive_summary(ctx)
    trust_text = build_scope_and_trust(ctx)
    for blob in (exec_text, trust_text):
        low = blob.lower()
        for tok in CLIENT_PAGE_FORBIDDEN:
            if tok.lower() in low:
                raise ValueError(f"client page leaked internal token: {tok}")
    exec_path = dest / "EXECUTIVE_SUMMARY.md"
    trust_path = dest / "SCOPE_AND_TRUST.md"
    exec_path.write_text(exec_text, encoding="utf-8")
    trust_path.write_text(trust_text, encoding="utf-8")
    return {"executive_summary": str(exec_path), "scope_and_trust": str(trust_path)}


def write_export_manifest(out: Path, stamp: EstateStamp) -> Path:
    dest = Path(out)
    dest.mkdir(parents=True, exist_ok=True)
    rels = list(EXPORT_CSV_REL) + list(EXPORT_MD_REL) + list(EXPORT_OTHER_REL)
    lines = [
        stamp.banner_md(),
        "",
        "# MANIFEST",
        "",
        "SHA-256 of exported files. Verify with `sha256sum -c MANIFEST` after stripping the banner lines, or hash each path below.",
        "",
        "| File | SHA-256 |",
        "|---|---|",
    ]
    for rel in rels:
        path = dest / rel
        if not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"| `{rel}` | `{digest}` |")
    path = dest / "MANIFEST"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def stamp_text_file(path: Path, stamp: EstateStamp, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(prepend_banner_md(body, stamp), encoding="utf-8")
