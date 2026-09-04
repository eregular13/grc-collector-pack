"""Load farm/SLOTS.yaml. Mapping form only. No binaries."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from dropbox.scope import FORBIDDEN_TOOLS
from dropbox.yaml_lite import load_yaml

FARM_ROOT = Path(__file__).resolve().parents[1]
SLOTS_PATH = FARM_ROOT / "SLOTS.yaml"
LICENSE_CLASSES = frozenset({"use_dont_ship", "commercial_byo", "oss_byo"})
LAYER_C_SENSORS = frozenset(
    {"cloud", "nmap", "vuln", "wazuh", "identity", "easm", "k8s", "code", "saas"}
)
FILE_DROP_ONLY = frozenset(
    {"nikto", "gobuster", "ffuf", "amass", "subfinder", "scoutsuite", "checkov"}
)
# Never live-subprocess these, even if allowlisted somehow.
LICENSE_LOCK_LIVE = frozenset(FORBIDDEN_TOOLS) | {
    "nuclei",
    "openvas",
    "gvm",
    "gvmd",
    "pingcastle",
    "purpleknight",
    "bloodhound",
    "osqueryi",
}
DISCOVER_PREFER = ("nmap", "rustscan", "naabu")
DEEPEN_PREFER = ("nessus", "nessuscli")
PLAN_STAGES = ("discover", "deepen", "external")
REQUIRED_FIELDS = (
    "id",
    "binary",
    "stage",
    "scope_key",
    "output_glob",
    "license_class",
    "default_batch",
)


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, Any]:
    data = load_yaml(SLOTS_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("SLOTS.yaml must be a mapping")
    slots = data.get("slots") or {}
    if not isinstance(slots, dict):
        raise ValueError("slots must be a mapping")
    return data


def load_slots() -> dict[str, dict[str, Any]]:
    slots = load_catalog().get("slots") or {}
    out: dict[str, dict[str, Any]] = {}
    for key, raw in slots.items():
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        if "invoke" not in row:
            row["invoke"] = bool(row.get("wired")) and row.get("scope_key") == "allow_tools"
        if key in FILE_DROP_ONLY:
            row["wired"] = False
            row["invoke"] = False
            row["scope_key"] = "file_drop"
        out[str(key)] = row
    return out


def wired_slots() -> dict[str, dict[str, Any]]:
    return {k: v for k, v in load_slots().items() if v.get("wired") is True}


def invoke_slots() -> dict[str, dict[str, Any]]:
    """Wired slots that may subprocess when allowlisted + on PATH."""
    return {k: v for k, v in wired_slots().items() if v.get("invoke") is True}


def slot_matrix(allow_tools: list[str], which=None) -> list[dict[str, Any]]:
    """allow_tools ∩ PATH ∩ SLOTS. Never downloads."""
    from dropbox.orchestrator import byo

    which_fn = which or byo.farm_which
    slots = load_slots()
    rows = byo.tool_matrix(allow_tools, which=which_fn)
    for row in rows:
        slot = slots.get(row["tool"]) or {}
        row["in_slots"] = row["tool"] in slots
        row["wired"] = bool(slot.get("wired"))
        row["license_class"] = str(slot.get("license_class") or "")
        if not row["in_slots"]:
            row["slot_state"] = "not-in-slots"
        elif row["on_path"]:
            row["slot_state"] = "present"
        else:
            row["slot_state"] = "missing"
    return rows


def refuse_live_slot(slot_id: str, binary: str | None = None) -> str | None:
    """Return a refuse reason, or None if the slot may be considered for live."""
    name = (slot_id or "").strip().lower()
    bin_name = (binary or name).strip().lower()
    if name in LICENSE_LOCK_LIVE or bin_name in LICENSE_LOCK_LIVE:
        return f"LICENSE-LOCK: never subprocess {name or bin_name}"
    if name in FILE_DROP_ONLY or bin_name in FILE_DROP_ONLY:
        return f"file_drop only: never subprocess {name or bin_name}"
    return None


def select_stage_slots(
    stage: str,
    allow_tools: list[str] | None = None,
    which=None,
) -> dict[str, Any]:
    """allow_tools ∩ wired invoke ∩ stage. Missing PATH stays selected with will_run false."""
    from dropbox.orchestrator import byo

    which_fn = which or byo.farm_which
    want = str(stage or "").strip().lower()
    allow = {str(t).strip().lower() for t in (allow_tools or []) if str(t).strip()}
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for name, slot in load_slots().items():
        cat = str(slot.get("category") or slot.get("stage") or "").lower()
        if cat != want:
            continue
        binary = str(slot.get("binary") or name).lower()
        refuse = refuse_live_slot(name, binary)
        allowlisted = name in allow or binary in allow
        invoke = bool(slot.get("invoke")) and bool(slot.get("wired"))
        if refuse:
            skipped.append(
                {
                    "slot": name,
                    "binary": binary,
                    "will_run": False,
                    "state": "file_drop",
                    "reason": refuse,
                }
            )
            continue
        if not invoke:
            skipped.append(
                {
                    "slot": name,
                    "binary": binary,
                    "will_run": False,
                    "state": "file_drop",
                    "reason": "file_drop (not a callable adapter)",
                }
            )
            continue
        if not allowlisted:
            skipped.append(
                {
                    "slot": name,
                    "binary": binary,
                    "will_run": False,
                    "state": "not-allowlisted",
                    "reason": "not in SCOPE.allow_tools",
                }
            )
            continue
        on_path = bool(which_fn(binary))
        selected.append(
            {
                "slot": name,
                "binary": binary,
                "will_run": on_path,
                "allowlisted": True,
                "on_path": on_path,
                "state": "present" if on_path else "missing",
                "reason": "" if on_path else "not on PATH — plan only (will not download)",
            }
        )
    prefer = DISCOVER_PREFER if want == "discover" else DEEPEN_PREFER if want == "deepen" else ()
    rank = {name: index for index, name in enumerate(prefer)}
    selected.sort(key=lambda row: (rank.get(row["slot"], 99), row["slot"]))
    skipped.sort(key=lambda row: row["slot"])
    ready = [row["slot"] for row in selected if row.get("will_run")]
    return {
        "stage": want,
        "selected": selected,
        "skipped": skipped,
        "ready": ready,
        "primary": ready[0] if ready else "",
    }


def plan_stage_slots(allow_tools: list[str] | None = None, which=None) -> dict[str, Any]:
    """Discover / deepen / external slot plans for orchestrate summary."""
    return {stage: select_stage_slots(stage, allow_tools, which=which) for stage in PLAN_STAGES}


def farm_slot_status(
    allow_tools: list[str] | None = None,
    which=None,
    category: str | None = None,
) -> list[dict[str, Any]]:
    """Full SLOTS matrix: wired / invoke / PATH / allowlist. Never downloads."""
    from dropbox.orchestrator import byo

    which_fn = which or byo.farm_which
    allow = {str(t).strip().lower() for t in (allow_tools or []) if str(t).strip()}
    rows: list[dict[str, Any]] = []
    for name, slot in load_slots().items():
        binary = str(slot.get("binary") or name).lower()
        on_path = bool(which_fn(binary))
        invoke = bool(slot.get("invoke"))
        allowlisted = name in allow or binary in allow
        if not invoke:
            state = "file_drop"
        elif allowlisted and on_path:
            state = "present"
        elif allowlisted:
            state = "missing"
        else:
            state = "not-allowlisted"
        rows.append(
            {
                "slot": name,
                "binary": binary,
                "wired": bool(slot.get("wired")),
                "invoke": invoke,
                "allowlisted": allowlisted,
                "on_path": on_path,
                "license_class": str(slot.get("license_class") or ""),
                "scope_key": str(slot.get("scope_key") or ""),
                "category": str(slot.get("category") or slot.get("stage") or ""),
                "sensor": slot.get("sensor"),
                "output_glob": slot.get("output_glob"),
                "state": state,
            }
        )
    if category:
        want = str(category).strip().lower()
        rows = [row for row in rows if str(row.get("category") or "").lower() == want]
    return rows


def audit_output_globs() -> list[str]:
    """Return slots whose output_glob is not in/<Layer-C-sensor>/…"""
    hits: list[str] = []
    for name, slot in load_slots().items():
        glob = str(slot.get("output_glob") or "")
        sensor = str(slot.get("sensor") or "")
        if sensor not in LAYER_C_SENSORS:
            hits.append(f"{name}: sensor {sensor!r} is not a Layer C dir")
            continue
        prefix = f"in/{sensor}/"
        if not glob.startswith(prefix):
            hits.append(f"{name}: output_glob {glob!r} does not land in {prefix}")
    return hits


def catalog_summary() -> dict[str, Any]:
    """Counts for conductor + SLOTS.md. No binaries."""
    slots = load_slots()
    by_category: dict[str, dict[str, int]] = {}
    wired = invoke = file_drop = 0
    for slot in slots.values():
        cat = str(slot.get("category") or slot.get("stage") or "other")
        bucket = by_category.setdefault(cat, {"total": 0, "wired": 0, "invoke": 0, "file_drop": 0})
        bucket["total"] += 1
        if slot.get("wired"):
            wired += 1
            bucket["wired"] += 1
        if slot.get("invoke"):
            invoke += 1
            bucket["invoke"] += 1
        else:
            file_drop += 1
            bucket["file_drop"] += 1
    return {
        "total": len(slots),
        "wired": wired,
        "invoke": invoke,
        "file_drop": file_drop,
        "by_category": dict(sorted(by_category.items())),
    }


BRAKES_DEFAULTS = (
    ("scope", "dropbox/SCOPE.yaml required"),
    ("deepen", "stages.deepen default false; live needs flag + allow_tools"),
    ("max_workers", "2"),
    ("deepen_batch", "3 (must be 2-5)"),
    ("host_timeout_sec", "30"),
    ("wildcard_cidr", "external named hosts only; refuse 0.0.0.0/0 and /8-/16 spray"),
    ("byo_path", "allow_tools ∩ PATH; missing → plan-only; never apt/embed"),
    ("license_lock", "never embed scanners; nuclei/openvas/osquery stay file_drop"),
    ("wrap", "push_riskready.sh review-only; never POST"),
    ("external_ingest", "file-drop inventory of in/easm|…; never probe"),
    ("layer_c", "parse-only ingest into in/<sensor>/"),
    ("compose", "scanner-free; runtime ABSENT without Docker CLI"),
)


def brakes_defaults() -> dict[str, str]:
    """Structured brakes table. Matches farm/INTEGRITY.md. No binaries."""
    return {key: value for key, value in BRAKES_DEFAULTS}


def ingest_map() -> dict[str, dict[str, int]]:
    """Slot counts by Layer C sensor dir. No theater sensors."""
    slots = load_slots()
    by_sensor: dict[str, dict[str, int]] = {
        sensor: {"total": 0, "invoke": 0, "file_drop": 0} for sensor in sorted(LAYER_C_SENSORS)
    }
    for slot in slots.values():
        sensor = str(slot.get("sensor") or "")
        bucket = by_sensor.setdefault(sensor, {"total": 0, "invoke": 0, "file_drop": 0})
        bucket["total"] += 1
        if slot.get("invoke"):
            bucket["invoke"] += 1
        else:
            bucket["file_drop"] += 1
    return by_sensor


SKIP_DROP_NAMES = frozenset({".gitkeep", "plan.json", "summary.json"})


def parse_output_glob(output_glob: str) -> tuple[str, str] | None:
    """`in/easm/*.jsonl` → (`easm`, `*.jsonl`). Refuse unknown sensors."""
    text = str(output_glob or "").strip()
    if not text.startswith("in/"):
        return None
    rest = text[3:]
    if "/" not in rest:
        return None
    sensor, pattern = rest.split("/", 1)
    if sensor not in LAYER_C_SENSORS or not pattern:
        return None
    return sensor, pattern


def dropped_file_inventory(dest_in: Path, category: str = "external") -> dict[str, Any]:
    """List operator-dropped files already in dest_in. Never probes. Never subprocess."""
    want = str(category or "").strip().lower()
    sensors: dict[str, list[str]] = {}
    for _name, slot in load_slots().items():
        cat = str(slot.get("category") or slot.get("stage") or "").lower()
        if cat != want:
            continue
        parsed = parse_output_glob(str(slot.get("output_glob") or ""))
        if not parsed:
            continue
        sensor, pattern = parsed
        folder = dest_in / sensor
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob(pattern)):
            if not path.is_file() or path.name in SKIP_DROP_NAMES:
                continue
            bucket = sensors.setdefault(sensor, [])
            if path.name not in bucket:
                bucket.append(path.name)
    for names in sensors.values():
        names.sort()
    files = [f"{sensor}/{name}" for sensor, names in sorted(sensors.items()) for name in names]
    return {
        "category": want,
        "file_count": len(files),
        "files": files,
        "sensors": {sensor: list(names) for sensor, names in sorted(sensors.items())},
        "will_run": False,
        "live": False,
        "probed": False,
        "note": (
            "Operator file-drop inventory only. Orchestrator does not probe. "
            "Land artifacts in in/easm|… then Layer C parses."
        ),
    }


def render_slots_md() -> str:
    summary = catalog_summary()
    lines = [
        "# Farm SLOTS catalog",
        "",
        "Private drop-box tool zoo. **No binaries in git.** Most slots are file_drop:",
        "the operator lands artifacts in `in/<sensor>/` for Layer C.",
        "",
        f"Total: {summary['total']}",
        f"Wired: {summary['wired']}",
        f"Invoke: {summary['invoke']}",
        f"File-drop: {summary['file_drop']}",
        "",
        "## By category",
        "",
        "| category | total | wired | invoke | file_drop |",
        "|---|---:|---:|---:|---:|",
    ]
    for cat, bucket in summary["by_category"].items():
        lines.append(
            f"| {cat} | {bucket['total']} | {bucket['wired']} | {bucket['invoke']} | {bucket['file_drop']} |"
        )
    lines.extend(
        [
            "",
            "## Ingest map (Layer C)",
            "",
            "Every `output_glob` lands in an existing Layer C sensor directory.",
            "`audit_output_globs()` is empty. No theater parsers.",
            "",
            "| sensor | total | invoke | file_drop |",
            "|---|---:|---:|---:|",
        ]
    )
    for sensor, bucket in ingest_map().items():
        lines.append(
            f"| in/{sensor}/ | {bucket['total']} | {bucket['invoke']} | {bucket['file_drop']} |"
        )
    lines.extend(
        [
            "",
            "File-drop only (never subprocess even if on PATH): "
            + ", ".join(sorted(FILE_DROP_ONLY))
            + ".",
            "",
            "LICENSE-LOCK names stay file_drop and are never subprocessed.",
            "",
            "## Nmap file-drop (Layer C)",
            "",
            "Drop Nmap **gnmap** (`-oG`), **XML** (`-oX`), or a thin **JSON** host/port",
            "export under `in/nmap/`. Also drop **masscan** `-oX` XML or `-oJ` JSON",
            "(`scanner=\"masscan\"`, `{ip, ports:[{port, proto, status}]}`). Open ports",
            "only — empty `ports` / empty `nmaprun` invent nothing. masscan stays",
            "`file_drop` / `use_dont_ship` (never subprocess). The inventory-nmap",
            "collector is parse-only — it never subprocesses `nmap` or `masscan`.",
            "Orchestrator discover may land DEMO stub gnmap",
            "(`farm/tool-bin/lab/nmap` → `dropbox-discover-*.gnmap`) or BYO output.",
            "Open 445 / 3389 / 23 map to the existing CISO/POA&M rows (SMB, RDP, Telnet).",
            "Also drop **rustscan** / **naabu** JSON or JSONL (`{ip, port}` or",
            "`{ip, ports:[int]}`). Open ports only — empty / closed invent nothing.",
            "rustscan / naabu *invoke* stays BYO (`allow_tools` + PATH); Layer C never",
            "subprocesses those binaries. Also drop **arp-scan** text or JSON",
            "(`Starting arp-scan` / IP + MAC + vendor lines, or `{ip, mac, vendor}`).",
            "Hosts become assets only — empty / header-only / 0 responded invent nothing.",
            "arp-scan stays `file_drop` (never subprocess; no live ARP). Also drop",
            "**fping** text or JSON (`host is alive` / `{ip, hostname, alive}`). Alive",
            "hosts become assets only — unreachable / empty invent nothing. fping stays",
            "`file_drop` (never subprocess; no live ping). Empty `in/` still loads",
            "`fixtures/demo/nmap/` (`scan.gnmap`, `scan.xml`, `masscan.xml`,",
            "`naabu.jsonl`, `arp-scan.txt`, `fping.txt`). No new catalog slots.",
            "",
            "## Kubernetes file-drop (Layer C)",
            "",
            "Drop **Kubescape** JSON (`summaryDetails.controls` or `results`) and",
            "**kube-bench** JSON (`Controls[].tests[].results[]` or a flat FAIL list) under",
            "`in/k8s/`. Failed/FAIL rows only — Passed/PASS stay silent. Parse-only — no",
            "`kubectl`, no live cluster API. High rows map to CISO/POA&M when obvious",
            "(privileged containers, anonymous-auth, privilege escalation, hostNetwork).",
            "Empty `in/` still loads `fixtures/demo/k8s/` (`kubescape.json`,",
            "`kube-bench.json`). kube-bench / kubescape stay file_drop (never subprocess).",
            "No new catalog slots.",
            "",
            "## KEEP-chain file-drop (Layer C)",
            "",
            "Drop **testssl.sh JSON** (native finding array or `scanResult` wrapper) under",
            "`in/vuln/` or `in/easm/`. HIGH/CRITICAL/WARN rows only — OK/INFO are silent.",
            "Drop **sslscan** XML (`ssltest` / `protocol`) or text (`SSL/TLS Protocols`)",
            "under `in/vuln/` or `in/easm/`. Weak/failed only (TLS 1.0, SSLv2/v3,",
            "Heartbleed, weak ciphers). Empty / TLS 1.2-only invent nothing. sslscan",
            "XML/text is not testssl JSON — a separate parse. No live TLS from Layer C.",
            "High rows map to CISO/POA&M when obvious (Heartbleed, TLS 1.0). Empty `in/`",
            "still loads `fixtures/demo/vuln/testssl.json` and `sslscan.xml`. testssl /",
            "sslscan *invoke* is separate BYO (`allow_tools`) and stays plan-only from",
            "orchestrate.",
            "",
            "Drop **Maester** / Entra assessment JSON under `in/saas/` (`TestResults` /",
            "`Tests`, or a Graph `directoryRoles` export). Failed rows only; Passed/Skipped",
            "stay silent. The collector does not call Microsoft Graph. Empty `in/` still",
            "loads `fixtures/demo/saas/maester.json`. Maester *invoke* is separate BYO.",
            "No new catalog slots.",
            "",
            "## BloodHound CE file-drop (Layer C)",
            "",
            "Drop **BloodHound CE** / **SharpHound** JSON under `in/identity/`",
            "(`data.nodes` / `data.edges`, a top-level `nodes`/`edges` graph, or SharpHound",
            "`data` arrays with `Properties` / `ObjectIdentifier` / `Aces`). Mapped edges",
            "only (GenericAll, DCSync, AdminTo, HasSession, …). Empty `data` / empty",
            "`Members` invent nothing. Parse-only — no LDAP, no BloodHound API, no",
            "SharpHound run. High rows map to CISO/POA&M (DCSync, GenericAll, roastable",
            "SPN, AS-REP, unconstrained delegation, Backup Operators). Empty `in/` still",
            "loads `fixtures/demo/identity/bloodhound.json` and `bloodhound-edges.json`.",
            "bloodhound / azurehound stay file_drop (never subprocess). No new catalog slots.",
            "",
            "## Endpoint file-drop (Layer C)",
            "",
            "Drop **HardeningKitty Audit CSV** under `in/identity/` (Failed/warning rows",
            "only; Passed and Guest-passed stay silent — the parser does not invent",
            "Windows findings). Drop a **Lynis** report or `report.dat` under `in/wazuh/`",
            "(`*.txt` / `*.log` / `*.dat`). Parse-only — no AD/LDAP/WinRM and no live",
            "Lynis run. High rows map to CISO/POA&M when the title is obvious (password",
            "history, LM hash, host firewall missing, SSH PermitRootLogin). Empty `in/`",
            "still loads `fixtures/demo/identity/hardeningkitty.csv` and",
            "`fixtures/demo/wazuh/lynis-report.txt`. Lynis *invoke* is separate BYO",
            "(`allow_tools`) when the binary is on PATH; this path is file-drop ingest.",
            "",
            "Drop **Fleet** host/policy JSON under `in/wazuh/` (`hosts`, `data.hosts`,",
            "or a single `host`, plus failing `policies`). Offline/MIA hosts become",
            "coverage gaps. `disk_encryption_enabled=false` and MDM enrollment Off map",
            "to CISO/POA&M. Passing policies stay silent. Empty `hosts` / `policies`",
            "invent nothing. Parse-only — no Fleet API, no fleetctl, no osqueryi.",
            "Empty `in/` still loads `fixtures/demo/wazuh/fleet.json`. No new catalog slots.",
            "",
            "Drop **CIS-CAT** / XCCDF JSON or XML under `in/wazuh/` or `in/identity/`.",
            "Failed/failing rows only — Pass stays silent. Empty `results` invents",
            "nothing. High rows map to CISO/POA&M when obvious (SSH PermitRootLogin,",
            "host firewall, disk encryption). Drop **osquery** check JSON under",
            "`in/wazuh/` (`queries` / `osquery` rows with status=fail). Inventory-only",
            "`system_info` stays host coverage, not invented checks. Parse-only — no",
            "CIS-CAT binary, no osqueryi. Empty `in/` still loads",
            "`fixtures/demo/wazuh/cis-cat.json` and `osquery-checks.json`.",
            "cis-cat / osqueryi stay file_drop. No new catalog slots.",
            "",
            "## Cloud file-drop (Layer C)",
            "",
            "Drop **Prowler** JSON or **ASFF** (`Findings` array / list / single object)",
            "and **ScoutSuite** `services.*.findings` JSON under `in/cloud/`. Optional",
            "same-folder drops: Cloud Custodian and Steampipe. Parse-only — no AWS/GCP/Azure",
            "API calls, no live cloud scan. High FAIL rows map to CISO/POA&M when the title",
            "or check id is obvious (public S3 / AllUsers, IAM AdministratorAccess, root MFA,",
            "SG `0.0.0.0/0`, public RDS, unencrypted S3/EBS). Empty `in/` still loads demo",
            "`fixtures/demo/cloud/` (including `prowler-asff.json` and `scoutsuite.json`).",
            "Prowler *invoke* is separate BYO (`allow_tools`) when the binary is on PATH;",
            "this path is file-drop ingest. ScoutSuite stays file_drop-only.",
            "No new catalog slots.",
            "",
            "## EASM file-drop (Layer C)",
            "",
            "Drop **httpx** / **Amass** / **Subfinder** JSON, JSONL, or a host list under",
            "`in/easm/`. Native JSON arrays and `{results|hosts|data}` wrappers parse.",
            "httpx `failed:true` rows and empty arrays invent nothing. Interesting",
            "rows only: sensitive perimeter names (vpn/admin/dev-api/staging) and",
            "admin/login titles. Also drop **ffuf** JSON (`results` + status/url) and",
            "**gobuster** text (`(Status: N)` lines). Interesting paths only",
            "(`/admin`, `/login`, `/.git`) — 404 and robots stay silent. Drop",
            "**WhatWeb** `--log-json` (`target` + `plugins`, or `{data}` wrap).",
            "Admin/login titles and interesting paths only — generic nginx/Home",
            "rows stay silent. Empty arrays invent nothing. High rows map to",
            "CISO/POA&M (perimeter hostnames, exposed admin UI, TLS weak",
            "cipher). Parse-only — no live DNS/HTTP, no amass/httpx/subfinder/ffuf/",
            "gobuster/whatweb subprocess. Empty `in/` still loads `fixtures/demo/easm/`",
            "(`httpx.jsonl`, `httpx.json`, `amass.jsonl`, `ffuf.json`, `whatweb.json`).",
            "amass / subfinder / ffuf / gobuster / whatweb stay file_drop; httpx",
            "*invoke* is separate BYO. No new catalog slots.",
            "",
            "## Nuclei JSON file-drop (Layer C)",
            "",
            "Drop **Nuclei** JSON / JSONL under `in/vuln/` (JSONL, a single object,",
            "an array, or a `{results|matches|findings}` wrapper). `template-id` /",
            "`template_id` / `info` rows only. INFO stays silent. Empty `results`",
            "invents nothing. Parse-only — this repo never subprocesses `nuclei`.",
            "High rows map to CISO/POA&M when obvious (Log4Shell / RCE). Empty `in/`",
            "still loads `fixtures/demo/vuln/nuclei.jsonl`. nuclei stays file_drop.",
            "No new catalog slots.",
            "",
            "## Nikto file-drop (Layer C)",
            "",
            "Drop **Nikto** text, XML (`niktoscan` / `scandetails`), or JSON",
            "(`vulnerabilities` / `items`) under `in/vuln/`. Slot glob is",
            "`in/vuln/*.txt`; `.xml` / `.json` also parse. Interesting/high rows",
            "only (`/admin`, `/login`, `/.git`, phpinfo, directory indexing).",
            "Missing security-header noise stays silent. Empty exports invent",
            "nothing. Deepen DEMO `.txt` stubs (NessusClientData) are not Nikto",
            "and invent nothing. High rows map to CISO/POA&M (exposed admin UI).",
            "Parse-only — this repo never subprocesses nikto and does not probe",
            "HTTP. Empty `in/` still loads `fixtures/demo/vuln/nikto.txt`.",
            "nikto stays file_drop. No new catalog slots.",
            "",
            "## Nessus file-drop (Layer C)",
            "",
            "Drop an operator-landed **NessusClientData** / `.nessus` XML under",
            "`in/vuln/` (`ReportHost` / `ReportItem`). High/Critical rows only,",
            "plus key Medium already patterned (SMB 445, RDP 3389, Telnet, TLS 1.0).",
            "Info/Low and empty `Report` invent nothing. Farm DEMO tool-bin `.txt`",
            "stubs (`NessusClientData` comment, no `ReportHost`) are not exports",
            "and invent nothing. High rows map to CISO/POA&M when the title is",
            "obvious (SMB, RDP, TLS). Parse-only — Layer C never runs a Nessus",
            "binary and never calls a Nessus API. nessus / nessuscli *invoke* is",
            "separate BYO (`allow_tools` + PATH). Empty `in/` still loads",
            "`fixtures/demo/vuln/demo.nessus`. No new catalog slots.",
            "",
            "## SaaS file-drop (Layer C)",
            "",
            "Drop **ScubaGear** / Entra assessment JSON or JSONL under `in/saas/`",
            "(`Results`, `{data|ScubaResults|scuba}` wrappers, or a row array).",
            "Failed/high rows only — Pass / Skip / Info stay silent. Empty `Results`",
            "invents nothing. Drop **Okta** org/policy JSON (`users` / `policies` /",
            "`org`, or `{data|okta}` wrappers). Inactive MFA_ENROLL (or an MFA-named",
            "policy) becomes a finding; empty `users`/`policies` invent nothing.",
            "Maester Failed rows and Graph `directoryRoles` exports stay parse-only.",
            "High MFA / standing Global Administrator rows map to CISO/POA&M.",
            "Parse-only — Layer C never calls Microsoft Graph or the Okta API.",
            "scuba / okta-logs / entra-export / graph-export stay file_drop.",
            "Maester *invoke* is separate BYO. Empty `in/` still loads",
            "`fixtures/demo/saas/` (`scuba.json`, `scuba-wrap.json`, `okta.json`,",
            "`maester.json`, `graph.json`). No new catalog slots.",
            "",
            "## Secrets / IaC file-drop (Layer C)",
            "",
            "Drop **Gitleaks** / **TruffleHog** / **Semgrep** / **Checkov** JSON or",
            "JSONL under `in/code/`. Gitleaks arrays and `{findings|leaks|results}`",
            "wrappers parse. TruffleHog JSONL and `{results}` wrappers parse.",
            "Checkov `results.failed_checks` only — passed / skipped / INFO stay",
            "silent. Empty exports invent nothing. Secret material is redacted.",
            "High rows map to CISO/POA&M (credential rotate, public S3 / public ACL).",
            "Parse-only — no gitleaks / trufflehog / semgrep / checkov subprocess.",
            "Empty `in/` still loads `fixtures/demo/code/` (`gitleaks.json`,",
            "`trufflehog.jsonl`, `checkov.json`). gitleaks / checkov stay file_drop.",
            "No new catalog slots.",
            "",
            "## SARIF file-drop (Layer C)",
            "",
            "nuclei / semgrep / trivy stay file_drop (this repo does not run them).",
            "Operator-landed SARIF is parsed by vuln-scan (`in/vuln/*.sarif`) and",
            "code-secrets (`in/code/*.sarif`). High rules map to CISO/POA&M.",
            "No new catalog slots.",
            "",
            "See `SLOTS.yaml`, `INTEGRITY.md`, and `OPERATOR.md`.",
            "",
        ]
    )
    return "\n".join(lines)


def write_slots_md() -> Path:
    dest = FARM_ROOT / "SLOTS.md"
    dest.write_text(render_slots_md(), encoding="utf-8")
    return dest
