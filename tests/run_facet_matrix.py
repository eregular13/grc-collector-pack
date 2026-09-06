"""Isolated product-facet checks. Uses tmp OUT_DIR; does not stop the 30m job."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SENSORS = ("cloud", "nmap", "vuln", "wazuh", "identity", "easm", "k8s", "code", "saas")
COLLECTORS = (
    "cloud_prowler",
    "inventory_nmap",
    "vuln_scan",
    "host_wazuh",
    "identity_ad",
    "easm",
    "k8s_kubescape",
    "code_secrets",
    "saas_idp",
)
FAILS: list[str] = []


def _ok(name: str, detail: str = "") -> None:
    print(f"FACET_OK  {name}  {detail}".rstrip())


def _fail(name: str, detail: str) -> None:
    FAILS.append(f"{name}: {detail}")
    print(f"FACET_FAIL  {name}  {detail}")


def facet_empty_in_fallback() -> None:
    from shared.io_util import discover_input_files

    tmp = Path(tempfile.mkdtemp(prefix="grc-empty-"))
    shutil.copytree(ROOT / "fixtures", tmp / "fixtures")
    for sensor in SENSORS:
        (tmp / "in" / sensor).mkdir(parents=True)
    os.environ["PACK_ROOT"] = str(tmp)
    try:
        files = discover_input_files("cloud")
        if not files:
            _fail("empty_in", "no fixture fallback")
            return
        if not all("fixtures" in str(p).replace("\\", "/") for p in files):
            _fail("empty_in", f"unexpected paths {files}")
            return
        _ok("empty_in", f"{len(files)} fixture files")
    finally:
        os.environ["PACK_ROOT"] = str(ROOT)
        shutil.rmtree(tmp, ignore_errors=True)


def facet_live_scan_ignored() -> None:
    from shared.io_util import refuse_live_scan

    os.environ["GRC_LIVE_SCAN"] = "1"
    try:
        refuse_live_scan()
        _ok("live_scan_ignored", "flag does not enable scanners")
    finally:
        os.environ["GRC_LIVE_SCAN"] = "0"


def facet_loader_race() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="grc-race-"))
    os.environ["OUT_DIR"] = str(tmp)
    os.environ["PACK_ROOT"] = str(ROOT)
    try:
        from collectors.grc_loader import run_loader

        try:
            run_loader()
            _fail("loader_race", "expected SystemExit for missing canonical")
        except SystemExit as exc:
            if "missing canonical" in str(exc):
                _ok("loader_race", str(exc))
            else:
                _fail("loader_race", str(exc))
    finally:
        os.environ.pop("OUT_DIR", None)
        shutil.rmtree(tmp, ignore_errors=True)


def facet_double_loader() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="grc-dbl-"))
    os.environ["OUT_DIR"] = str(tmp)
    os.environ["PACK_ROOT"] = str(ROOT)
    os.environ["GRC_LIVE_SCAN"] = "0"
    try:
        from collectors.grc_loader import run_loader
        import importlib

        for name in COLLECTORS:
            mod = importlib.import_module(f"collectors.{name}")
            mod.main()
        first = run_loader()
        second = run_loader()
        if first != second:
            _fail("double_loader", f"{first} != {second}")
            return
        if first.get("assets", 0) < 20 or first.get("findings", 0) < 20:
            _fail("double_loader", f"short counts {first}")
            return
        _ok("double_loader", json.dumps(first, sort_keys=True))
    except Exception as exc:  # noqa: BLE001
        _fail("double_loader", repr(exc))
    finally:
        os.environ.pop("OUT_DIR", None)
        os.environ["PACK_ROOT"] = str(ROOT)
        shutil.rmtree(tmp, ignore_errors=True)


def facet_redact() -> None:
    from shared.io_util import redact_text

    raw = "id AKIAIOSFODNN7EXAMPLE trailing"
    out = redact_text(raw)
    if "AKIAIOSFODNN7EXAMPLE" in out or "[REDACTED]" not in out:
        _fail("redact", out)
        return
    _ok("redact", "AKIA stripped")


def facet_push_scripts_safe() -> None:
    forbidden = "POST /api/risks"
    hits = []
    for path in ROOT.glob("push_*"):
        if forbidden in path.read_text(encoding="utf-8", errors="replace"):
            hits.append(path.name)
    if hits:
        _fail("push_scripts_safe", str(hits))
        return
    _ok("push_scripts_safe", "no forbidden risk upload string")


def facet_push_sh_dry_run() -> None:
    env = os.environ.copy()
    env["CISO_PUSH"] = "0"
    env["RISKREADY_PUSH"] = "0"
    env["DRY_RUN"] = "1"
    bash = shutil.which("bash")
    if os.name == "nt" or not bash:
        _ok("push_sh_dry_run", "skipped on Windows host; Linux containers run the .sh scripts")
        return
    for script in ("push_ciso.sh", "push_riskready.sh"):
        path = ROOT / script
        if not path.exists():
            _fail("push_sh_dry_run", f"missing {script}")
            return
        proc = subprocess.run(
            [bash, str(path)],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            _fail("push_sh_dry_run", f"{script} exit {proc.returncode} {proc.stderr[-200:]}")
            return
        blob = proc.stdout + proc.stderr
        if script == "push_riskready.sh":
            if "WRAP_DEAD" not in blob:
                _fail("push_sh_dry_run", f"{script} no WRAP_DEAD banner")
                return
        elif "DRY_RUN" not in blob:
            _fail("push_sh_dry_run", f"{script} no DRY_RUN banner")
            return
    _ok("push_sh_dry_run", "ciso dry-run + riskready WRAP_DEAD")


def facet_parse_each_sensor() -> None:
    import importlib

    mapping = {
        "cloud": "cloud_prowler",
        "nmap": "inventory_nmap",
        "vuln": "vuln_scan",
        "wazuh": "host_wazuh",
        "identity": "identity_ad",
        "easm": "easm",
        "k8s": "k8s_kubescape",
        "code": "code_secrets",
        "saas": "saas_idp",
    }
    tmp = Path(tempfile.mkdtemp(prefix="grc-parse-"))
    os.environ["OUT_DIR"] = str(tmp)
    os.environ["PACK_ROOT"] = str(ROOT)
    try:
        for sensor, modname in mapping.items():
            mod = importlib.import_module(f"collectors.{modname}")
            mod.main()
            canon = tmp / "canonical" / f"{sensor}.jsonl"
            if not canon.exists() or canon.stat().st_size == 0:
                _fail("parse_each", f"{sensor} empty canonical")
                return
        _ok("parse_each", "nine canonical jsonl")
    except Exception as exc:  # noqa: BLE001
        _fail("parse_each", repr(exc))
    finally:
        os.environ.pop("OUT_DIR", None)
        shutil.rmtree(tmp, ignore_errors=True)


def facet_sink() -> None:
    url = os.environ.get("SINK_URL")
    if not url:
        _ok("sink", "skipped (no SINK_URL)")
        return
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "hit_mock_sink.py")],
        cwd=str(ROOT),
        env={**os.environ, "SINK_URL": url},
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        _fail("sink", proc.stdout + proc.stderr)
        return
    _ok("sink", url)


def main() -> int:
    os.environ.setdefault("PACK_ROOT", str(ROOT))
    os.environ.setdefault("DRY_RUN", "1")
    os.environ.setdefault("CISO_PUSH", "0")
    os.environ.setdefault("RISKREADY_PUSH", "0")
    os.environ.setdefault("GRC_LIVE_SCAN", "0")
    print("FACET_MATRIX begin", ROOT)
    facet_empty_in_fallback()
    facet_live_scan_ignored()
    facet_loader_race()
    facet_redact()
    facet_push_scripts_safe()
    facet_push_sh_dry_run()
    facet_parse_each_sensor()
    facet_double_loader()
    facet_sink()
    if FAILS:
        print("FACET_MATRIX_FAIL")
        for item in FAILS:
            print(" -", item)
        return 1
    print("FACET_MATRIX_GREEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
