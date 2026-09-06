from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_push_scripts_do_not_post_risks() -> None:
    forbidden = "POST /api/risks"
    for path in ROOT.glob("push_*"):
        text = path.read_text(encoding="utf-8")
        assert forbidden not in text, path


def test_riskready_wrap_dead_source() -> None:
    tokens = (
        "/api/itsm",
        "/api/auth/login",
        "/api/incidents",
        "/api/evidence",
        "/api/risks",
        "curl",
        "Invoke-WebRequest",
        "Invoke-RestMethod",
    )
    for name in ("push_riskready.ps1", "push_riskready.sh"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "WRAP_DEAD" in text
        code = "\n".join(
            ln for ln in text.splitlines() if not ln.lstrip().startswith("#")
        ).lower()
        for tok in tokens:
            assert tok.lower() not in code, f"{name} still contains {tok}"


def test_riskready_push_1_fail_closed() -> None:
    if shutil.which("powershell") is None:
        pytest.skip("powershell not on PATH")
    env = os.environ.copy()
    env["RISKREADY_PUSH"] = "1"
    env["DRY_RUN"] = "0"
    env["RISKREADY_TOKEN"] = "should-not-matter"
    proc = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "push_riskready.ps1"),
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode == 2
    assert "WRAP_DEAD" in blob
    assert "curl" not in blob.lower()


def test_env_example_disables_live_and_push() -> None:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "CISO_PUSH=0" in text
    assert "RISKREADY_PUSH=0" in text
    assert "GRC_LIVE_SCAN=0" in text
    assert "DRY_RUN=1" in text


def test_collectors_never_enable_live_scan_by_default() -> None:
    from shared.io_util import live_scan_enabled

    os.environ.pop("GRC_LIVE_SCAN", None)
    assert live_scan_enabled() is False


def test_scripts_never_download_scanner_installers() -> None:
    banned = (
        "nmap.org",
        "npcap.com",
        "tenable.com/downloads",
        "github.com/projectdiscovery/nuclei",
        "apt-get install nmap",
        "choco install nmap",
        "winget install nmap",
        "invoke-webrequest",
    )
    roots = list(ROOT.glob("*.ps1")) + list(ROOT.glob("*.sh")) + list((ROOT / "dropbox").rglob("*.py"))
    for path in roots:
        if path.name.startswith("push_riskready"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        for tok in banned:
            if tok == "invoke-webrequest" and path.suffix.lower() == ".ps1" and "push_ciso" in path.name:
                continue
            assert tok not in text, f"{path} looks like a scanner installer download ({tok})"


def test_pack_images_do_not_embed_scanners() -> None:
    banned = (
        "apt-get install nmap",
        "apt install nmap",
        "apk add nmap",
        "image: nmap",
        "image: nessus",
        "image: nuclei",
        "image: openvas",
        "npcap",
    )
    for name in ("Dockerfile", "docker-compose.yml", "docker-compose.facets.yml"):
        text = (ROOT / name).read_text(encoding="utf-8").lower()
        for tok in banned:
            assert tok not in text, f"{name} embeds {tok}"


def test_no_live_scanner_invocations_in_collectors() -> None:
    banned = ("subprocess", "os.system", "os.popen", "nmap -", "nuclei ", "curl http")
    for path in (ROOT / "collectors").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, f"{path} contains {token}"


def test_push_ps1_exists_for_windows() -> None:
    assert (ROOT / "push_ciso.ps1").exists()
    assert (ROOT / "push_riskready.ps1").exists()


def test_ciso_push_assets_evidences_only() -> None:
    """Northstar P0: auto-push assets/evidences only. Findings stay HITL."""
    forbidden_on_curl = ("findings.csv", "vulnerabilities.csv", "risk_scenarios.csv", "applied_controls.csv")
    for name in ("push_ciso.ps1", "push_ciso.sh"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "assets.csv" in text
        assert "evidences.csv" in text
        assert "HITL" in text or "clica" in text.lower()
        for ln in text.splitlines():
            low = ln.lower()
            if "curl" in low or "file=@" in low or "-f " in low:
                for tok in forbidden_on_curl:
                    assert tok not in ln, f"{name} would POST {tok}: {ln}"


def _run_push_ps1(name: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["CISO_PUSH"] = "0"
    env["RISKREADY_PUSH"] = "0"
    env["DRY_RUN"] = "1"
    env["GRC_LIVE_SCAN"] = "0"
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / name),
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_push_ps1_dry_run_exit_0() -> None:
    if shutil.which("powershell") is None:
        pytest.skip("powershell not on PATH (Linux collector image)")
    for script in ("push_ciso.ps1", "push_riskready.ps1"):
        proc = _run_push_ps1(script)
        blob = (proc.stdout or "") + (proc.stderr or "")
        assert proc.returncode == 0, f"{script} dry-run exit {proc.returncode}: {blob}"
        if script == "push_riskready.ps1":
            assert "WRAP_DEAD" in proc.stdout
        else:
            assert "DRY_RUN" in proc.stdout
        assert "POST /api/risks" not in blob
        assert "/api/itsm" not in blob


def test_live_scan_flag_is_ignored(capsys) -> None:
    os.environ["GRC_LIVE_SCAN"] = "1"
    from shared.io_util import refuse_live_scan

    refuse_live_scan()
    captured = capsys.readouterr().out
    assert "ignored" in captured
    os.environ["GRC_LIVE_SCAN"] = "0"


def test_redact_aws_key() -> None:
    from shared.io_util import redact_text

    raw = "id AKIAIOSFODNN7EXAMPLE trailing"
    assert "AKIAIOSFODNN7EXAMPLE" not in redact_text(raw)
    assert "[REDACTED]" in redact_text(raw)


def test_redact_aws_secret_access_key_yaml_jsonl() -> None:
    from shared.io_util import redact_obj, redact_text

    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    yaml_plain = f"aws_secret_access_key: {secret}\n"
    yaml_quoted = f'aws_secret_access_key: "{secret}"\n'
    jsonl = '{"aws_secret_access_key": "' + secret + '"}\n'
    for raw in (yaml_plain, yaml_quoted, jsonl):
        out = redact_text(raw)
        assert secret not in out, raw
        assert "[REDACTED]" in out
    stuffed = redact_obj({"aws_secret_access_key": secret, "region": "us-east-1"})
    assert stuffed["aws_secret_access_key"] == "[REDACTED]"
    assert stuffed["region"] == "us-east-1"
    fixture = ROOT / "in" / "code" / "aws-creds.yaml"
    assert fixture.exists()
    assert secret in fixture.read_text(encoding="utf-8")


def test_changelog_cycle_entries_include_summary_counts() -> None:
    import re

    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(r"^## cycle\s+\d+", text, re.M)
    keys = (
        "assets",
        "findings",
        "evidence",
        "incidents",
        "vulnerabilities",
        "risks_proposed",
        "applied_controls",
        "canonical_rows",
        "sensors_canonical",
    )
    bodies = re.split(r"(?im)^## cycle\s+\d+\s*$", text)[1:]
    assert bodies, "CHANGELOG missing cycle sections"
    latest = bodies[0]
    assert "summary:" in latest.lower()
    for key in keys:
        assert re.search(rf"\b{re.escape(key)}\b", latest, re.I), f"latest cycle missing {key}"


def test_run_lab_ps1_double_run_collectors_loader() -> None:
    text = (ROOT / "run_lab.ps1").read_text(encoding="utf-8")
    lower = text.lower()
    assert "invoke-collectorsandloader" in lower
    assert "pass 1" in lower
    assert "pass 2" in lower
    assert "idempotent" in lower
    assert "summary-pass1.json" in lower
    assert lower.count("invoke-collectorsandloader") >= 2


def test_makefile_documents_run_lab_ps1() -> None:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "run_lab.ps1" in text
    lower = text.lower()
    assert "windows" in lower
    assert "real lab" in lower
    assert "powershell" in lower
    assert "lab_outputs" in lower


def test_readme_sensor_format_matrix() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Sensor formats" in text
    lower = text.lower()
    expected = {
        "in/cloud/": ("prowler", "asff", "csv"),
        "in/nmap/": ("xml", "gnmap"),
        "in/vuln/": ("nuclei", "sarif", "openvas", "nessus"),
        "in/wazuh/": ("osquery", "sca", "alert"),
        "in/identity/": ("bloodhound", "pingcastle", "scuba"),
        "in/easm/": ("amass", "httpx", "subfinder"),
        "in/k8s/": ("kubescape", "kube-bench", "failedcontrols"),
        "in/code/": ("gitleaks", "trivy", "semgrep", "misconfig"),
        "in/saas/": ("m365", "okta", "credentials.provider", "userregistrationdetails"),
    }
    for folder, tokens in expected.items():
        assert folder in lower, f"README matrix missing {folder}"
        for token in tokens:
            assert token in lower, f"README matrix missing {token} for {folder}"
    assert "grc_loader.py" in lower
    assert "out/canonical" in lower
