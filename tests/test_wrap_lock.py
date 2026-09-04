"""LICENSE-LOCK: RiskReady stay-out. Fail if wrap POSTs reappear."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RR = ROOT / "push_riskready.sh"
CISO = ROOT / "push_ciso.sh"

WRAP_PATHS = (
    "/api/auth/login",
    "/itsm/assets",
    "/api/evidence",
    "/api/incidents",
    "/api/risks",
    "${API}/auth/login",
    "${API}/itsm/assets",
    "${API}/evidence",
    "${API}/incidents",
    "${API}/risks",
)


def _code_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def test_riskready_script_has_no_http_client() -> None:
    text = RR.read_text(encoding="utf-8")
    code = "\n".join(_code_lines(text))
    assert "curl" not in text
    assert "wget" not in text
    assert "python" not in code
    assert "-X POST" not in text
    assert "--data-binary" not in text
    assert "Authorization: Bearer" not in text
    for path in WRAP_PATHS:
        assert path not in code, f"wrap path in executable line: {path}"


def test_riskready_push_1_is_review_only(tmp_path: Path) -> None:
    marker = tmp_path / "curl_invoked"
    fake = tmp_path / "curl"
    fake.write_text(
        "#!/bin/sh\necho invoked > \"%s\"\nexit 0\n" % marker.as_posix(),
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    env = os.environ.copy()
    env["PATH"] = str(tmp_path) + os.pathsep + env.get("PATH", "")
    env["RISKREADY_PUSH"] = "1"
    env["DRY_RUN"] = "0"
    env["RISKREADY_EMAIL"] = "wrap@example.invalid"
    env["RISKREADY_PASSWORD"] = "wrap-password"
    env["OUT_DIR"] = str(ROOT / "out")
    proc = subprocess.run(
        ["bash", str(RR)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "LICENSE-LOCK" in proc.stdout
    assert "review-only" in proc.stdout.lower() or "Review-only" in proc.stdout
    assert "risks_proposed.json" in proc.stdout
    assert not marker.exists(), "curl was invoked — wrap POSTs reappeared"


def test_ciso_never_invents_findings_assessment() -> None:
    text = CISO.read_text(encoding="utf-8")
    assert re.search(r"(Never|Do not) invent FindingsAssessment UUIDs", text)
    posts = re.findall(r"curl[^\n]+", text)
    for line in posts:
        assert "FindingsAssessment" not in line
    assert not re.search(r"uuidgen|uuid4|/findings-assessments", text, re.I)
    assert "${API}/risks" not in text
    assert not re.search(r"curl[^\n]*/api/risks", text)


def test_ciso_rest_limited_to_assets_and_evidences() -> None:
    text = CISO.read_text(encoding="utf-8")
    posts = [ln for ln in text.splitlines() if re.search(r"^\s*curl\s", ln)]
    assert posts, "expected optional CISO assets/evidences curl lines"
    allowed = ("/api/assets/", "/api/evidences/", "${API}/assets/", "${API}/evidences/")
    for line in posts:
        assert any(a in line for a in allowed), line
        assert "/api/risks" not in line
        assert "FindingsAssessment" not in line


def test_import_rr_and_security_never_allow_riskready_write() -> None:
    for rel in ("docs/IMPORT_RR.md", "SECURITY.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "Allowed live POSTs" not in text
        assert "RiskReady assets/evidence/incidents" not in text
        assert re.search(r"review-only|stay-out|never wraps|wrap is dead", text, re.I)


def test_farm_sop_never_points_at_riskready_write() -> None:
    write_needles = (
        "Allowed live POSTs",
        "/api/auth/login",
        "/itsm/assets",
        "${API}/auth/login",
        "${API}/itsm/assets",
        "${API}/evidence",
        "${API}/incidents",
        "${API}/risks",
    )
    for rel in (
        "farm/OPERATOR.md",
        "farm/QUICKSTART.md",
        "farm/README.md",
        "farm/INTEGRITY.md",
        "farm/SLOTS.md",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        for needle in write_needles:
            assert needle not in text, f"{rel} points at RiskReady write: {needle}"
        for line in text.splitlines():
            if "/api/risks" not in line:
                continue
            low = line.lower()
            assert any(
                token in low
                for token in ("do not", "never", "- post", "review-only", "stay-out")
            ), f"{rel} RiskReady write instruction: {line}"
