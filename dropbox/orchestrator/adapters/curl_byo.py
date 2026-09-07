"""BYO curl adapter. Named internet-facing URLs only. Never CIDRs. Never spray."""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from typing import Any
from urllib.parse import urlparse

from dropbox.orchestrator.scope import Scope

MAX_DEEPEN_TARGETS = 5
MAX_STDOUT_BYTES = 200_000
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")


def binary_name() -> str:
    if shutil.which("curl"):
        return "curl"
    if shutil.which("curl.exe"):
        return "curl.exe"
    return "curl"


def on_path() -> bool:
    return shutil.which("curl") is not None or shutil.which("curl.exe") is not None


def allowed(scope: Scope) -> bool:
    return scope.tool_allowed("curl")


def live_exec_permitted(scope: Scope) -> bool:
    return bool(scope.integrity.allow_live_exec) and os.environ.get("EVERGREEN_ORCH_LIVE", "0") == "1"


def _looks_like_cidr(target: str) -> bool:
    text = target.strip()
    if "/" not in text:
        return False
    prefix, _, bits = text.partition("/")
    return bits.isdigit() and any(ch.isdigit() or ch == ":" for ch in prefix)


def _safe_external(raw: str) -> bool:
    t = (raw or "").strip()
    if not t or t.startswith("-") or t in {"<url>", "<host>"}:
        return False
    if _looks_like_cidr(t):
        return False
    if "://" in t:
        if not t.lower().startswith(("https://", "http://")):
            return False
        parsed = urlparse(t)
        host = parsed.hostname or ""
        if parsed.username or parsed.password:
            return False
        t = host
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return bool(_HOST_RE.fullmatch(t))


def as_url(target: str) -> str:
    t = (target or "").strip()
    if t.lower().startswith(("https://", "http://")):
        return t
    return f"https://{t}"


def shard_brake(batch: list[str]) -> str | None:
    if not batch:
        return "empty_batch"
    if len(batch) > MAX_DEEPEN_TARGETS:
        return "batch_too_large"
    cidrs = [t for t in batch if _looks_like_cidr(str(t))]
    if cidrs:
        return "cidr_refused"
    if any(not _safe_external(str(t)) for t in batch):
        return "unsafe_target"
    return None


def plan_command(targets: list[str]) -> list[str]:
    url = as_url(targets[0]) if targets and _safe_external(targets[0]) else "<url>"
    return [binary_name(), "-I", "--max-time", "10", "--max-redirs", "0", "--proto", "=http,https", url]


def describe(scope: Scope, batch: list[str]) -> dict[str, Any]:
    missing = not on_path()
    gate = scope.tool_gate("curl")
    cidrs = [t for t in batch if _looks_like_cidr(str(t))]
    tool_ok = allowed(scope)
    brake = shard_brake(batch) if batch else "empty_batch"
    live = (
        live_exec_permitted(scope)
        and tool_ok
        and not missing
        and gate is None
        and brake is None
        and not scope.refuse_live()
    )
    return {
        "adapter": "curl_byo",
        "tool": "curl",
        "allow_tools": tool_ok,
        "target_kind_gate": gate,
        "cidr_refused": cidrs,
        "on_path": not missing,
        "batch_size": len(batch),
        "would_exec": live,
        "shard_brake": brake,
        "command": plan_command(batch) if batch else plan_command(["https://example.invalid"]),
        "brake": "named URLs/hostnames only; never a CIDR; never the whole internet",
        "note": (
            "BYO only; pack does not embed curl scanners. HEAD-only. "
            "Live exec requires allow_live_exec + EVERGREEN_ORCH_LIVE=1. "
            + ("binary missing — plan-only." if missing else "")
            + ("" if tool_ok else " curl not in allow_tools or target kind.")
            + (f" gate={gate}." if gate else "")
            + (" CIDRs refused." if cidrs else "")
            + (f" brake={brake}." if brake else "")
        ),
        "label": "plan-only" if not live else "live-eligible",
    }


def parse_curl_headers(blob: str, url: str) -> list[dict[str, Any]]:
    """Cleartext HTTP from the URL scheme. Missing headers only when a status line was sampled.
    Do not invent CVEs or SMBv1 from a HEAD response. Empty reply (cycle 5) is not a header sample."""
    host = urlparse(url).hostname or url
    rows: list[dict[str, Any]] = []

    def _row(name: str, severity: str) -> dict[str, Any]:
        return {
            "host": host,
            "asset": host,
            "name": name,
            "weakness": name,
            "severity": severity,
        }

    if url.lower().startswith("http://"):
        rows.append(_row("Cleartext HTTP", "medium"))
    low = (blob or "").lower()
    if "http/" not in low:
        return rows
    if "strict-transport-security:" not in low:
        rows.append(_row("Missing HSTS", "medium"))
    if "x-frame-options:" not in low:
        rows.append(_row("Missing X-Frame-Options", "low"))
    if "content-security-policy:" not in low:
        rows.append(_row("Missing CSP", "low"))
    if re.search(r"(?im)^server:", blob or ""):
        rows.append(_row("Server banner disclosure", "low"))
    for match in re.finditer(r"(?im)^set-cookie:\s*(.+)$", blob or ""):
        cookie = (match.group(1) or "").lower()
        if "secure" not in cookie or "httponly" not in cookie:
            rows.append(_row("Insecure session cookie", "medium"))
            break
    if re.search(r"(?im)^access-control-allow-origin:\s*\*\s*$", blob or ""):
        rows.append(_row("Permissive CORS policy", "low"))
    if url.lower().startswith("http://") and re.search(r"(?im)^www-authenticate:\s*basic\b", blob or ""):
        rows.append(_row("HTTP Basic auth without TLS", "high"))
    return rows


def parse_curl_body(blob: str, url: str) -> list[dict[str, Any]]:
    """Directory listing / stub_status / leaked files from a GET body only. HEAD samples are not enough."""
    host = urlparse(url).hostname or url
    low = (blob or "").lower()
    rows: list[dict[str, Any]] = []
    if "index of /" in low or "<title>index of" in low:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "Directory listing enabled",
                "weakness": "Directory listing enabled",
                "severity": "low",
            }
        )
    if "active connections:" in low and "server accepts handled requests" in low:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "Web server status page exposed",
                "weakness": "Web server status page exposed",
                "severity": "low",
            }
        )
    path = (urlparse(url).path or "").lower()
    if "/.git/" in path and ("ref: refs/" in low or "repositoryformatversion" in low):
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "Git metadata exposed",
                "weakness": "Git metadata exposed",
                "severity": "medium",
            }
        )
    if path.rstrip("/") in {"/.env", "/.env.example"} and re.search(r"(?m)^[A-Z][A-Z0-9_]+=", blob or ""):
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "Environment file exposed",
                "weakness": "Environment file exposed",
                "severity": "high",
            }
        )
    backup_path = bool(re.search(r"\.(?:sql|bak|old|backup)(?:$|/)", path) or path.endswith("~"))
    backup_body = bool(
        re.search(
            r"(?is)(?:^|\n)\s*(?:--\s*mysql dump|create table|insert into|pg_dump|<\?php)",
            blob or "",
        )
    )
    if backup_path and backup_body:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "Backup file exposed",
                "weakness": "Backup file exposed",
                "severity": "high",
            }
        )
    phpinfo_path = bool(re.search(r"(?:^|/)(?:phpinfo|info)\.php$", path))
    if phpinfo_path and "phpinfo()" in low and "php version" in low:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "phpinfo page exposed",
                "weakness": "phpinfo page exposed",
                "severity": "medium",
            }
        )
    metrics_path = path.rstrip("/") in {"/metrics", "/prometheus", "/actuator/prometheus"}
    if metrics_path and "# help" in low and "# type" in low:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "Prometheus metrics exposed",
                "weakness": "Prometheus metrics exposed",
                "severity": "low",
            }
        )
    openapi_path = path.rstrip("/") in {
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
        "/api-docs",
    } or "swagger-ui" in path
    openapi_body = '"openapi"' in low or '"swagger"' in low or "swagger ui" in low
    if openapi_path and openapi_body:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "OpenAPI specification exposed",
                "weakness": "OpenAPI specification exposed",
                "severity": "low",
            }
        )
    sourcemap_path = bool(re.search(r"\.(?:js|mjs|css)\.map$", path))
    if sourcemap_path and '"version"' in low and '"sources"' in low:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "JavaScript source map exposed",
                "weakness": "JavaScript source map exposed",
                "severity": "low",
            }
        )
    p = path.rstrip("/")
    actuator_path = p == "/actuator" or p.startswith("/actuator/")
    actuator_body = ('"_links"' in low and ("health" in low or "actuator" in low)) or (
        '"status"' in low and '"up"' in low and ("components" in low or "groups" in low)
    )
    if actuator_path and actuator_body:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "Spring Actuator endpoint exposed",
                "weakness": "Spring Actuator endpoint exposed",
                "severity": "medium",
            }
        )
    graphql_path = p in {"/graphql", "/graphiql", "/api/graphql"}
    if graphql_path and '"__schema"' in low and '"types"' in low:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "GraphQL introspection enabled",
                "weakness": "GraphQL introspection enabled",
                "severity": "medium",
            }
        )
    key_path = bool(
        re.search(r"(?:^|/)(?:\.ssh/)?(?:id_rsa|id_ed25519|id_ecdsa)$", path)
        or re.search(r"(?:^|/)(?:privkey|server)\.(?:pem|key)$", path)
    )
    key_body = "-----begin" in low and "private key-----" in low
    if key_path and key_body:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "Private key file exposed",
                "weakness": "Private key file exposed",
                "severity": "high",
            }
        )
    kube_path = p in {"/kubeconfig", "/.kube/config"}
    kube_body = "kind: config" in low and "apiversion: v1" in low and (
        "clusters:" in low or "users:" in low
    )
    if kube_path and kube_body:
        rows.append(
            {
                "host": host,
                "asset": host,
                "name": "Kubernetes kubeconfig exposed",
                "weakness": "Kubernetes kubeconfig exposed",
                "severity": "high",
            }
        )
    return rows


def parse_curl_tls(stderr: str, url: str) -> list[dict[str, Any]]:
    """Self-signed / expired / verify-fail on https:// only. Do not invent SMBv1."""
    if not (url or "").lower().startswith("https://"):
        return []
    low = (stderr or "").lower()
    host = urlparse(url).hostname or url
    rows: list[dict[str, Any]] = []

    def _row(name: str) -> dict[str, Any]:
        return {
            "host": host,
            "asset": host,
            "name": name,
            "weakness": name,
            "severity": "medium",
        }

    expired = any(
        tok in low
        for tok in (
            "certificate has expired",
            "cert_e_expired",
            "expired certificate",
            "certificate is expired",
            "error 10 at 0 depth lookup",
        )
    )
    mismatch = any(
        tok in low
        for tok in (
            "no alternative certificate subject name matches",
            "does not match target host",
            "cert_e_cn_no_match",
            "cn name does not match",
            "hostname mismatch",
            "does not match the passed value",
        )
    )
    untrusted = any(
        tok in low
        for tok in (
            "self-signed",
            "self signed certificate",
            "unable to get local issuer",
            "certificate verify failed",
            "untrusted_root",
            "sec_e_untrusted_root",
            "not trusted",
        )
    )
    # Generic "ssl certificate problem" is untrusted only when expiry/mismatch was not the sampled reason.
    if expired:
        rows.append(_row("Expired TLS certificate"))
    elif mismatch:
        rows.append(_row("TLS hostname mismatch"))
    elif untrusted or "ssl certificate problem" in low:
        rows.append(_row("Untrusted TLS certificate"))
    return rows


def execute(scope: Scope, batch: list[str], timeout: int | None = None) -> dict[str, Any]:
    """HEAD-only curl on named URLs. Never CIDR. Never shell=True. Never download."""
    desc = describe(scope, batch)
    desc["executed"] = False
    desc["findings"] = []
    if not desc["would_exec"]:
        desc["note"] = (desc.get("note") or "") + " execute skipped (plan-only)."
        return desc
    seconds = int(timeout or 10)
    seconds = max(1, min(seconds, 30))
    findings: list[dict[str, Any]] = []
    ran = False
    for target in [t for t in batch if _safe_external(t)][:MAX_DEEPEN_TARGETS]:
        url = as_url(target)
        cmd = [
            binary_name(),
            "-I",
            "--max-time",
            str(seconds),
            "--max-redirs",
            "0",
            "--proto",
            "=http,https",
            "--",
            url,
        ]
        if cmd[0] not in {"curl", "curl.exe"}:
            desc["shard_brake"] = "unsafe_command"
            return desc
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=seconds + 2,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            desc["shard_brake"] = "timeout"
            desc["label"] = "live-byo-timeout"
            desc["findings"] = findings
            return desc
        except OSError as exc:
            desc["shard_brake"] = "exec_error"
            desc["error"] = type(exc).__name__
            desc["findings"] = findings
            return desc
        ran = True
        blob = (proc.stdout or "")[:MAX_STDOUT_BYTES]
        err = (proc.stderr or "")[:MAX_STDOUT_BYTES]
        findings.extend(parse_curl_tls(err, url))
        findings.extend(parse_curl_headers(blob, url))
        if url.lower().startswith("https://") and "http/" not in blob.lower():
            insecure = cmd[:1] + ["-k"] + cmd[1:]
            try:
                proc2 = subprocess.run(
                    insecure,
                    capture_output=True,
                    text=True,
                    timeout=seconds + 2,
                    check=False,
                    shell=False,
                )
                findings.extend(parse_curl_headers((proc2.stdout or "")[:MAX_STDOUT_BYTES], url))
            except (subprocess.TimeoutExpired, OSError):
                pass
        desc["returncode"] = proc.returncode
        desc["stderr_bytes"] = len(proc.stderr or "")
    uniq: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any]] = set()
    for row in findings:
        key = (row.get("name"), row.get("host"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(row)
    desc["executed"] = ran
    desc["findings"] = uniq
    desc["label"] = "live-byo" if ran else "plan-only"
    return desc
