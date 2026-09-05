#!/usr/bin/env python3
"""Local operator console for grc-collector-pack.

Binds 127.0.0.1 only. Reads out/. Can refresh collectors on this host.
Never proxies or POSTs /api/risks. Not an eleventh Compose service.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import traceback
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}

ROOT = Path(__file__).resolve().parents[1]
STATIC = Path(__file__).resolve().parent / "static"
COLLECTORS = [
    "cloud_prowler.py",
    "inventory_nmap.py",
    "vuln_scan.py",
    "host_wazuh.py",
    "identity_ad.py",
    "easm.py",
    "k8s_kubescape.py",
    "code_secrets.py",
    "saas_idp.py",
    "grc_loader.py",
]


def out_dir() -> Path:
    raw = os.environ.get("OUT_DIR")
    return Path(raw) if raw else ROOT / "out"


def bind_host() -> str:
    return os.environ.get("GRC_PRODUCT_HOST", "127.0.0.1")


def bind_port() -> int:
    return int(os.environ.get("GRC_PRODUCT_PORT", "18765"))


def assert_loopback_host(host: str) -> str:
    raw = (host or "").strip()
    normalized = raw.lower().strip("[]")
    if normalized not in ALLOWED_HOSTS:
        sys.stderr.write("GRC_PRODUCT_HOST must be 127.0.0.1, localhost, or ::1\n")
        raise SystemExit(2)
    return raw


def _read_csv(path: Path, delim: str = ",") -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh, delimiter=delim))


def _read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def estate() -> dict:
    out = out_dir()
    summary = _read_json(out / "summary.json") or {}
    findings = _read_csv(out / "ciso-assistant" / "findings.csv")
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in findings:
        key = str(row.get("severity") or "").lower()
        if key in sev:
            sev[key] += 1
    return {
        "product": "GRC Collector Pack",
        "version": "0.3.0",
        "repo": str(ROOT),
        "out_dir": str(out),
        "bind": f"{bind_host()}:{bind_port()}",
        "ready": bool(summary),
        "demo": bool(summary.get("demo")),
        "summary": summary,
        "severity": sev,
        "safety": {
            "dry_run": os.environ.get("DRY_RUN", "1"),
            "ciso_push": os.environ.get("CISO_PUSH", "0"),
            "riskready_push": os.environ.get("RISKREADY_PUSH", "0"),
            "riskready_wrap": False,
            "riskready_review_only": True,
            "live_scan": os.environ.get("GRC_LIVE_SCAN", "0"),
            "posts_api_risks": False,
            "bind": "127.0.0.1",
        },
    }


def payload(kind: str):
    out = out_dir()
    mapping = {
        "assets": out / "ciso-assistant" / "assets.csv",
        "findings": out / "ciso-assistant" / "findings.csv",
        "vulnerabilities": out / "ciso-assistant" / "vulnerabilities.csv",
        "evidences": out / "ciso-assistant" / "evidences.csv",
        "controls": out / "ciso-assistant" / "applied_controls.csv",
        "scenarios": out / "ciso-assistant" / "risk_scenarios.csv",
        "poam": out / "poam" / "poam.csv",
        "incidents": out / "riskready" / "incidents.json",
        "proposed": out / "riskready" / "risks_proposed.json",
        "rr_assets": out / "riskready" / "assets.json",
        "rr_evidence": out / "riskready" / "evidence.json",
    }
    path = mapping.get(kind)
    if path is None:
        return None
    if path.suffix == ".json":
        data = _read_json(path)
        return data if data is not None else []
    delim = ";" if path.name == "risk_scenarios.csv" else ","
    return _read_csv(path, delim)


def build_drop_zip() -> bytes:
    out = out_dir()
    buf = io.BytesIO()
    files = [
        out / "summary.json",
        out / "evidence" / "lab-report.md",
        out / "ocsf" / "compliance_findings.json",
    ]
    files.extend(sorted((out / "ciso-assistant").glob("*.csv")))
    files.extend(sorted((out / "poam").glob("*")))
    files.extend(sorted((out / "riskready").glob("*.json")))
    drop = ROOT / "product-lab" / "drop"
    if drop.is_dir():
        files.extend(sorted((drop / "ciso").glob("*.csv")))
        files.extend(sorted((drop / "riskready").glob("*.json")))
    readme = (
        "GRC Collector Pack drop\n"
        "Pentera finds it; Evergreen maps it.\n"
        "Import CISO CSVs with clica or the CISO Assistant UI.\n"
        "POA&M: poam/poam.csv — owner and due are blank for a human.\n"
        "RiskReady JSON is review-only (LICENSE-LOCK stay-out). Do not wrap or POST.\n"
        "risks_proposed.json is for a human. Do not POST /api/risks.\n"
    )
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("IMPORT.md", readme)
        for path in files:
            if path.is_file():
                try:
                    arc = path.relative_to(out).as_posix()
                except ValueError:
                    arc = path.relative_to(ROOT).as_posix()
                zf.write(path, arcname=arc)
    return buf.getvalue()


def refresh_estate() -> dict:
    os.environ["PYTHONPATH"] = str(ROOT)
    os.environ.setdefault("OUT_DIR", str(ROOT / "out"))
    os.environ["DRY_RUN"] = "1"
    os.environ["CISO_PUSH"] = "0"
    os.environ["RISKREADY_PUSH"] = "0"
    os.environ["GRC_LIVE_SCAN"] = "0"
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    ran = []
    for name in COLLECTORS:
        mod = f"collectors.{name.replace('.py', '')}"
        if mod in sys.modules:
            del sys.modules[mod]
        module = __import__(mod, fromlist=["main"])
        module.main()
        ran.append(name)
    return {"ok": True, "ran": ran, "summary": estate()["summary"]}


class Handler(BaseHTTPRequestHandler):
    server_version = "GRCCollectorPack/1.0"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, code: int, data) -> None:
        raw = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _bytes(self, code: int, body: bytes, content_type: str, filename: str | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def _forbid_risks(self, path: str) -> bool:
        if "/api/risks" in path:
            self._json(403, {"error": "POST /api/risks is forbidden", "posted": False})
            return True
        return False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if self._forbid_risks(path):
            return
        if path in {"/", "/index.html"}:
            html = (STATIC / "index.html").read_bytes()
            self._bytes(200, html, "text/html; charset=utf-8")
            return
        if path == "/static/app.css":
            self._bytes(200, (STATIC / "app.css").read_bytes(), "text/css; charset=utf-8")
            return
        if path == "/static/app.js":
            self._bytes(200, (STATIC / "app.js").read_bytes(), "application/javascript; charset=utf-8")
            return
        if path == "/health":
            self._json(200, {"ok": True, "ready": estate()["ready"]})
            return
        if path == "/api/summary":
            data = estate()
            self._json(200 if data["ready"] else 503, data)
            return
        table = {
            "/api/assets": "assets",
            "/api/findings": "findings",
            "/api/vulnerabilities": "vulnerabilities",
            "/api/evidences": "evidences",
            "/api/controls": "controls",
            "/api/scenarios": "scenarios",
            "/api/poam": "poam",
            "/api/incidents": "incidents",
            "/api/proposed": "proposed",
        }
        if path in table:
            self._json(200, payload(table[path]))
            return
        if path == "/export.zip":
            blob = build_drop_zip()
            if len(blob) < 64:
                self._json(503, {"error": "no estate yet — refresh first"})
                return
            self._bytes(200, blob, "application/zip", "grc-collector-pack-drop.zip")
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if self._forbid_risks(path):
            return
        if path != "/api/refresh":
            self._json(404, {"error": "not found"})
            return
        peer = (self.client_address[0] if self.client_address else "").strip("[]")
        if peer not in ALLOWED_HOSTS:
            self._json(403, {"error": "refresh is loopback-only"})
            return
        try:
            result = refresh_estate()
            self._json(200, result)
        except Exception:
            traceback.print_exc()
            self._json(500, {"ok": False, "error": "refresh failed"})


def make_server(host: str | None = None, port: int | None = None) -> ThreadingHTTPServer:
    bound = assert_loopback_host(host if host is not None else bind_host())
    httpd = ThreadingHTTPServer((bound, port if port is not None else bind_port()), Handler)
    httpd.allow_reuse_address = True
    return httpd


def main() -> None:
    os.environ.setdefault("DRY_RUN", "1")
    os.environ.setdefault("CISO_PUSH", "0")
    os.environ.setdefault("RISKREADY_PUSH", "0")
    os.environ.setdefault("GRC_LIVE_SCAN", "0")
    os.environ.setdefault("PYTHONPATH", str(ROOT))
    os.environ.setdefault("OUT_DIR", str(ROOT / "out"))
    host, port = assert_loopback_host(bind_host()), bind_port()
    httpd = make_server(host, port)
    print(f"GRC Collector Pack  http://{host}:{port}/", flush=True)
    print("Local operator console. Never POSTs /api/risks.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
