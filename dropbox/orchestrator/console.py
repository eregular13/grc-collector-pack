"""Localhost-only operator console. Not an attack socket. 127.0.0.1 only."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PACK = Path(__file__).resolve().parents[2]
OUT = PACK / "dropbox" / "out"
HOST = "127.0.0.1"
PORT = 18765


def _load(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _infer_stage(files: dict[str, bool]) -> str:
    if files.get("grc_export"):
        return "grc_export"
    if files.get("poam"):
        return "ingest"
    if files.get("deepen"):
        return "deepen"
    if files.get("discover"):
        return "discover"
    if files.get("plan"):
        return "plan"
    return "idle"


def _esc(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def html_page() -> str:
    p = status_payload()
    stop = p.get("integrity_stop") or "none"
    waves = p.get("discover_waves") or []
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Evergreen orchestrator brakes</title>
<style>
body {{ font-family: sans-serif; margin: 1.5rem; max-width: 52rem; color: #111; background: #fafafa; }}
h1 {{ font-size: 1.2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }}
.note {{ color: #333; }}
</style>
</head>
<body>
<h1>Orchestrator brakes</h1>
<p class="note">{_esc(p.get("note"))}</p>
<table>
<tr><th>bind</th><td>{_esc(p.get("bind"))}</td></tr>
<tr><th>stage</th><td>{_esc(p.get("stage"))}</td></tr>
<tr><th>deepen batch</th><td>{_esc(p.get("deepen_batch_size"))}</td></tr>
<tr><th>max concurrent discover</th><td>{_esc(p.get("max_concurrent_discover"))}</td></tr>
<tr><th>max concurrent deepen</th><td>{_esc(p.get("max_concurrent_deepen"))}</td></tr>
<tr><th>integrity stop</th><td>{_esc(stop)}</td></tr>
<tr><th>workers alive</th><td>{_esc(p.get("workers_alive"))}</td></tr>
<tr><th>discover waves</th><td>{_esc(len(waves) if isinstance(waves, list) else waves)}</td></tr>
<tr><th>HITL required</th><td>{_esc(p.get("hitl_required"))}</td></tr>
<tr><th>discover label</th><td>{_esc(p.get("discover_label"))}</td></tr>
<tr><th>deepen label</th><td>{_esc(p.get("deepen_label"))}</td></tr>
<tr><th>ingest label</th><td>{_esc(p.get("ingest_label"))}</td></tr>
</table>
<p>JSON: <a href="/status">/status</a>. Not an exploit dashboard. Localhost only.</p>
</body>
</html>
"""


def status_payload() -> dict[str, Any]:
    plan = _load(OUT / "plan.json")
    discover = _load(OUT / "discover.json")
    deepen = _load(OUT / "deepen.json")
    destroy_discover = _load(OUT / "destroy_discover.json")
    destroy_deepen = _load(OUT / "destroy_deepen.json")
    poam_manifest = _load(OUT / "poam_MANIFEST.json")
    ingest_preview = _load(OUT / "normalized" / "findings.json")
    workers_dir = OUT / "workers"
    alive = list(workers_dir.glob("*.alive")) if workers_dir.is_dir() else []
    files = {
        "plan": (OUT / "plan.json").is_file(),
        "discover": (OUT / "discover.json").is_file(),
        "deepen": (OUT / "deepen.json").is_file(),
        "destroy_discover": (OUT / "destroy_discover.json").is_file(),
        "destroy_deepen": (OUT / "destroy_deepen.json").is_file(),
        "poam": (OUT / "poam.csv").is_file(),
        "simplerisk": (OUT / "simplerisk_import.csv").is_file(),
        "quote": (OUT / "quote.csv").is_file(),
        "grc_export": (OUT / "grc_export.json").is_file(),
    }
    brakes = (plan or {}).get("brakes") if isinstance(plan, dict) else {}
    stop = (brakes or {}).get("refuse_live")
    if isinstance(deepen, dict) and deepen.get("refused") is True:
        stop = deepen.get("reason") or stop
    elif isinstance(discover, dict) and discover.get("brake"):
        stop = discover.get("brake") or stop
    payload: dict[str, Any] = {
        "ok": True,
        "bind": f"{HOST}:{PORT}",
        "stage": _infer_stage(files),
        "deepen_batch_size": (brakes or {}).get("deepen_batch_size"),
        "max_concurrent_discover": (brakes or {}).get("max_concurrent_discover"),
        "max_concurrent_deepen": (brakes or {}).get("max_concurrent_deepen"),
        "integrity_stop": stop,
        "tool_gates": (plan or {}).get("tool_gates") if isinstance(plan, dict) else None,
        "profile_isolation": (plan or {}).get("profile_isolation") if isinstance(plan, dict) else None,
        "workers_alive": len(alive),
        "discover_waves": (discover or {}).get("waves") if isinstance(discover, dict) else None,
        "deepen_waves": (deepen or {}).get("waves") if isinstance(deepen, dict) else None,
        "destroyed": {
            "discover": (destroy_discover or {}).get("destroyed") if isinstance(destroy_discover, dict) else None,
            "deepen": (destroy_deepen or {}).get("destroyed") if isinstance(destroy_deepen, dict) else None,
        },
        "poam_manifest": poam_manifest,
        "hitl_required": True,
        "discover_label": (discover or {}).get("label") if isinstance(discover, dict) else None,
        "deepen_label": (deepen or {}).get("label") if isinstance(deepen, dict) else None,
        "ingest_label": (ingest_preview or {}).get("label") if isinstance(ingest_preview, dict) else None,
        "files": files,
        "note": "brakes console — not an exploit dashboard",
    }
    if isinstance(plan, dict):
        payload["plan"] = plan
    return payload


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.client_address[0] not in {"127.0.0.1", "::1"}:
            self._send(403, b'{"error":"localhost only"}')
            return
        if self.path in {"/health", "/status"}:
            self._send(200, json.dumps(status_payload(), indent=2).encode("utf-8"))
            return
        if self.path in {"/", "/ui"}:
            self._send(200, html_page().encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(404, b'{"error":"not found"}')

    def do_POST(self) -> None:  # noqa: N802
        self._send(405, b'{"error":"method not allowed","note":"brakes console is GET-only"}')

    def do_PUT(self) -> None:  # noqa: N802
        self.do_POST()

    def do_DELETE(self) -> None:  # noqa: N802
        self.do_POST()

    def do_PATCH(self) -> None:  # noqa: N802
        self.do_POST()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.do_POST()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def serve() -> int:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"operator console http://{HOST}:{PORT}/ (localhost only)", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
