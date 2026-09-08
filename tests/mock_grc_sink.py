"""Local GRC HTTP sink for Docker extra-lab. Does not upload proposed risks."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from shared.io_util import get_out, write_json

LOG: list[dict] = []
ALLOWED_PREFIXES = (
    "/api/itsm/assets",
    "/api/incidents",
    "/api/evidence",
    "/api/importer",
)


class Sink(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _is_risks(self, path: str) -> bool:
        lowered = path.lower().rstrip("/")
        return lowered.endswith("/risks") or lowered.endswith("/api/risks")

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in {"/health", "/"}:
            self._send(200, {"ok": True, "received": len(LOG)})
            return
        if self._is_risks(path):
            self._send(403, {"error": "proposed-risks upload is forbidden"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self._is_risks(path):
            self._send(403, {"error": "proposed-risks upload is forbidden"})
            return
        LOG.append({"method": "POST", "path": path, "bytes": len(body)})
        try:
            write_json(get_out() / "evidence" / "sink-log.json", LOG)
        except OSError:
            pass
        if any(path.startswith(prefix) for prefix in ALLOWED_PREFIXES):
            self._send(200, {"accepted": True, "path": path})
            return
        self._send(404, {"error": "not found"})

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def main() -> None:
    port = int(__import__("os").environ.get("SINK_PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Sink)
    print(f"mock_grc_sink listening on {port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
