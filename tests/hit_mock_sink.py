from __future__ import annotations

import os
import time
import urllib.error
import urllib.request

BASE = os.environ.get("SINK_URL", "http://127.0.0.1:18080").rstrip("/")


def post(path: str, expect: int) -> None:
    req = urllib.request.Request(
        BASE + path,
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            code = resp.status
            body = resp.read()[:120]
    except urllib.error.HTTPError as exc:
        code = exc.code
        body = exc.read()[:120]
    print(path, code, body)
    if code != expect:
        raise SystemExit(f"expected {expect} for {path} got {code}")


def main() -> None:
    last: Exception | None = None
    for _ in range(25):
        try:
            with urllib.request.urlopen(BASE + "/health", timeout=2) as resp:
                print("health", resp.status, resp.read())
            last = None
            break
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.4)
    if last is not None:
        raise SystemExit(f"sink health failed: {last}")
    for path in (
        "/api/itsm/assets",
        "/api/incidents",
        "/api/evidence",
        "/api/importer/",
    ):
        post(path, 200)
    post("/api/risks", 403)
    print("SINK_OK")


if __name__ == "__main__":
    main()
