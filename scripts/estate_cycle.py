"""One isolated Docker estate cycle. Not a client LAN. Not 192.168.10.0/24."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

PACK = Path(__file__).resolve().parents[1]
ROOT = PACK.parent
CYCLES = ROOT / "product-lab" / "estate-cycles"
COUNTER = CYCLES / "COUNTER.json"
LEARNING = CYCLES / "LEARNING.md"
LOCK = CYCLES / ".run.lock"
PT = timezone(timedelta(hours=-7))
FORBIDDEN_CIDRS = ("192.168.10.0/24", "0.0.0.0/0", "8.8.8.8/32")
MAX_CYCLES = 10

RECIPES = [
    {"id": "nginx-whoami", "web": "nginx:alpine", "api": "traefik/whoami", "learn": "default nginx HEAD: Server token, no XFO/CSP/HSTS"},
    {"id": "httpd-whoami", "web": "httpd:2.4-alpine", "api": "traefik/whoami", "learn": "Apache httpd Server banner vs nginx"},
    {"id": "double-whoami", "web": "traefik/whoami", "api": "traefik/whoami", "learn": "two whoami banners, same cleartext finding class"},
    {"id": "nginx-whoami-b", "web": "nginx:alpine", "api": "traefik/whoami", "learn": "repeat nginx to see header stability"},
    {"id": "py-http-whoami", "web": "python:3.12-alpine", "web_cmd": "python -m http.server 80", "api": "traefik/whoami", "learn": "stdlib http.server Server: SimpleHTTP"},
    {"id": "httpd-httpd", "web": "httpd:2.4-alpine", "api": "httpd:2.4-alpine", "learn": "two Apache listeners, same stack"},
    {"id": "nginx-httpd", "web": "nginx:alpine", "api": "httpd:2.4-alpine", "learn": "mixed nginx+httpd cleartext pair"},
    {"id": "whoami-nginx", "web": "traefik/whoami", "api": "nginx:alpine", "learn": "whoami as 'web' role, nginx as api"},
    {"id": "nginx-whoami-c", "web": "nginx:alpine", "api": "traefik/whoami", "learn": "third nginx sample; compare Date/Server"},
    {"id": "httpd-whoami-b", "web": "httpd:2.4-alpine", "api": "traefik/whoami", "learn": "second Apache sample; Server token persistence"},
]


def _now() -> datetime:
    return datetime.now(PT)


def _run(cmd: list[str], cwd: Path | None = None, env: dict | None = None, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd or PACK), env=env, text=True, capture_output=True, timeout=timeout)


def _load_counter() -> dict:
    if COUNTER.is_file():
        return json.loads(COUNTER.read_text(encoding="utf-8"))
    return {"completed": 0, "max": MAX_CYCLES, "scheduler_id": None}


def _save_counter(data: dict) -> None:
    CYCLES.mkdir(parents=True, exist_ok=True)
    COUNTER.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _compose_yaml(n: int, recipe: dict, subnet: str, web_ip: str, api_ip: str, web_port: int, api_port: int) -> str:
    web_cmd = ""
    if recipe.get("web_cmd"):
        web_cmd = f'\n    command: ["sh", "-c", "{recipe["web_cmd"]}"]'
    return f"""# Cycle {n} unique estate. Isolated compose lab. Office LAN out of scope.
name: grc-estate-c{n:02d}
services:
  estate-web:
    image: {recipe["web"]}
    ports:
      - "127.0.0.1:{web_port}:80"{web_cmd}
    networks:
      grc-estate-c{n:02d}:
        ipv4_address: {web_ip}
  estate-api:
    image: {recipe["api"]}
    ports:
      - "127.0.0.1:{api_port}:80"
    networks:
      grc-estate-c{n:02d}:
        ipv4_address: {api_ip}
  estate-nmap:
    image: instrumentisto/nmap:latest
    profiles: ["scan"]
    networks:
      - grc-estate-c{n:02d}
    entrypoint: ["nmap"]
    command: ["-sn", "-n", "--max-retries", "1", "{subnet}"]
networks:
  grc-estate-c{n:02d}:
    name: grc-estate-c{n:02d}
    ipam:
      config:
        - subnet: {subnet}
"""


def _scope_yaml(n: int, client: str, subnet: str, web_ip: str, api_ip: str, web_port: int, api_port: int) -> str:
    now = _now()
    start = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S-07:00")
    end = (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S-07:00")
    return f"""# Cycle {n} estate SCOPE. Lab only. Not Litware. Office LAN out of scope.
client_legal_name: "{client}"
named_contact: "Reid Schram"
consent_attested: true
window_start: "{start}"
window_end: "{end}"
internal:
  cidrs:
    - "{subnet}"
  hosts:
    - "{web_ip}"
    - "{api_ip}"
  endpoints: []
external:
  hostnames:
    - "127.0.0.1"
  urls:
    - "http://127.0.0.1:{web_port}/"
    - "http://127.0.0.1:{api_port}/"
allow_tools:
  - curl
  - nmap
profiles:
  - both
batch:
  discover_shard_size: 32
  deepen_batch_size: 3
  max_concurrent_discover: 2
  max_concurrent_deepen: 1
integrity:
  timeouts_seconds: 600
  max_runtime_seconds: 14400
  refuse_if_unsigned: true
  refuse_if_empty_targets: true
  allow_live_exec: true
"""


def _acquire_lock() -> bool:
    try:
        fd = os.open(str(LOCK), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, f"{os.getpid()}\n".encode("utf-8"))
        os.close(fd)
        return True
    except FileExistsError:
        try:
            if time.time() - LOCK.stat().st_mtime > 900:
                LOCK.unlink(missing_ok=True)
                return _acquire_lock()
        except OSError:
            return False
        return False


def _release_lock() -> None:
    try:
        LOCK.unlink(missing_ok=True)
    except OSError:
        pass


def _curl_head(url: str, dest: Path) -> str:
    """HEAD with short retries. Cycle 5: python http.server can empty-reply on first HEAD."""
    blob = ""
    for _ in range(4):
        proc = _run(["curl.exe", "-sS", "-I", "--max-time", "10", "--max-redirs", "0", url], timeout=20)
        blob = (proc.stdout or "") + (proc.stderr or "")
        dest.write_text(blob, encoding="utf-8")
        if "HTTP/" in blob:
            return blob[:4000]
        time.sleep(2)
    get_path = dest.with_name(dest.stem + "-get.txt")
    proc = _run(
        ["curl.exe", "-sS", "-D", "-", "-o", "NUL", "--max-time", "10", "--max-redirs", "0", url],
        timeout=20,
    )
    get_blob = (proc.stdout or "") + (proc.stderr or "")
    get_path.write_text(get_blob, encoding="utf-8")
    return (blob + "\n--- GET fallback ---\n" + get_blob)[:4000]


def _headers_of_interest(blob: str) -> dict[str, bool]:
    low = blob.lower()
    return {
        "x_frame_options": "x-frame-options:" in low,
        "csp": "content-security-policy:" in low,
        "hsts": "strict-transport-security:" in low,
        "server_token": "server:" in low,
        "cleartext_http11": "http/1.1" in low,
    }


def run_cycle(n: int) -> dict:
    recipe = RECIPES[n - 1]
    subnet = f"172.28.{90 + n}.0/24"
    web_ip = f"172.28.{90 + n}.10"
    api_ip = f"172.28.{90 + n}.11"
    web_port = 18200 + n * 2
    api_port = web_port + 1
    client = f"Evergreen Docker Estate Cycle {n:02d} LLC"
    stamp = _now().strftime("%Y%m%d-%H%M%S")
    out = CYCLES / f"{n:02d}-{recipe['id']}-{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    compose_path = out / "docker-compose.yml"
    compose_path.write_text(
        _compose_yaml(n, recipe, subnet, web_ip, api_ip, web_port, api_port), encoding="utf-8"
    )
    project = f"grc-estate-c{n:02d}"
    env = os.environ.copy()
    env["DRY_RUN"] = "1"
    env["CISO_PUSH"] = "0"
    env["RISKREADY_PUSH"] = "0"
    env["GRC_LIVE_SCAN"] = "0"
    env.pop("EVERGREEN_ORCH_LIVE", None)
    _run(["docker", "compose", "-p", project, "-f", str(compose_path), "down", "-v"], timeout=90)

    up = _run(
        ["docker", "compose", "-p", project, "-f", str(compose_path), "up", "-d", "--pull", "missing"],
        timeout=240,
    )
    (out / "compose-up.txt").write_text(up.stdout + "\n" + up.stderr, encoding="utf-8")
    if up.returncode != 0:
        return {"ok": False, "cycle": n, "error": "compose_up", "stderr": up.stderr[-2000:]}

    net = _run(["docker", "network", "inspect", project], timeout=30)
    (out / "network.json").write_text(net.stdout or net.stderr, encoding="utf-8")
    net_blob = net.stdout or ""
    if any(cid in net_blob for cid in FORBIDDEN_CIDRS) or "192.168.10.0/24" in net_blob:
        _run(["docker", "compose", "-p", project, "-f", str(compose_path), "down", "-v"], timeout=60)
        return {"ok": False, "cycle": n, "error": "forbidden_cidr"}

    web_h = _curl_head(f"http://127.0.0.1:{web_port}/", out / "curl-web.txt")
    api_h = _curl_head(f"http://127.0.0.1:{api_port}/", out / "curl-api.txt")
    nmap = _run(
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            str(compose_path),
            "--profile",
            "scan",
            "run",
            "--rm",
            "estate-nmap",
        ],
        timeout=120,
    )
    (out / "nmap-sn.txt").write_text((nmap.stdout or "") + (nmap.stderr or ""), encoding="utf-8")

    scope_text = _scope_yaml(n, client, subnet, web_ip, api_ip, web_port, api_port)
    if any(cid in scope_text.replace("Office LAN out of scope", "") for cid in FORBIDDEN_CIDRS):
        raise SystemExit("forbidden CIDR in SCOPE")
    if "172.28." not in subnet or subnet.startswith("192.168.10"):
        raise SystemExit("estate subnet must be the isolated 172.28.x lab net")
    scope_path = PACK / "dropbox" / f"SCOPE.docker-estate-c{n:02d}.yaml"
    scope_path.write_text(scope_text, encoding="utf-8")
    (out / "SCOPE.yaml").write_text(scope_text, encoding="utf-8")

    env_live = env.copy()
    env_live["EVERGREEN_ORCH_LIVE"] = "1"
    env_live["PYTHONPATH"] = str(PACK)
    plan = _run(
        [sys.executable, "-m", "dropbox.orchestrator", "plan", "--scope", str(scope_path)],
        env=env_live,
        timeout=60,
    )
    (out / "plan.json").write_text(plan.stdout or plan.stderr, encoding="utf-8")
    runp = _run(
        [sys.executable, "-m", "dropbox.orchestrator", "run", "--scope", str(scope_path), "--stage", "all"],
        env=env_live,
        timeout=120,
    )
    (out / "run.json").write_text(runp.stdout or runp.stderr, encoding="utf-8")
    deepen_label = None
    findings = []
    facing = None
    blocked = None
    try:
        payload = json.loads(runp.stdout or "{}")
        deepen = ((payload.get("deepen") or {}).get("deepen") or {})
        deepen_label = deepen.get("label")
        findings = deepen.get("findings") or []
        ge = payload.get("grc_export") or {}
        facing = ge.get("client_facing_ready")
        blocked = (ge.get("hitl") or {}).get("blocked_by")
    except json.JSONDecodeError:
        payload = {}

    sink = _run(["curl.exe", "-sS", "http://127.0.0.1:18080/health"], timeout=10)
    (out / "sink-health.txt").write_text(sink.stdout or sink.stderr, encoding="utf-8")

    _run(["docker", "compose", "-p", project, "-f", str(compose_path), "down", "-v"], timeout=90)

    learning = {
        "cycle": n,
        "recipe": recipe["id"],
        "hypothesis": recipe["learn"],
        "subnet": subnet,
        "web_headers": _headers_of_interest(web_h),
        "api_headers": _headers_of_interest(api_h),
        "nmap_return": nmap.returncode,
        "nmap_hosts_up_line": next((ln for ln in (nmap.stdout or "").splitlines() if "Nmap done" in ln), ""),
        "deepen_label": deepen_label,
        "deepen_finding_names": sorted({str(f.get("name")) for f in findings if isinstance(f, dict)}),
        "smb_v1_dumped": any("smb" in str(f).lower() for f in findings),
        "client_facing_ready": facing,
        "blocked_by": blocked,
        "sink_health": (sink.stdout or "").strip(),
        "plan_exit": plan.returncode,
        "run_exit": runp.returncode,
    }
    (out / "LEARNING.json").write_text(json.dumps(learning, indent=2), encoding="utf-8")
    CYCLES.mkdir(parents=True, exist_ok=True)
    with LEARNING.open("a", encoding="utf-8") as handle:
        handle.write(
            f"\n## cycle {n:02d} {recipe['id']} {_now().strftime('%Y-%m-%dT%H:%M:%S-07:00')}\n"
            f"- {recipe['learn']}\n"
            f"- web headers: {learning['web_headers']}\n"
            f"- deepen_label={deepen_label} findings={learning['deepen_finding_names']} smb_dumped={learning['smb_v1_dumped']}\n"
            f"- nmap: {learning['nmap_hosts_up_line'] or 'no-done-line rc=' + str(nmap.returncode)}\n"
            f"- facing={facing} blocked_by={blocked}\n"
        )
    return {"ok": True, "cycle": n, "out": str(out), "learning": learning}


def main() -> int:
    CYCLES.mkdir(parents=True, exist_ok=True)
    if not LEARNING.is_file():
        LEARNING.write_text("# Estate cycle learning\n\nIsolated Docker only. Not a client LAN.\n", encoding="utf-8")
    data = _load_counter()
    done = int(data.get("completed") or 0)
    if done >= MAX_CYCLES:
        print(json.dumps({"ok": True, "done_all": True, "completed": done}))
        return 0
    if not _acquire_lock():
        print(json.dumps({"ok": False, "error": "lock_held", "completed": done}))
        return 3
    try:
        n = done + 1
        result = run_cycle(n)
        if result.get("ok"):
            data["completed"] = n
            data["last"] = result.get("learning")
            _save_counter(data)
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("ok") else 2
    finally:
        _release_lock()


if __name__ == "__main__":
    raise SystemExit(main())
