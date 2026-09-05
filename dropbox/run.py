"""CLI: gate → internal / external / demo ingest → pack in/."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from dropbox.scope import ROOT, GateError, load_scope
from dropbox import runners

SENSORS = ("cloud", "nmap", "vuln", "wazuh", "identity", "easm", "k8s", "code", "saas")


def _print_gate(scope) -> None:
    print(f"SCOPE gate OK  client={scope.client_name!r}")
    print(f"  consent {scope.consent_path} sha256={scope.consent_sha256[:12]}…")
    print(f"  window {scope.window_start} .. {scope.window_end}")
    print(f"  internal cidrs={len(scope.internal_cidrs)} hosts={scope.internal_hosts}")
    print(f"  external hosts={scope.external_hosts} domains={scope.external_domains} ips={scope.external_ips}")
    print(f"  allow_tools={scope.allow_tools}")
    print(
        f"  orchestrator quiet→loud  discover={scope.stage_discover} "
        f"deepen={scope.stage_deepen} max_workers={scope.max_workers} "
        f"batch={scope.deepen_batch} host_timeout_sec={scope.host_timeout_sec}"
    )


def cmd_gate(args: argparse.Namespace) -> int:
    scope = load_scope(Path(args.scope) if args.scope else None)
    _print_gate(scope)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if not os.environ.get("IN_DIR") and os.environ.get("DROPBOX_WORK_IN"):
        os.environ["IN_DIR"] = os.environ["DROPBOX_WORK_IN"]
    scope = load_scope(Path(args.scope) if args.scope else None)
    _print_gate(scope)
    demo = not args.live
    os.environ["DROPBOX_DEMO"] = "0" if args.live else "1"
    os.environ["DROPBOX_LIVE"] = "1" if args.live else "0"
    if demo:
        print("DEMO profile — not a client estate")
    written: list[Path] = []
    profile = args.profile
    if profile in {"internal", "all"}:
        written.append(runners.write_inventory(scope, demo=demo))
        lynis = runners.write_lynis(scope, demo=demo)
        if lynis:
            written.append(lynis)
        if args.live:
            written.extend(runners.write_byo(scope, demo=False))
    if profile in {"external", "all"}:
        written.append(runners.write_tls_headers(scope, demo=demo, live=args.live))
    print("wrote:")
    for path in written:
        print(f"  {path}")
    return 0


def _seed_fixtures(dest_in: Path) -> None:
    src = ROOT / "fixtures" / "demo"
    for sensor in SENSORS:
        sdir = dest_in / sensor
        sdir.mkdir(parents=True, exist_ok=True)
        fixture = src / sensor
        if not fixture.is_dir():
            continue
        for path in fixture.iterdir():
            if path.is_file():
                shutil.copy2(path, sdir / path.name)


def cmd_status(args: argparse.Namespace) -> int:
    from dropbox.orchestrator.pipeline import STAGE_GRAPH, _orch_dir, integrity_stops
    from farm.adapters.catalog import slot_matrix

    scope = load_scope(Path(args.scope) if args.scope else None)
    _print_gate(scope)

    print("governor: quiet→loud")
    print(f"stage graph: {STAGE_GRAPH}")
    print(
        f"  stage=discover volume=quiet armed={scope.stage_discover} "
        f"prefix=/{scope.discover_prefix} max_workers={scope.max_workers}"
    )
    print(
        f"  stage=deepen volume=loud armed={scope.stage_deepen} "
        f"batch={scope.deepen_batch} deepen_hosts={len(scope.deepen_hosts)}"
    )
    print("  stage=external volume=named-only armed=False plan-only (no live probe)")
    print("  stage=ingest Layer C — files in in/ only; dropped_external inventory; not live")
    print("  stage=grc_export CISO CSVs + POA&M (owner/due blank); wrap review-only")
    print("integrity stops:")
    for stop in integrity_stops(scope):
        print(f"  - {stop}")
    print("allow_tools ∩ PATH ∩ SLOTS:")
    for row in slot_matrix(scope.allow_tools):
        loc = row["path"] or "—"
        slot_state = row.get("slot_state") or row["state"]
        print(f"  {row['tool']:24} {slot_state:12} {loc}")
    summary_path = _orch_dir() / "summary.json"
    if summary_path.is_file():
        data = json.loads(summary_path.read_text(encoding="utf-8"))
        disc = data.get("discover") or {}
        deep = data.get("deepen") or {}
        print(
            f"last run: discover mode={disc.get('mode')} shards={disc.get('shard_count')} "
            f"destroyed={disc.get('destroyed')} | deepen mode={deep.get('mode')} "
            f"batches={deep.get('batch_count')} destroyed={deep.get('destroyed')}"
        )
        last_stop = (
            data.get("last_integrity_stop")
            or disc.get("skip_reason")
            or deep.get("skip_reason")
            or ""
        )
        print(f"last integrity stop: {last_stop or 'none (run completed under brakes)'}")
        if "DEMO" in str(data.get("client") or "").upper():
            print("DEMO fixtures ≠ client estate.")
    else:
        print("last run: none (python3 -m dropbox orchestrate)")
        print("last integrity stop: none")
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    if args.tool == "serve":
        from dropbox.mcp_stub import serve

        extra: list[str] = []
        if getattr(args, "stdio", False):
            extra.append("--stdio")
        elif getattr(args, "once", False):
            extra.append("--once")
        else:
            extra.append("--list")
        if args.scope:
            extra.extend(["--scope", args.scope])
        return serve(extra)
    from dropbox.mcp_stub import dispatch

    result = dispatch(args.tool, live=False, scope_path=Path(args.scope) if args.scope else None)
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_orchestrate(args: argparse.Namespace) -> int:
    from dropbox.orchestrator.pipeline import orchestrate

    scope = load_scope(Path(args.scope) if args.scope else None)
    _print_gate(scope)
    summary = orchestrate(scope, live=bool(args.live))
    print(json.dumps(summary, indent=2))
    return 0


def cmd_lab(args: argparse.Namespace) -> int:
    """gate → seed fixtures + demo runners → leave work IN_DIR ready for collectors."""
    work_in = Path(os.environ.get("DROPBOX_WORK_IN") or (ROOT / "dropbox" / "work" / "in"))
    if work_in.exists():
        shutil.rmtree(work_in)
    work_in.mkdir(parents=True, exist_ok=True)
    os.environ["IN_DIR"] = str(work_in)
    scope = load_scope(Path(args.scope) if args.scope else None)
    _print_gate(scope)
    _seed_fixtures(work_in)
    os.environ["DROPBOX_DEMO"] = "1"
    os.environ["DROPBOX_LIVE"] = "0"
    runners.write_inventory(scope, demo=True)
    runners.write_lynis(scope, demo=True)
    runners.write_tls_headers(scope, demo=True, live=False)
    from dropbox.orchestrator.pipeline import orchestrate

    orch = orchestrate(scope, live=False, dest_in=work_in)
    print(
        f"orchestrator plan-only  shards={orch['discover']['shard_count']} "
        f"batches={orch['deepen']['batch_count']} destroyed={orch['discover']['destroyed']}"
    )
    print(f"dropbox-lab ingest ready under {work_in}")
    print("Estate is fixtures + demo runner overlays. Not a client.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dropbox", description="SCOPE-gated drop-box ingest")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate", help="validate SCOPE and consent; print and exit")
    g.add_argument("--scope", help="path to SCOPE.yaml (default dropbox/SCOPE.yaml)")
    g.set_defaults(func=cmd_gate)
    r = sub.add_parser("run", help="run a profile after the gate")
    r.add_argument("--scope", help="path to SCOPE.yaml (default dropbox/SCOPE.yaml)")
    r.add_argument("--profile", choices=("internal", "external", "all"), required=True)
    r.add_argument("--live", action="store_true", help="use ss/lynis/curl if on PATH (still SCOPE-gated)")
    r.set_defaults(func=cmd_run)
    lab = sub.add_parser("lab", help="demo ingest for make dropbox-lab")
    lab.add_argument("--scope", help="path to SCOPE.yaml (default dropbox/SCOPE.yaml)")
    lab.set_defaults(func=cmd_lab)
    o = sub.add_parser("orchestrate", help="discover → deepen → ingest (plan-only without BYO binaries)")
    o.add_argument("--scope", help="path to SCOPE.yaml (default dropbox/SCOPE.yaml)")
    o.add_argument("--live", action="store_true", help="run nmap/nessus only if on PATH and in allow_tools")
    o.set_defaults(func=cmd_orchestrate)
    st = sub.add_parser("status", help="show SCOPE brakes and last orchestrator run")
    st.add_argument("--scope", help="path to SCOPE.yaml (default dropbox/SCOPE.yaml)")
    st.set_defaults(func=cmd_status)
    mcp = sub.add_parser("mcp", help="operator MCP stub (SCOPE-gated; no attack API)")
    mcp.add_argument("tool", help="serve|scope_status|orchestrator_plan|orchestrator_status|stage_*|farm_slots|farm_slot_status|farm_toolbin_status|export_ciso_poam")
    mcp.add_argument("--scope", help="path to SCOPE.yaml (default dropbox/SCOPE.yaml)")
    mcp.add_argument("--stdio", action="store_true", help="JSON-RPC stdio loop (serve only)")
    mcp.add_argument("--once", action="store_true", help="one JSON-RPC line on stdin (serve only)")
    mcp.set_defaults(func=cmd_mcp)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except GateError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
