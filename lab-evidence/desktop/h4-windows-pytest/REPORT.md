# H4 — Windows pytest triage (ce67328)

LAB desktop testbed. Not a client estate. SAMPLE != LAB != client.
posted=false. No `/api/risks`. RiskReady stay-out. Did not flip `client_facing_ready`.

**Stamp:** 20260926-1917 PT  
**Python:** `C:\Python314\python.exe` 3.14.6  
**Host:** Windows 11  
**Base:** `ce67328` (`hermes/testbed-base-2026-09-26`)  
**Branch:** `hermes/h4-windows-pytest-2026-09-26`

## Commands

```
C:/Python314/python.exe lab-evidence/desktop/h4-windows-pytest/run_pytest.py baseline
C:/Python314/python.exe lab-evidence/desktop/h4-windows-pytest/run_pytest.py after
```

Exit 1 both times (failures remain). No live GRC. No container start/stop. No scan.

## Before / after (same 1516 collected)

| phase    | passed | failed | errors | skipped | elapsed |
|----------|--------|--------|--------|---------|---------|
| baseline | 1424   | 91     | 0      | 1       | 93.8s   |
| after    | 1481   | 11     | 0      | 24      | 95.4s   |

Delta: +57 passed, −80 failed, +23 skipped (bash wrappers).

## Baseline failures by root cause (91)

| bucket | n | what |
|--------|---|------|
| `/bin/bash` (WSL `execvpe(/bin/bash)` missing) | 23 | `.sh` wrappers via `subprocess [bash, …]` |
| `python3` alias (Microsoft Store stub / exit 9009) | ~20 | CLI tests argv `"python3"` |
| WinError 1314 symlink | 5 | `tests/hermetic_path.py` `symlink_to(python)` |
| CRLF MANIFEST (`sha256sum: 'poam/poam.csv'$'\r'`) | 5 | `Path.write_text` translated LF→CRLF |
| CRLF consent hash (raw sha256 of CRLF vs `attestation_digest` LF) | ~15 | tests stamped `hashlib.sha256(att.read_bytes())` then `load_scope` |
| path separators | 3 | `'farm/work' in windows_path`, `tool-bin/lab/`, `endswith("/lab/nmap")` |
| POSIX shebang / WinError 193 | rest | `#!/bin/sh` lab stubs are not Win32 apps |

Exact nodeids: `baseline/summary.json`, `baseline/grouped.json`, `baseline/pytest-stdout.txt`.

## Portability fixes on this branch (Linux-safe)

- `tests/cli_python.py`: `PYTHON = sys.executable`; `skip_unless_bash` (`os.name == "nt"`, reason: bash wrapper; WSL `/bin/bash` missing).
- Subprocess CLI tests use `PYTHON` instead of `"python3"` (docs that assert the string `python3 -m …` unchanged).
- Bash-only tests decorated `@skip_unless_bash` (not skipped on Linux/CI).
- `tests/hermetic_path.py`: Windows copies `python3.exe`/`python.exe`; no symlink (WinError 1314).
- Consent stamps use `attestation_digest` (LF-canonical) so Windows `write_text` CRLF still gates.
- `write_export_manifest`: `newline="\n"` so GNU `sha256sum -c MANIFEST` does not see `$'\r'` filenames.
- `missing_keep_package_files`: relative POSIX `keep/__main__.py` (Windows `keep\__main__.py` broke `pytest.raises(..., match=)`).
- Path assertions use `Path(...).as_posix()`.

## Remaining 11 — real Windows product bugs (not skipped)

POSIX shebang lab stubs (`farm/tool-bin/lab/nmap` etc. are `#!/bin/sh`, not MZ/Win32). `CreateProcess` → WinError 193, or `shutil.which("nmap")` misses extension-less files, so live discover stays `plan`. **Do not skip these.**

1. `tests/test_adapter_contract.py::test_allowlisted_live_discover_invokes_stub` — `plan` != `live` (`#!/bin/sh` nmap stub).
2. `tests/test_adapter_contract.py::test_curl_and_testssl_byo_stubs` — same BYO sh stubs.
3. `tests/test_farm_adapters.py::test_wired_slots_invoke_path_stubs` — invoke stays `plan`.
4. `tests/test_farm_adapters.py::test_plan_only_when_live_false` — `will_run` / stub PATH.
5. `tests/test_farm_orch.py::test_live_discover_uses_path_invoke_only` — `plan` != `live`.
6. `tests/test_farm_orch.py::test_live_deepen_only_deepen_invoke_on_named_hosts` — `invoked.txt` never written (stub not executed).
7. `tests/test_farm_tool_bin.py::test_farm_tool_bin_dry_invoke_writes_work_out_no_network` — WinError 193.
8. `tests/test_farm_tool_bin.py::test_farm_tool_bin_dry_invoke_deepen_external_adjacent` — WinError 193.
9. `tests/test_farm_toolbin_e2e.py::test_farm_toolbin_e2e_quiet_to_loud_under_farm_work` — stub invoke / JSON.
10. `tests/test_mcp_stub.py::test_host_nmap_on_path_does_not_flip_isolated_toolbin_status` — extra_bins `nmap` (no `.exe`) → `which` None.
11. `tests/test_parsers.py::test_lab_stub_gnmap_parses` — `subprocess.check_output([lab/nmap])` WinError 193.

Follow-up (not this branch): Windows `.cmd` shims for lab stubs, or `skipif(os.name=="nt")` only after CoS agrees those tests are POSIX-only. Do not paper over CreateProcess.

## Honesty

- LAB pytest != SAMPLE fixtures != client KEEP.
- File-true export tests still file-true. No live CISO/OpenGRC/Probo POST.
- OpenGRC `--live` still refused (would be `/api/risks`). RiskReady WRAP_DEAD.
- Linux CI: `sys.executable` still the runner; bash skipif is false; MANIFEST stays LF; consent digest unchanged on LF files.
