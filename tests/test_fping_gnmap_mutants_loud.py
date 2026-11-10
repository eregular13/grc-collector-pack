"""Damaged fping text and greppable nmap must fail loud, never return a short OK.

Each mutant is one small, deterministic edit (byte insert, bit flip, line
truncate, line drop) on a clean export. Before the fix these parsed as OK with
fewer hosts (or zero); now they raise and name the damaged line numbers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from collectors.inventory_nmap import parse_file
from shared.fast_portscan import parse_fast_portscan

FPING_E = "# fping -e\n" + "".join(
    f"10.0.1.{i} is alive (0.{i} ms)\n" for i in range(10, 16)
) + "10.0.1.99 is unreachable\n"
FPING_A = "".join(f"10.0.1.{i}\n" for i in range(10, 16))
FPING_C = "".join(
    f"10.0.1.{i} : [0], 84 bytes, 0.{i} ms (0.{i} avg, 0% loss)\n" for i in range(10, 16)
) + "10.0.1.99 : [0], timed out (NaN avg, 100% loss)\n"
FPING_NAMES = "# fping -e\n" + "".join(f"h{i}.corp.example is alive\n" for i in range(6))


def _gnmap(hosts: int = 7) -> str:
    out = "# Nmap 7.94 scan initiated Thu Sep 10 12:00:00 2026 as: nmap -sV -oG scan.gnmap targets\n"
    for i in range(hosts):
        out += f"Host: 10.0.2.{10 + i} (srv{i}.corp.example)\tStatus: Up\n"
        out += (
            f"Host: 10.0.2.{10 + i} (srv{i}.corp.example)\t"
            f"Ports: 22/open/tcp//ssh///, {8000 + i}/open/tcp//http///\tIgnored State: closed (998)\n"
        )
    out += (
        f"# Nmap done at Thu Sep 10 12:00:15 2026 -- {hosts} IP addresses "
        f"({hosts} hosts up) scanned in 15.00 seconds\n"
    )
    return out


GNMAP = _gnmap()


def _assets(records: list[dict]) -> set[str]:
    return {r["name"] for r in records if r.get("kind") == "asset"}


def _write(tmp_path: Path, name: str, data: bytes | str) -> Path:
    path = tmp_path / name
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)
    return path


def _edit_line(text: str, lineno: int, fn) -> bytes:
    lines = text.encode("utf-8").split(b"\n")
    lines[lineno - 1] = fn(bytearray(lines[lineno - 1]))
    return b"\n".join(bytes(x) for x in lines)


def _insert(pos: int, byte: int):
    def go(line: bytearray) -> bytes:
        line[pos:pos] = bytes([byte])
        return bytes(line)

    return go


def _flip(pos: int, bit: int):
    def go(line: bytearray) -> bytes:
        line[pos] ^= 1 << bit
        return bytes(line)

    return go


def _truncate(keep: int):
    return lambda line: bytes(line[:keep])


# --- clean exports keep their real counts ---------------------------------


@pytest.mark.parametrize("text", [FPING_E, FPING_A, FPING_C, FPING_NAMES])
def test_clean_fping_counts(tmp_path: Path, text: str) -> None:
    assert len(_assets(parse_file(_write(tmp_path, "fping.txt", text)))) == 6


def test_clean_fping_with_stats_timestamps_and_summaries(tmp_path: Path) -> None:
    text = (
        "[1700000000.12345] 10.0.1.10 : [0], 84 bytes, 0.10 ms (0.10 avg, 0% loss)\n"
        "[1700000000.22345] 10.0.1.11 : [0], 84 bytes, 0.11 ms (0.11 avg, 0% loss)\n"
        "10.0.1.12 : [0], timed out (NaN avg, 100% loss)\n"
        "\n"
        "10.0.1.10 : xmt/rcv/%loss = 1/1/0%, min/avg/max = 0.10/0.10/0.10\n"
        "10.0.1.11 : xmt/rcv/%loss = 1/1/0%, min/avg/max = 0.11/0.11/0.11\n"
        "10.0.1.12 : xmt/rcv/%loss = 1/0/100%\n"
        "ICMP Host Unreachable from 10.0.1.1 for ICMP Echo sent to 10.0.1.12\n"
        "\n"
        "       3 targets\n"
        "       2 alive\n"
        "       1 unreachable\n"
        "       0 unknown addresses\n"
        "\n"
        "       1 timeouts (waiting for response)\n"
        "       3 ICMP Echos sent\n"
        "       2 ICMP Echo Replies received\n"
        "       1 other ICMP received\n"
        "\n"
        " 0.10 ms (min round trip time)\n"
        " 0.10 ms (avg round trip time)\n"
        " 0.11 ms (max round trip time)\n"
        "        1.012 sec (elapsed real time)\n"
    )
    assert _assets(parse_file(_write(tmp_path, "fping.txt", text))) == {"10.0.1.10", "10.0.1.11"}


def test_clean_gnmap_counts(tmp_path: Path) -> None:
    assert len(_assets(parse_file(_write(tmp_path, "scan.gnmap", GNMAP)))) == 7


def test_gnmap_all_ports_ignored_is_a_real_host(tmp_path: Path) -> None:
    text = (
        "# Nmap 7.94 scan initiated Thu Sep 10 12:00:00 2026 as: nmap -oG scan.gnmap t\n"
        "Host: 10.0.2.10 (a.corp.example)\tStatus: Up\n"
        "Host: 10.0.2.10 (a.corp.example)\tPorts: 22/open/tcp//ssh///\tIgnored State: closed (999)\n"
        "Host: 10.0.2.11 (b.corp.example)\tStatus: Up\n"
        "Host: 10.0.2.11 (b.corp.example)\tPorts: \tIgnored State: closed (1000)\n"
        "# Nmap done at Thu Sep 10 12:00:15 2026 -- 2 IP addresses (2 hosts up) scanned in 1.00 seconds\n"
    )
    assert _assets(parse_file(_write(tmp_path, "scan.gnmap", text))) == {
        "a.corp.example",
        "b.corp.example",
    }


def test_gnmap_host_timeout_has_no_ports_record(tmp_path: Path) -> None:
    text = (
        "# Nmap 7.94 scan initiated Thu Sep 10 12:00:00 2026 as: nmap -oG scan.gnmap t\n"
        "Host: 10.0.2.10 (a.corp.example)\tStatus: Up\n"
        "Host: 10.0.2.10 (a.corp.example)\tPorts: 22/open/tcp//ssh///\n"
        "Host: 10.0.2.11 (b.corp.example)\tStatus: Up\n"
        "Host: 10.0.2.11 (b.corp.example)\tStatus: Timeout\n"
        "# Nmap done at Thu Sep 10 12:00:15 2026 -- 2 IP addresses (2 hosts up) scanned in 1.00 seconds\n"
    )
    assert _assets(parse_file(_write(tmp_path, "scan.gnmap", text))) == {"a.corp.example"}


def test_gnmap_ping_scan_status_only_stays_ok(tmp_path: Path) -> None:
    text = (
        "# Nmap 7.94 scan initiated Thu Sep 10 12:00:00 2026 as: nmap -sn -oG scan.gnmap t\n"
        "Host: 10.0.2.10 ()\tStatus: Up\n"
        "Host: 10.0.2.11 ()\tStatus: Up\n"
        "# Nmap done at Thu Sep 10 12:00:15 2026 -- 2 IP addresses (2 hosts up) scanned in 1.00 seconds\n"
    )
    assert parse_file(_write(tmp_path, "scan.gnmap", text)) == []


# --- fping mutants ----------------------------------------------------------

FPING_MUTANTS = {
    # -e: bit flip in "is alive" -> "is elive"
    "e_flip_alive": (FPING_E, 7, _flip(13, 2), [7]),
    # -e: line truncated mid reply
    "e_truncate": (FPING_E, 4, _truncate(22), [4]),
    # -e: bit flip in the address separator
    "e_flip_addr": (FPING_E, 5, _flip(4, 1), [5]),
    # -e: "x is unreachable" cut down to a bare "x" must not become a host
    "e_unreachable_to_bare": (FPING_E, 8, _truncate(9), [8]),
    # -a: inserted byte inside an address
    "a_insert": (FPING_A, 4, _insert(7, 0xF1), [4]),
    # -a: inserted 0x1c (splitlines separator) used to read as "10.0.1.1" + "3"
    # and then as a JSON number list, which claimed the file as empty naabu.
    "a_insert_sep": (FPING_A, 4, _insert(8, 0x1C), [4]),
    # -a: truncated to a bare number, also used to give 0 rows
    "a_truncate_number": (FPING_A, 3, _truncate(2), [3]),
    # -c: bit flip in "bytes"
    "c_flip_bytes": (FPING_C, 6, _flip(20, 2), [6]),
    # -c: inserted byte inside the address
    "c_insert_addr": (FPING_C, 4, _insert(1, 0xC7), [4]),
    # names: inserted byte inside "alive"
    "names_insert": (FPING_NAMES, 2, _insert(20, 0x97), [2]),
    # names: hostname truncated
    "names_truncate": (FPING_NAMES, 4, _truncate(8), [4]),
}


@pytest.mark.parametrize("case", sorted(FPING_MUTANTS))
def test_fping_mutant_is_loud(tmp_path: Path, case: str) -> None:
    text, lineno, fn, bad = FPING_MUTANTS[case]
    path = _write(tmp_path, "fping.txt", _edit_line(text, lineno, fn))
    with pytest.raises(ValueError, match="unparseable fping line") as exc:
        parse_file(path)
    for n in bad:
        assert str(n) in str(exc.value)


def test_fping_stats_alive_count_mismatch_is_loud(tmp_path: Path) -> None:
    lines = FPING_E.splitlines()
    del lines[3]  # one "is alive" line lost
    text = "\n".join(lines) + "\n\n       7 targets\n       6 alive\n       1 unreachable\n"
    with pytest.raises(ValueError, match="unparseable fping line"):
        parse_file(_write(tmp_path, "fping.txt", text))


def test_fping_duplicate_line_keeps_count(tmp_path: Path) -> None:
    lines = FPING_E.splitlines()
    lines.insert(3, lines[3])
    path = _write(tmp_path, "fping.txt", "\n".join(lines) + "\n")
    assert len(_assets(parse_file(path))) == 6


def test_fping_json_corrupt_line_is_loud(tmp_path: Path) -> None:
    text = (
        '{"resp": {"host": "10.0.1.10", "seq": 0, "size": 84, "rtt": 0.1}}\n'
        '{"resp": {"host": "10.0.1.11", "seq": 0, "size": 84, "rtt"\n'
        '{"resp": {"host": "10.0.1.12", "seq": 0, "size": 84, "rtt": 0.1}}\n'
    )
    with pytest.raises(ValueError, match=r"corrupt JSON line\(s\) 2;"):
        parse_file(_write(tmp_path, "fping.txt", text))


def test_scalar_json_lines_are_not_naabu(tmp_path: Path) -> None:
    path = _write(tmp_path, "hosts.txt", "10\n3\n")
    assert parse_fast_portscan(path) is None


# --- gnmap mutants ----------------------------------------------------------

# Line 1 is the header; host i has Status on line 2+2i and Ports on line 3+2i.
GNMAP_MUTANTS = {
    # Ports line cut down to "Hos": Up host left without its Ports record
    "ports_truncate_short": (_truncate(3), 9, [8]),
    # Ports line cut down to nothing: Up host left without its Ports record
    "ports_truncate_empty": (_truncate(0), 9, [8]),
    # bit flip in the Ports hostname (srv3 -> srv2) merged two hosts
    "ports_flip_hostname": (_flip(23, 0), 9, [8]),
    # bit flip in the Ports address (10.0.2.13 -> 10.0.2.12)
    "ports_flip_addr": (_flip(14, 0), 9, [8]),
    # bit flip in the Status hostname
    "status_flip_hostname": (_flip(23, 0), 8, [8]),
}


@pytest.mark.parametrize("case", sorted(GNMAP_MUTANTS))
def test_gnmap_mutant_is_loud(tmp_path: Path, case: str) -> None:
    fn, lineno, bad = GNMAP_MUTANTS[case]
    path = _write(tmp_path, "scan.gnmap", _edit_line(GNMAP, lineno, fn))
    with pytest.raises(ValueError, match="unparseable gnmap Host line") as exc:
        parse_file(path)
    for n in bad:
        assert str(n) in str(exc.value)


def test_gnmap_vertical_tab_is_not_nbtscan(tmp_path: Path) -> None:
    # A vertical tab after "Host:" used to make the file read as nbtscan (1 host).
    path = _write(tmp_path, "scan.gnmap", _edit_line(GNMAP, 10, _insert(5, 0x0B)))
    assert len(_assets(parse_file(path))) == 7


def test_gnmap_line_numbers_ignore_control_bytes(tmp_path: Path) -> None:
    # 0x1e inside the port list on line 5 must not shift the reported line.
    path = _write(tmp_path, "scan.gnmap", _edit_line(GNMAP, 5, _insert(50, 0x1E)))
    with pytest.raises(ValueError, match=r"line\(s\) 5;"):
        parse_file(path)
