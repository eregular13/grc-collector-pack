"""SCOPE keys must be spelled exactly as documented.

The allowlist used to case-fold and strip, so PORTS_ALLOWED / ' ports_allowed '
loaded as an absent port limit and a live run to :22 proceeded. Refuse at the
loader boundary instead of silently normalising. Each named test fails if
that refuse is reverted.
"""

from __future__ import annotations

import contextvars
import hashlib
import socket
from datetime import date, timedelta
from pathlib import Path

import pytest

from dropbox.scope import (
    GateError,
    _SCOPE_KEYS,
    allowlisted_scope_keys,
    load_scope,
    refuse_unknown_scope_keys,
)
from dropbox.yaml_lite import load_yaml
from shared.web_tls_live import LiveRefuse, run_live

ROOT = Path(__file__).resolve().parents[1]
NBSP = "\u00a0"

# Security-relevant keys: misspelling used to drop the restriction.
SECURITY_SCOPE_KEYS = frozenset(
    {
        ("", "ports_allowed"),
        ("", "status"),
        ("", "revoked"),
        ("engagement", "ports_allowed"),
        ("engagement", "status"),
        ("engagement", "revoked"),
        ("engagement", "start"),
        ("engagement", "end"),
        ("internal", "hosts"),
        ("internal", "cidrs"),
        ("external", "hosts"),
        ("external", "ips"),
        ("external", "domains"),
        ("consent", "attestation_sha256"),
        ("consent", "attestation_path"),
    }
)


def _consent(tmp_path: Path) -> tuple[Path, str]:
    att = tmp_path / "consent.md"
    att.write_text("canonical-key consent\n", encoding="utf-8")
    return att, hashlib.sha256(att.read_bytes()).hexdigest()


def _mixed(canonical: str) -> str:
    parts = canonical.split("_")
    mixed = "_".join((p[:1].upper() + p[1:]) if p else p for p in parts)
    if mixed == canonical:
        mixed = canonical[:1].upper() + canonical[1:]
    if mixed == canonical:
        mixed = canonical.swapcase()
    return mixed


def key_variants(canonical: str) -> list[tuple[str, str]]:
    """Non-canonical spellings. Exact quoted ``'ports_allowed'`` is YAML
    syntax for the canonical name (#199) and is not a variant here.
    """
    return [
        ("upper", canonical.upper()),
        ("mixed", _mixed(canonical)),
        ("space", f"' {canonical} '"),
        ("nbsp", f"'{NBSP}{canonical}'"),
        ("quoted", f"'{canonical} '"),
        ("quoted_upper", f"'{canonical.upper()}'"),
    ]


def _scalar(value: object) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, list) and not value:
        return "[]"
    text = str(value)
    if text == "" or any(ch.isspace() for ch in text) or ":" in text:
        return f'"{text}"'
    return text


def _rewrite(section: str, key: str, target_section: str, target_key: str, variant: str) -> str:
    if section == target_section and key == target_key:
        return variant
    return key


def _emit_byo_item(
    lines: list[str],
    item: dict[str, object],
    indent: int,
    target_section: str,
    target_key: str,
    variant: str,
) -> None:
    pad = " " * indent
    first = True
    for key, value in item.items():
        token = _rewrite("byo[]", key, target_section, target_key, variant)
        if first:
            if isinstance(value, list) and not value:
                lines.append(f"{pad}- {token}: []\n")
            else:
                lines.append(f"{pad}- {token}: {_scalar(value)}\n")
            first = False
        else:
            if isinstance(value, list) and not value:
                lines.append(f"{pad}  {token}: []\n")
            else:
                lines.append(f"{pad}  {token}: {_scalar(value)}\n")


def _emit_mapping(
    lines: list[str],
    mapping: dict[str, object],
    indent: int,
    section: str,
    target_section: str,
    target_key: str,
    variant: str,
) -> None:
    pad = " " * indent
    for key, value in mapping.items():
        token = _rewrite(section, key, target_section, target_key, variant)
        child = f"{section}.{key}" if section else key
        if isinstance(value, dict):
            lines.append(f"{pad}{token}:\n")
            _emit_mapping(
                lines, value, indent + 2, child, target_section, target_key, variant
            )
        elif isinstance(value, list):
            if not value:
                lines.append(f"{pad}{token}: []\n")
                continue
            lines.append(f"{pad}{token}:\n")
            for item in value:
                if isinstance(item, dict):
                    _emit_byo_item(
                        lines, item, indent + 2, target_section, target_key, variant
                    )
                else:
                    lines.append(f"{pad}  - {_scalar(item)}\n")
        else:
            lines.append(f"{pad}{token}: {_scalar(value)}\n")


def _full_scope_tree(tmp_path: Path) -> dict[str, object]:
    att, digest = _consent(tmp_path)
    today = date.today()
    start = (today - timedelta(days=1)).isoformat()
    end = (today + timedelta(days=30)).isoformat()
    return {
        "client": {"name": "lab-client"},
        "consent": {
            "attestation_path": str(att),
            "attestation_sha256": digest,
        },
        "engagement": {
            "start": start,
            "end": end,
            "status": "authorized",
            "revoked": False,
            "ports_allowed": [443],
        },
        "revoked": False,
        "status": "authorized",
        "ports_allowed": [443],
        "internal": {
            "cidrs": ["192.0.2.0/24"],
            "hosts": ["192.0.2.10", "127.0.0.1"],
        },
        "external": {
            "hosts": ["vpn.example.invalid"],
            "domains": ["example.invalid"],
            "ips": ["192.0.2.10"],
        },
        "allow_tools": ["curl"],
        "orchestrator": {
            "discover_prefix": 24,
            "deepen_batch": 3,
            "max_live_shards": 16,
            "max_workers": 2,
            "host_timeout_sec": 30,
            "stages": {"discover": True, "deepen": False, "external": False},
            "deepen_hosts": ["192.0.2.10"],
            "stage_tools": {"discover": ["nmap"], "deepen": ["nessus"]},
        },
        "byo": [],
    }


def _stored_key(yaml_key: str) -> str:
    """What yaml_lite stores after stripping one matching quote pair."""
    text = yaml_key
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    return text


def write_scope_with_key(
    tmp_path: Path,
    section: str,
    key: str,
    yaml_key: str,
) -> Path:
    tree = _full_scope_tree(tmp_path)
    lines: list[str] = []
    _emit_mapping(lines, tree, 0, "", section, key, yaml_key)
    path = tmp_path / "SCOPE.yaml"
    path.write_text("".join(lines), encoding="utf-8")
    return path


def _byo_item_with_variant(key: str, yaml_key: str) -> dict[str, object]:
    item: dict[str, object] = {
        "name": "curl",
        "args": [],
        "sensor": "nmap",
        "timeout": 10,
    }
    value = item.pop(key)
    item[_stored_key(yaml_key)] = value
    return item


def refuse_or_load_variant(
    tmp_path: Path, section: str, key: str, yaml_key: str
) -> None:
    """Load a SCOPE whose ``key`` is spelled ``yaml_key``. byo[] mappings are
    constructed (yaml_lite list items are scalars, not mappings).
    """
    if section == "byo[]":
        tree = _full_scope_tree(tmp_path)
        tree["byo"] = [_byo_item_with_variant(key, yaml_key)]
        refuse_unknown_scope_keys(tree)
        return
    path = write_scope_with_key(tmp_path, section, key, yaml_key)
    load_scope(path)


def _record_sockets(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    recorded: list[tuple[str, int]] = []
    real_cc = socket.create_connection
    real_gai = socket.getaddrinfo

    def wrap_cc(addr, timeout=None, *args, **kwargs):
        host, port = addr[0], addr[1]
        recorded.append((str(host), int(port)))
        if str(host) in {"127.0.0.1", "::1"}:
            return real_cc(addr, timeout, *args, **kwargs)
        raise OSError(f"blocked connect {host}:{port}")

    def wrap_gai(host, port, *args, **kwargs):
        recorded.append((f"gai:{host}", int(port or 0)))
        return real_gai(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", wrap_cc)
    monkeypatch.setattr(socket, "getaddrinfo", wrap_gai)
    return recorded


def _variant_cases() -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for section, key in allowlisted_scope_keys():
        for label, yaml_key in key_variants(key):
            rows.append((section, key, label, yaml_key))
    return rows


VARIANT_CASES = _variant_cases()


def test_allowlisted_scope_keys_covers_every_section_key() -> None:
    """Catalog test: adding an allowlisted key without this list fails."""
    listed = set(allowlisted_scope_keys())
    expected = {(section, name) for section, names in _SCOPE_KEYS.items() for name in names}
    assert listed == expected
    assert listed, "allowlist must not be empty"
    assert ("engagement", "begin") not in listed


@pytest.mark.parametrize(
    "section,key,label,yaml_key",
    VARIANT_CASES,
    ids=[
        f"{section or 'root'}.{key}-{label}"
        for section, key, label, _yaml in VARIANT_CASES
    ],
)
def test_allowlisted_key_variant_refuses_load(
    tmp_path: Path, section: str, key: str, label: str, yaml_key: str
) -> None:
    """Every allowlisted key refuses upper / mixed / space / NBSP / quoted / quoted+upper."""
    folder = tmp_path / f"{section or 'root'}_{key}_{label}"
    folder.mkdir()
    with pytest.raises(GateError, match="non-canonical key|BOM|non-ASCII|unknown key"):
        refuse_or_load_variant(folder, section, key, yaml_key)


@pytest.mark.parametrize(
    "section,key",
    sorted(SECURITY_SCOPE_KEYS),
    ids=[f"{section or 'root'}.{key}" for section, key in sorted(SECURITY_SCOPE_KEYS)],
)
def test_security_key_variant_never_connects_out_of_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, section: str, key: str
) -> None:
    """Misspelled security keys must not load and must never open a socket."""
    recorded = _record_sockets(monkeypatch)
    yaml_key = key.upper()
    path = write_scope_with_key(tmp_path, section, key, yaml_key)
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    (tmp_path / "out").mkdir()
    with pytest.raises((GateError, LiveRefuse)):
        run_live(scope_path=path, target="192.0.2.10", ports=[22])
    connects = [(h, p) for h, p in recorded if not str(h).startswith("gai:")]
    assert connects == []
    assert not any(p == 22 and not str(h).startswith("gai:") for h, p in recorded)


def test_uppercase_ports_allowed_refuses_live_port_22(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PORTS_ALLOWED: [443] must not load with no port limit."""
    recorded = _record_sockets(monkeypatch)
    path = write_scope_with_key(tmp_path, "", "ports_allowed", "PORTS_ALLOWED")
    with pytest.raises((GateError, LiveRefuse), match="canonical: ports_allowed"):
        run_live(scope_path=path, target="192.0.2.10", ports=[22])
    assert not any(p == 22 and not str(h).startswith("gai:") for h, p in recorded)


def test_engagement_mixed_ports_allowed_refuses_live_port_22(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """engagement.Ports_Allowed must not load with no port limit."""
    recorded = _record_sockets(monkeypatch)
    path = write_scope_with_key(tmp_path, "engagement", "ports_allowed", "Ports_Allowed")
    with pytest.raises((GateError, LiveRefuse), match="canonical: ports_allowed"):
        run_live(scope_path=path, target="192.0.2.10", ports=[22])
    assert not any(p == 22 and not str(h).startswith("gai:") for h, p in recorded)


def test_quoted_spaced_ports_allowed_refuses_live_port_22(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """' ports_allowed ' must not load with no port limit."""
    recorded = _record_sockets(monkeypatch)
    path = write_scope_with_key(tmp_path, "", "ports_allowed", "' ports_allowed '")
    with pytest.raises((GateError, LiveRefuse), match="canonical: ports_allowed"):
        run_live(scope_path=path, target="192.0.2.10", ports=[22])
    assert not any(p == 22 and not str(h).startswith("gai:") for h, p in recorded)


def test_noncanonical_error_names_canonical_spelling(tmp_path: Path) -> None:
    path = write_scope_with_key(tmp_path, "", "ports_allowed", "PORTS_ALLOWED")
    with pytest.raises(GateError, match=r"non-canonical key 'PORTS_ALLOWED'.*canonical: ports_allowed"):
        load_scope(path)


def test_canonical_full_scope_still_loads(tmp_path: Path) -> None:
    path = write_scope_with_key(tmp_path, "", "client", "client")
    scope = load_scope(path)
    assert scope.ports_allowed == [443]
    assert not scope.allows_port(22)
    assert scope.allows_port(443)


def test_engagement_begin_is_not_allowlisted() -> None:
    """Undocumented begin alias must not sit on the allowlist untested."""
    assert "begin" not in _SCOPE_KEYS["engagement"]
    assert ("engagement", "begin") not in allowlisted_scope_keys()


def test_engagement_begin_refuses_load(tmp_path: Path) -> None:
    att, digest = _consent(tmp_path)
    today = date.today()
    path = tmp_path / "SCOPE.yaml"
    path.write_text(
        "client:\n  name: lab-client\nconsent:\n"
        f"  attestation_path: {att}\n  attestation_sha256: {digest}\n"
        f"engagement:\n  begin: {today.isoformat()}\n"
        f"  end: {(today + timedelta(days=2)).isoformat()}\n"
        "internal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.invalid\n"
        "allow_tools:\n  - curl\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="unknown key 'begin'|canonical"):
        load_scope(path)


def test_bom_key_refuses_load(tmp_path: Path) -> None:
    path = write_scope_with_key(tmp_path, "", "ports_allowed", f"\ufeffports_allowed")
    with pytest.raises(GateError, match="BOM"):
        load_scope(path)


def test_bom_prefixed_file_refuses_load(tmp_path: Path) -> None:
    path = write_scope_with_key(tmp_path, "", "client", "client")
    text = path.read_text(encoding="utf-8")
    path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
    with pytest.raises(GateError, match="BOM"):
        load_scope(path)


def test_copy_context_run_is_nested_bind() -> None:
    """copy_context().run inherits _BIND_HELD and is a nested bind."""
    from shared import web_tls_live as live

    seen: list[str] = []

    def nested() -> str:
        with live._bind_scope(object()):
            seen.append("nested")
            return "ok"

    with live._bind_scope(object()):
        ctx = contextvars.copy_context()
        assert ctx.run(nested) == "ok"
    assert seen == ["nested"]


def _enable_commented_example_keys(text: str) -> str:
    """Turn documented optional keys on. Leave prose comments alone."""
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("# status: authorized"):
            out.append(line.replace("# ", "", 1))
        elif stripped.startswith("# ports_allowed:"):
            out.append(line.replace("# ", "", 1))
        elif stripped.startswith("#   - 80") or stripped.startswith("#   - 443"):
            out.append(line.replace("# ", "", 1))
        else:
            out.append(line)
    return "".join(out)


def test_example_scope_commented_keys_enabled_still_parses() -> None:
    """SCOPE.example.yaml with its commented keys enabled must still parse."""
    raw = (ROOT / "dropbox" / "SCOPE.example.yaml").read_text(encoding="utf-8")
    enabled = _enable_commented_example_keys(raw)
    assert "status: authorized" in enabled
    assert "ports_allowed:" in enabled
    data = load_yaml(enabled)
    refuse_unknown_scope_keys(data)
    assert data["engagement"].get("status") == "authorized" or "status: authorized" in enabled
    assert data.get("ports_allowed") == [80, 443]


def test_example_scope_commented_keys_enabled_loads(tmp_path: Path) -> None:
    """Filled example + uncommented optional keys must load_scope."""
    att, digest = _consent(tmp_path)
    today = date.today()
    raw = (ROOT / "dropbox" / "SCOPE.example.yaml").read_text(encoding="utf-8")
    enabled = _enable_commented_example_keys(raw)
    enabled = enabled.replace("YYYY-MM-DD", today.isoformat(), 1)
    enabled = enabled.replace(
        "YYYY-MM-DD", (today + timedelta(days=30)).isoformat(), 1
    )
    enabled = enabled.replace(
        "dropbox/consent/SIGNED-CONSENT.md", str(att)
    )
    enabled = enabled.replace(
        '"sha256-of-the-signed-attestation-file"', digest
    )
    path = tmp_path / "SCOPE.example.enabled.yaml"
    path.write_text(enabled, encoding="utf-8")
    scope = load_scope(path)
    assert scope.ports_allowed == [80, 443]
    assert not scope.allows_port(22)
    assert scope.client_name == "CLIENT LEGAL NAME"


def test_committed_scope_and_example_still_load() -> None:
    demo = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    assert demo.ports_allowed is None
    example = load_yaml((ROOT / "dropbox" / "SCOPE.example.yaml").read_text(encoding="utf-8"))
    refuse_unknown_scope_keys(example)
    assert example["orchestrator"]["stages"]["deepen"] is False
