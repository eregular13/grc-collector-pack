"""Minimal YAML subset loader for SCOPE files. No PyYAML dependency."""

from __future__ import annotations

from typing import Any


def load_yaml(text: str) -> Any:
    lines = text.replace("\t", "  ").splitlines()
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if stripped.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError(f"list item without list parent: {stripped}")
            item = _scalar(stripped[2:].strip())
            parent.append(item)
            continue
        if ":" not in stripped:
            raise ValueError(f"expected key: {stripped}")
        key, rest = stripped.split(":", 1)
        key = key.strip()
        rest = rest.strip()
        if not isinstance(parent, dict):
            raise ValueError(f"mapping entry without mapping parent: {stripped}")
        if rest == "":
            nxt = _next_significant(lines, i)
            if nxt is not None and nxt.lstrip().startswith("- "):
                parent[key] = []
            else:
                parent[key] = {}
            stack.append((indent, parent[key]))
        else:
            parent[key] = _scalar(rest)
    return root


def _next_significant(lines: list[str], start: int) -> str | None:
    for line in lines[start:]:
        if line.strip() and not line.lstrip().startswith("#"):
            return line
    return None


def _scalar(value: str) -> Any:
    if value == "[]":
        return []
    if value == "{}":
        return {}
    if value.startswith("'") and value.endswith("'") and len(value) >= 2:
        return value[1:-1]
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        return value[1:-1]
    low = value.lower()
    if low in {"true", "yes"}:
        return True
    if low in {"false", "no"}:
        return False
    if low in {"null", "~", ""}:
        return None
    try:
        if value.startswith("0") and value != "0" and not value.startswith("0."):
            return value
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value
