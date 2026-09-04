"""Minimal YAML subset loader. No PyYAML dependency."""

from __future__ import annotations

from typing import Any


def load_yaml(text: str) -> Any:
    lines = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        lines.append(raw.rstrip())
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    pending_key: str | None = None
    pending_indent = 0
    for line in lines:
        indent = len(line) - len(line.lstrip())
        body = line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if body.startswith("- "):
            item = _scalar(body[2:].strip())
            if not isinstance(parent, list):
                if pending_key is not None and isinstance(stack[-1][1], dict):
                    lst: list[Any] = []
                    stack[-1][1][pending_key] = lst
                    parent = lst
                    stack.append((pending_indent, lst))
                else:
                    raise ValueError(f"list item without key: {line}")
            parent.append(item)
            continue
        if ":" not in body:
            raise ValueError(f"bad yaml line: {line}")
        key, rest = body.split(":", 1)
        key = key.strip()
        rest = rest.strip()
        if rest == "":
            pending_key = key
            pending_indent = indent
            placeholder: dict[str, Any] = {}
            if isinstance(parent, dict):
                parent[key] = placeholder
            stack.append((indent, placeholder))
            continue
        pending_key = None
        value = _scalar(rest)
        if isinstance(parent, dict):
            parent[key] = value
    return root


def _scalar(raw: str) -> Any:
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_scalar(p.strip()) for p in inner.split(",")]
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    low = raw.lower()
    if low in {"true", "yes"}:
        return True
    if low in {"false", "no"}:
        return False
    if raw.isdigit() or (raw.startswith("-") and raw[1:].isdigit()):
        return int(raw)
    return raw
