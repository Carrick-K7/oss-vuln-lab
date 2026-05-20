from __future__ import annotations

from pathlib import Path


def validate_simple_filename(value: str, *, label: str = "filename") -> str:
    name = str(value).strip()
    path = Path(name)
    if not name or path.name != name or name in {".", ".."}:
        raise ValueError(f"{label} must be a simple filename without path segments")
    return name
