from __future__ import annotations

import subprocess
from pathlib import Path

from oss_vuln_lab.models import ScanTarget, TargetMode


def stage_target(spec: str, checkout_dir: Path) -> ScanTarget:
    if _looks_like_git_url(spec):
        checkout_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", spec, str(checkout_dir)],
            check=True,
            capture_output=True,
            text=True,
        )
        return ScanTarget(
            spec=spec,
            resolved_path=str(checkout_dir.resolve()),
            mode=TargetMode.SOURCE_REPO,
            origin="git_url",
        )

    path = Path(spec).expanduser().resolve()
    if path.is_dir():
        return ScanTarget(
            spec=spec,
            resolved_path=str(path),
            mode=TargetMode.SOURCE_REPO,
            origin="local_path",
        )
    if path.is_file() and _is_elf(path):
        return ScanTarget(
            spec=spec,
            resolved_path=str(path),
            mode=TargetMode.BINARY_ARTIFACT,
            origin="local_binary",
        )
    raise ValueError(f"Unsupported target specification: {spec}")


def _looks_like_git_url(spec: str) -> bool:
    return spec.startswith(("http://", "https://", "ssh://", "git@")) or spec.endswith(".git")


def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False
