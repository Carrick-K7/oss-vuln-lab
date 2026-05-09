from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from oss_vuln_digger.models import ScanResult, ensure_directory


STATE_FILE = "run.json"
REPORT_JSON = "report.json"
REPORT_MD = "report.md"


def create_run_dir(base_dir: str, label: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safe_label = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in label)
    root = Path(base_dir).expanduser().resolve()
    run_dir = root / f"{stamp}-{safe_label}"
    if not run_dir.exists():
        return ensure_directory(run_dir)
    suffix = 1
    while True:
        candidate = root / f"{stamp}-{safe_label}-{suffix}"
        if not candidate.exists():
            return ensure_directory(candidate)
        suffix += 1


def write_scan_result(result: ScanResult) -> None:
    run_dir = Path(result.run_dir)
    ensure_directory(run_dir)
    payload = result.to_dict()
    (run_dir / STATE_FILE).write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    report_json = {
        "run_id": result.run_id,
        "created_at": result.created_at,
        "target": result.target.to_dict(),
        "project": result.project.to_dict(),
        "findings": [record.final.to_dict() for record in result.records],
        "metadata": result.metadata,
    }
    (run_dir / REPORT_JSON).write_text(
        json.dumps(report_json, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_scan_result(run_ref: str, base_dir: str = ".ovd_runs") -> ScanResult:
    candidate = Path(run_ref)
    if candidate.is_dir():
        run_dir = candidate
    else:
        run_dir = Path(base_dir) / run_ref
    data = json.loads((run_dir / STATE_FILE).read_text(encoding="utf-8"))
    return ScanResult.from_dict(data)
