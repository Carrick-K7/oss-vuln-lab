from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha1
import json
from pathlib import Path
import time
from typing import Any

from oss_vuln_digger.models import ensure_directory
from oss_vuln_digger.pipeline import ScanEngine


BATCHES_DIR_NAME = "batches"
SCHEDULES_DIR_NAME = "schedules"
BATCH_STATE_FILE = "batch.json"
BATCH_REPORT_MD = "batch.md"
SCHEDULE_STATE_FILE = "state.json"


class AutomationValidationError(ValueError):
    pass


@dataclass(slots=True)
class BatchJobSpec:
    name: str
    mode: str
    target: str
    cve_id: str = ""
    manifest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode,
            "target": self.target,
            "cve_id": self.cve_id,
            "manifest": self.manifest,
        }


@dataclass(slots=True)
class BatchSpec:
    name: str
    jobs: list[BatchJobSpec]


@dataclass(slots=True)
class BatchJobResult:
    name: str
    mode: str
    target: str
    status: str
    run_id: str = ""
    run_dir: str = ""
    finding_count: int = 0
    error: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode,
            "target": self.target,
            "status": self.status,
            "run_id": self.run_id,
            "run_dir": self.run_dir,
            "finding_count": self.finding_count,
            "error": self.error,
            "findings": self.findings,
        }


@dataclass(slots=True)
class BatchResult:
    batch_id: str
    name: str
    created_at: str
    manifest_ref: str
    jobs: list[BatchJobResult]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "name": self.name,
            "created_at": self.created_at,
            "manifest_ref": self.manifest_ref,
            "jobs": [item.to_dict() for item in self.jobs],
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class ScheduledTaskSpec:
    name: str
    every_minutes: int
    job: BatchJobSpec
    enabled: bool = True


@dataclass(slots=True)
class ScheduleSpec:
    name: str
    tasks: list[ScheduledTaskSpec]


@dataclass(slots=True)
class ScheduleRunResult:
    schedule_name: str
    evaluated_at: str
    due_tasks: list[str]
    batch_result: BatchResult | None


class BatchRunner:
    def __init__(self, engine: ScanEngine):
        self.engine = engine

    def run_manifest(self, manifest_ref: str) -> BatchResult:
        manifest_path = Path(manifest_ref).expanduser().resolve()
        spec = load_batch_spec(manifest_path)
        return self.run_spec(spec, manifest_ref=str(manifest_path))

    def run_spec(
        self,
        spec: BatchSpec,
        *,
        manifest_ref: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> BatchResult:
        previous_batch = _latest_batch_by_name(self.engine.config.runs_dir, spec.name)
        batch_dir = create_batch_dir(self.engine.config.runs_dir, spec.name)
        job_results: list[BatchJobResult] = []
        for job in spec.jobs:
            job_results.append(self._run_job(job))
        derived_metadata = _build_batch_metadata(job_results, previous_batch)
        combined_metadata = dict(metadata or {})
        combined_metadata.update(derived_metadata)
        batch = BatchResult(
            batch_id=batch_dir.name,
            name=spec.name,
            created_at=_utc_now(),
            manifest_ref=manifest_ref,
            jobs=job_results,
            metadata=combined_metadata,
        )
        write_batch_result(batch, batch_dir)
        return batch

    def _run_job(self, job: BatchJobSpec) -> BatchJobResult:
        try:
            if job.mode == "scan":
                result = self.engine.scan(job.target)
            elif job.mode == "replay_cve":
                result = self.engine.replay_cve(job.target, job.cve_id)
            elif job.mode == "replay_manifest":
                result = self.engine.replay_manifest(job.target, job.manifest)
            else:
                raise AutomationValidationError(f"Unsupported batch job mode: {job.mode}")
        except Exception as exc:
            return BatchJobResult(
                name=job.name,
                mode=job.mode,
                target=job.target,
                status="failed",
                error=str(exc),
            )
        return BatchJobResult(
            name=job.name,
            mode=job.mode,
            target=job.target,
            status="completed",
            run_id=result.run_id,
            run_dir=result.run_dir,
            finding_count=len(result.records),
            findings=_summarize_result_findings(job.name, result),
        )


class ScheduleRunner:
    def __init__(self, engine: ScanEngine):
        self.engine = engine
        self.batch_runner = BatchRunner(engine)

    def run_once(self, manifest_ref: str, *, now: datetime | None = None) -> ScheduleRunResult:
        manifest_path = Path(manifest_ref).expanduser().resolve()
        spec = load_schedule_spec(manifest_path)
        state_path = schedule_state_path(self.engine.config.runs_dir, spec.name)
        state = _load_state(state_path)
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        due_tasks: list[ScheduledTaskSpec] = []
        for task in spec.tasks:
            if task.enabled and _task_due(task, state, current):
                due_tasks.append(task)
        batch_result: BatchResult | None = None
        if due_tasks:
            batch_result = self.batch_runner.run_spec(
                BatchSpec(name=f"{spec.name}-scheduled", jobs=[task.job for task in due_tasks]),
                manifest_ref=str(manifest_path),
                metadata={
                    "schedule_name": spec.name,
                    "scheduled_tasks": [task.name for task in due_tasks],
                    "evaluated_at": current.isoformat(),
                },
            )
            for task in due_tasks:
                state.setdefault("tasks", {}).setdefault(task.name, {})
                state["tasks"][task.name]["last_run_at"] = current.isoformat()
                state["tasks"][task.name]["last_batch_id"] = batch_result.batch_id
        state["schedule_name"] = spec.name
        state["evaluated_at"] = current.isoformat()
        _write_state(state_path, state)
        return ScheduleRunResult(
            schedule_name=spec.name,
            evaluated_at=current.isoformat(),
            due_tasks=[task.name for task in due_tasks],
            batch_result=batch_result,
        )

    def run_loop(
        self,
        manifest_ref: str,
        *,
        iterations: int = 0,
        poll_seconds: int = 60,
    ) -> list[ScheduleRunResult]:
        results: list[ScheduleRunResult] = []
        completed = 0
        while iterations <= 0 or completed < iterations:
            results.append(self.run_once(manifest_ref))
            completed += 1
            if iterations > 0 and completed >= iterations:
                break
            time.sleep(max(1, poll_seconds))
        return results

    def show_state(self, manifest_ref: str) -> dict[str, Any]:
        manifest_path = Path(manifest_ref).expanduser().resolve()
        spec = load_schedule_spec(manifest_path)
        return _load_state(schedule_state_path(self.engine.config.runs_dir, spec.name))


def create_batch_dir(base_dir: str, label: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safe = _safe_label(label)
    root = ensure_directory(Path(base_dir).expanduser().resolve() / BATCHES_DIR_NAME)
    directory = root / f"{stamp}-{safe}"
    if not directory.exists():
        return ensure_directory(directory)
    suffix = 1
    while True:
        candidate = root / f"{stamp}-{safe}-{suffix}"
        if not candidate.exists():
            return ensure_directory(candidate)
        suffix += 1


def write_batch_result(batch: BatchResult, batch_dir: Path) -> None:
    ensure_directory(batch_dir)
    payload = batch.to_dict()
    (batch_dir / BATCH_STATE_FILE).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    (batch_dir / BATCH_REPORT_MD).write_text(render_batch_markdown(batch), encoding="utf-8")


def load_batch_result(batch_ref: str, runs_dir: str) -> BatchResult:
    candidate = Path(batch_ref)
    if candidate.is_dir():
        batch_dir = candidate
    else:
        batch_dir = Path(runs_dir).expanduser().resolve() / BATCHES_DIR_NAME / batch_ref
    data = json.loads((batch_dir / BATCH_STATE_FILE).read_text(encoding="utf-8"))
    return BatchResult(
        batch_id=data["batch_id"],
        name=data["name"],
        created_at=data["created_at"],
        manifest_ref=data.get("manifest_ref", ""),
        jobs=[BatchJobResult(**item) for item in data.get("jobs", [])],
        metadata=dict(data.get("metadata", {})),
    )


def list_batches(runs_dir: str) -> list[BatchResult]:
    base_dir = Path(runs_dir).expanduser().resolve() / BATCHES_DIR_NAME
    if not base_dir.exists():
        return []
    results: list[BatchResult] = []
    for path in sorted(base_dir.iterdir(), reverse=True):
        if path.is_dir() and (path / BATCH_STATE_FILE).exists():
            results.append(load_batch_result(str(path), runs_dir))
    return results


def load_batch_spec(manifest_path: Path) -> BatchSpec:
    data = _load_json_object(manifest_path)
    name = _required_string(data, "name", manifest_path)
    jobs_payload = data.get("jobs")
    if not isinstance(jobs_payload, list) or not jobs_payload:
        raise AutomationValidationError(f"{manifest_path}: jobs must be a non-empty list")
    jobs = [parse_batch_job(item, manifest_path, index) for index, item in enumerate(jobs_payload)]
    return BatchSpec(name=name, jobs=jobs)


def parse_batch_job(payload: object, manifest_path: Path, index: int) -> BatchJobSpec:
    label = f"jobs[{index}]"
    if not isinstance(payload, dict):
        raise AutomationValidationError(f"{manifest_path}: {label} must be an object")
    name = _required_string(payload, "name", manifest_path, prefix=f"{label}.")
    mode = _required_string(payload, "mode", manifest_path, prefix=f"{label}.")
    target = _required_string(payload, "target", manifest_path, prefix=f"{label}.")
    cve_id = _optional_string(payload, "cve_id")
    manifest = _optional_string(payload, "manifest")
    if mode == "replay_cve" and not cve_id:
        raise AutomationValidationError(f"{manifest_path}: {label}.cve_id is required for replay_cve jobs")
    if mode == "replay_manifest" and not manifest:
        raise AutomationValidationError(f"{manifest_path}: {label}.manifest is required for replay_manifest jobs")
    if mode not in {"scan", "replay_cve", "replay_manifest"}:
        raise AutomationValidationError(f"{manifest_path}: {label}.mode is not supported")
    return BatchJobSpec(name=name, mode=mode, target=target, cve_id=cve_id, manifest=manifest)


def load_schedule_spec(manifest_path: Path) -> ScheduleSpec:
    data = _load_json_object(manifest_path)
    name = _required_string(data, "name", manifest_path)
    tasks_payload = data.get("tasks")
    if not isinstance(tasks_payload, list) or not tasks_payload:
        raise AutomationValidationError(f"{manifest_path}: tasks must be a non-empty list")
    tasks: list[ScheduledTaskSpec] = []
    for index, item in enumerate(tasks_payload):
        label = f"tasks[{index}]"
        if not isinstance(item, dict):
            raise AutomationValidationError(f"{manifest_path}: {label} must be an object")
        task_name = _required_string(item, "name", manifest_path, prefix=f"{label}.")
        every_minutes = item.get("every_minutes")
        if not isinstance(every_minutes, int) or every_minutes <= 0:
            raise AutomationValidationError(f"{manifest_path}: {label}.every_minutes must be a positive integer")
        job_payload = item.get("job")
        if not isinstance(job_payload, dict):
            raise AutomationValidationError(f"{manifest_path}: {label}.job must be an object")
        tasks.append(
            ScheduledTaskSpec(
                name=task_name,
                every_minutes=every_minutes,
                job=parse_batch_job(job_payload, manifest_path, index),
                enabled=bool(item.get("enabled", True)),
            )
        )
    return ScheduleSpec(name=name, tasks=tasks)


def schedule_state_path(runs_dir: str, schedule_name: str) -> Path:
    safe_name = _safe_label(schedule_name)
    directory = ensure_directory(Path(runs_dir).expanduser().resolve() / SCHEDULES_DIR_NAME / safe_name)
    return directory / SCHEDULE_STATE_FILE


def render_batch_markdown(batch: BatchResult) -> str:
    lines = [
        "# Batch Report",
        "",
        f"- Batch ID: `{batch.batch_id}`",
        f"- Name: `{batch.name}`",
        f"- Created: `{batch.created_at}`",
    ]
    if batch.manifest_ref:
        lines.append(f"- Manifest: `{batch.manifest_ref}`")
    dedup = dict(batch.metadata.get("dedup", {}))
    comparison = dict(batch.metadata.get("comparison", {}))
    if dedup:
        lines.extend(
            [
                f"- Unique Findings: `{dedup.get('unique_findings', 0)}`",
                f"- Duplicate Findings: `{dedup.get('duplicate_findings', 0)}`",
            ]
        )
    if comparison:
        lines.extend(
            [
                f"- Previous Batch: `{comparison.get('previous_batch_id', 'n/a')}`",
                f"- New Findings: `{comparison.get('new_count', 0)}`",
                f"- Resolved Findings: `{comparison.get('resolved_count', 0)}`",
                f"- Repeated Findings: `{comparison.get('repeated_count', 0)}`",
            ]
        )
    lines.extend(["", "## Jobs", ""])
    for job in batch.jobs:
        lines.extend(
            [
                f"### {job.name}",
                "",
                f"- Mode: `{job.mode}`",
                f"- Target: `{job.target}`",
                f"- Status: `{job.status}`",
                f"- Run ID: `{job.run_id or 'n/a'}`",
                f"- Findings: `{job.finding_count}`",
            ]
        )
        if job.error:
            lines.append(f"- Error: {job.error}")
        if job.findings:
            lines.append("- Findings:")
            for finding in job.findings:
                lines.append(
                    f"  - `{finding['status']}` `{finding['vuln_family']}` {finding['title']} ({finding['signature'][:12]})"
                )
        lines.append("")
    if dedup.get("groups"):
        lines.extend(["## Deduplication", ""])
        for group in dedup["groups"]:
            lines.append(
                f"- `{group['signature'][:12]}` count={group['count']} jobs={', '.join(group['jobs'])} titles={', '.join(group['titles'])}"
            )
        lines.append("")
    return "\n".join(lines)


def _task_due(task: ScheduledTaskSpec, state: dict[str, Any], current: datetime) -> bool:
    task_state = state.get("tasks", {}).get(task.name, {})
    last_run_at = task_state.get("last_run_at")
    if not last_run_at:
        return True
    previous = _parse_datetime(last_run_at)
    delta = current - previous
    return delta.total_seconds() >= task.every_minutes * 60


def _load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"tasks": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    ensure_directory(path.parent)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as exc:
        raise AutomationValidationError(f"{path}: invalid JSON manifest: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise AutomationValidationError(f"{path}: manifest must be a JSON object")
    return data


def _required_string(data: dict[str, Any], key: str, path: Path, *, prefix: str = "") -> str:
    if key not in data or not isinstance(data[key], str) or not data[key].strip():
        raise AutomationValidationError(f"{path}: {prefix}{key} must be a non-empty string")
    return data[key].strip()


def _optional_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key, "")
    if value == "":
        return ""
    if not isinstance(value, str):
        raise AutomationValidationError(f"{key} must be a string when provided")
    return value.strip()


def _safe_label(label: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in label)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _summarize_result_findings(job_name: str, result) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for record in result.records:
        final = record.final
        signature = _finding_signature(
            target=result.target.resolved_path,
            vuln_family=final.vuln_family,
            file_path=final.file,
            line=final.line,
            function_or_sink=final.function_or_sink,
            title=final.title,
            repro_command=final.repro_command,
        )
        findings.append(
            {
                "job_name": job_name,
                "run_id": result.run_id,
                "signature": signature,
                "title": final.title,
                "status": final.status.value,
                "vuln_family": final.vuln_family,
                "file": final.file,
                "line": final.line,
                "function_or_sink": final.function_or_sink,
                "severity_estimate": final.severity_estimate,
                "poc_status": final.poc_status,
                "evidence": final.evidence[:280],
            }
        )
    return findings


def _finding_signature(
    *,
    target: str,
    vuln_family: str,
    file_path: str,
    line: int | None,
    function_or_sink: str,
    title: str,
    repro_command: str,
) -> str:
    payload = "\n".join(
        [
            target,
            vuln_family,
            file_path,
            str(line or ""),
            function_or_sink,
            title,
            repro_command,
        ]
    )
    return sha1(payload.encode("utf-8")).hexdigest()


def _build_batch_metadata(
    jobs: list[BatchJobResult],
    previous_batch: BatchResult | None,
) -> dict[str, Any]:
    findings = [finding for job in jobs for finding in job.findings]
    signature_groups: dict[str, dict[str, Any]] = {}
    for finding in findings:
        group = signature_groups.setdefault(
            finding["signature"],
            {
                "signature": finding["signature"],
                "count": 0,
                "titles": set(),
                "jobs": set(),
                "statuses": Counter(),
            },
        )
        group["count"] += 1
        group["titles"].add(finding["title"])
        group["jobs"].add(finding["job_name"])
        group["statuses"][finding["status"]] += 1
    duplicate_groups = []
    for group in signature_groups.values():
        if group["count"] <= 1:
            continue
        duplicate_groups.append(
            {
                "signature": group["signature"],
                "count": group["count"],
                "titles": sorted(group["titles"]),
                "jobs": sorted(group["jobs"]),
                "statuses": dict(group["statuses"]),
            }
        )
    current_signatures = set(signature_groups)
    previous_signatures = _signature_set(previous_batch)
    new_signatures = sorted(current_signatures - previous_signatures)
    resolved_signatures = sorted(previous_signatures - current_signatures)
    repeated_signatures = sorted(current_signatures & previous_signatures)
    return {
        "dedup": {
            "total_findings": len(findings),
            "unique_findings": len(current_signatures),
            "duplicate_findings": len(findings) - len(current_signatures),
            "groups": sorted(duplicate_groups, key=lambda item: (-item["count"], item["signature"])),
        },
        "comparison": {
            "previous_batch_id": previous_batch.batch_id if previous_batch else "",
            "new_count": len(new_signatures),
            "resolved_count": len(resolved_signatures),
            "repeated_count": len(repeated_signatures),
            "new_signatures": new_signatures,
            "resolved_signatures": resolved_signatures,
            "repeated_signatures": repeated_signatures,
        },
    }


def _signature_set(batch: BatchResult | None) -> set[str]:
    if not batch:
        return set()
    signatures: set[str] = set()
    for job in batch.jobs:
        for finding in job.findings:
            signatures.add(finding["signature"])
    return signatures


def _latest_batch_by_name(runs_dir: str, name: str) -> BatchResult | None:
    for batch in list_batches(runs_dir):
        if batch.name == name:
            return batch
    return None
