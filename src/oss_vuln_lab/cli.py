from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

from oss_vuln_lab.automation import (
    BatchRunner,
    ScheduleRunner,
    list_batches,
    load_batch_result,
)
from oss_vuln_lab.config import load_config
from oss_vuln_lab.corpus import CorpusStore
from oss_vuln_lab.dashboard import serve_dashboard, write_dashboard
from oss_vuln_lab.impact import (
    ImpactRunner,
    list_impact_reports,
    load_impact_report,
)
from oss_vuln_lab.models import ArtifactEncoding
from oss_vuln_lab.pipeline import ScanEngine
from oss_vuln_lab.registry import build_default_registry


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="Path to TOML configuration file", default=argparse.SUPPRESS)
    common.add_argument("--runs-dir", help="Override directory used to store scan runs", default=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(prog="ovl", description="Local-first OSS vulnerability research lab")
    parser.add_argument("--config", help="Path to TOML configuration file", default=argparse.SUPPRESS)
    parser.add_argument("--runs-dir", help="Override directory used to store scan runs", default=argparse.SUPPRESS)

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a repository or binary artifact", parents=[common])
    scan.add_argument("target", help="Local path or Git URL")

    triage = subparsers.add_parser("triage", help="Re-run analysis for one finding", parents=[common])
    triage.add_argument("run_id", help="Run directory name or path")
    triage.add_argument("finding_id", help="Finding identifier")

    repro = subparsers.add_parser("repro", help="Re-run validators for one finding", parents=[common])
    repro.add_argument("run_id", help="Run directory name or path")
    repro.add_argument("finding_id", help="Finding identifier")

    verify_known = subparsers.add_parser(
        "verify-known",
        help="Replay an imported known PoC against a target",
        parents=[common],
    )
    verify_known.add_argument("target", help="Local path or Git URL")
    verify_known.add_argument("--title", required=True, help="Human-readable finding title")
    verify_known.add_argument("--vuln-family", required=True, help="Builtin or custom vulnerability family name")
    verify_known.add_argument("--repro-command", required=True, help="Command template using @payload_path@ or other placeholders")
    verify_known.add_argument("--artifact-name", help="Artifact filename to write under the run directory")
    artifact_group = verify_known.add_mutually_exclusive_group(required=True)
    artifact_group.add_argument("--artifact-file", help="Import artifact bytes from a local file")
    artifact_group.add_argument("--artifact-text", help="Inline text artifact content")
    artifact_group.add_argument("--artifact-base64", help="Inline base64-encoded artifact content")
    verify_known.add_argument("--severity", default="high", help="Severity hint for the imported finding")
    verify_known.add_argument("--candidate-file", default="", help="Source file associated with the known PoC")
    verify_known.add_argument("--candidate-line", type=int, help="Line number associated with the known PoC")
    verify_known.add_argument("--function-or-sink", default="known_poc", help="Relevant function or sink name")
    verify_known.add_argument("--notes", default="", help="Optional notes captured in the finding record")
    verify_known.add_argument(
        "--configure-arg",
        action="append",
        default=[],
        help="Extra argument appended to ./configure for configure-based projects",
    )

    report = subparsers.add_parser("report", help="Re-render run reports", parents=[common])
    report.add_argument("run_id", help="Run directory name or path")

    corpus = subparsers.add_parser("corpus", help="Inspect local CVE replay corpus", parents=[common])
    corpus_subparsers = corpus.add_subparsers(dest="corpus_command", required=True)
    corpus_subparsers.add_parser("list", help="List local corpus records", parents=[common])
    show = corpus_subparsers.add_parser("show", help="Show one corpus record", parents=[common])
    show.add_argument("cve_id", help="CVE or alias to inspect")

    replay = subparsers.add_parser("replay", help="Replay a CVE or replay manifest", parents=[common])
    replay_subparsers = replay.add_subparsers(dest="replay_command", required=True)
    replay_cve = replay_subparsers.add_parser("cve", help="Replay a local corpus CVE against a target", parents=[common])
    replay_cve.add_argument("target", help="Local path or Git URL")
    replay_cve.add_argument("cve_id", help="CVE or alias to replay")
    replay_manifest = replay_subparsers.add_parser("manifest", help="Replay an explicit manifest file against a target", parents=[common])
    replay_manifest.add_argument("target", help="Local path or Git URL")
    replay_manifest.add_argument("manifest", help="Manifest path, absolute or relative to corpus_dir")

    ui = subparsers.add_parser("ui", help="Build or serve a local dashboard", parents=[common])
    ui_subparsers = ui.add_subparsers(dest="ui_command", required=True)
    ui_build = ui_subparsers.add_parser("build", help="Build a static dashboard", parents=[common])
    ui_build.add_argument("--output-dir", help="Directory to write the dashboard into", default="")
    ui_serve = ui_subparsers.add_parser("serve", help="Serve the local dashboard over HTTP", parents=[common])
    ui_serve.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    ui_serve.add_argument("--port", default=8765, type=int, help="Port to bind")

    batch = subparsers.add_parser("batch", help="Run or inspect local batch manifests", parents=[common])
    batch_subparsers = batch.add_subparsers(dest="batch_command", required=True)
    batch_run = batch_subparsers.add_parser("run", help="Execute a batch manifest", parents=[common])
    batch_run.add_argument("manifest", help="Path to a batch JSON manifest")
    batch_subparsers.add_parser("list", help="List recorded batch executions", parents=[common])
    batch_show = batch_subparsers.add_parser("show", help="Show one batch execution", parents=[common])
    batch_show.add_argument("batch_id", help="Batch directory name or path")

    schedule = subparsers.add_parser("schedule", help="Run or inspect local schedules", parents=[common])
    schedule_subparsers = schedule.add_subparsers(dest="schedule_command", required=True)
    schedule_once = schedule_subparsers.add_parser("once", help="Evaluate a schedule once", parents=[common])
    schedule_once.add_argument("manifest", help="Path to a schedule JSON manifest")
    schedule_once.add_argument("--at", help="ISO timestamp used instead of current time", default="")
    schedule_run = schedule_subparsers.add_parser("run", help="Run the polling scheduler loop", parents=[common])
    schedule_run.add_argument("manifest", help="Path to a schedule JSON manifest")
    schedule_run.add_argument("--iterations", type=int, default=0, help="Number of polling iterations; 0 means run forever")
    schedule_run.add_argument("--poll-seconds", type=int, default=60, help="Seconds to sleep between iterations")
    schedule_show = schedule_subparsers.add_parser("show", help="Show saved state for a schedule manifest", parents=[common])
    schedule_show.add_argument("manifest", help="Path to a schedule JSON manifest")

    impact = subparsers.add_parser("impact", help="Plan or assess advisory impact across versions", parents=[common])
    impact_subparsers = impact.add_subparsers(dest="impact_command", required=True)
    impact_plan = impact_subparsers.add_parser("plan", help="Resolve impact manifest version targets", parents=[common])
    impact_plan.add_argument("manifest", help="Path to an impact JSON manifest")
    impact_plan.add_argument("--allow-network", action="store_true", help="Allow configured public intelligence and network Git access")
    impact_assess = impact_subparsers.add_parser("assess", help="Assess version impact and write an impact report", parents=[common])
    impact_assess.add_argument("manifest", help="Path to an impact JSON manifest")
    impact_assess.add_argument("--allow-network", action="store_true", help="Allow configured public intelligence and network Git access")
    impact_assess.add_argument(
        "--execute-discovered-poc",
        action="store_true",
        help="Allow execution of supported discovered PoC command templates",
    )
    impact_assess.add_argument(
        "--execute-generated-poc",
        action="store_true",
        help="Allow generated PoC execution through configured validators",
    )
    impact_subparsers.add_parser("list", help="List recorded impact assessments", parents=[common])
    impact_show = impact_subparsers.add_parser("show", help="Show one impact assessment", parents=[common])
    impact_show.add_argument("impact_id", help="Impact directory name or path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = load_config(getattr(args, "config", None))
    if hasattr(args, "runs_dir"):
        config.runs_dir = args.runs_dir

    engine = ScanEngine(config=config, registry=build_default_registry())
    batch_runner = BatchRunner(engine)
    schedule_runner = ScheduleRunner(engine)
    impact_runner = ImpactRunner(engine)

    try:
        if args.command == "scan":
            result = engine.scan(args.target)
            _print_scan_summary(result.run_id, len(result.records), Path(result.run_dir))
            return 0
        if args.command == "triage":
            result = engine.triage(args.run_id, args.finding_id)
            print(f"Updated analysis for {args.finding_id} in run {result.run_id}")
            return 0
        if args.command == "repro":
            result = engine.repro(args.run_id, args.finding_id)
            print(f"Updated validation for {args.finding_id} in run {result.run_id}")
            return 0
        if args.command == "verify-known":
            artifact_name, artifact_content, artifact_encoding = _load_known_artifact(args)
            result = engine.verify_known(
                target_spec=args.target,
                title=args.title,
                vuln_family=args.vuln_family,
                repro_command=args.repro_command,
                artifact_name=artifact_name,
                artifact_content=artifact_content,
                artifact_encoding=artifact_encoding,
                severity_hint=args.severity,
                file_path=args.candidate_file,
                line=args.candidate_line,
                function_or_sink=args.function_or_sink,
                notes=args.notes,
                configure_extra_args=args.configure_arg,
            )
            _print_scan_summary(result.run_id, len(result.records), Path(result.run_dir))
            return 0
        if args.command == "report":
            result = engine.report(args.run_id)
            print(f"Re-rendered reports for run {result.run_id}")
            return 0
        if args.command == "corpus":
            store = CorpusStore(config.corpus_dir)
            if args.corpus_command == "list":
                _print_corpus_list(store)
                return 0
            if args.corpus_command == "show":
                record = store.load_record(args.cve_id)
                _print_corpus_record(record)
                return 0
        if args.command == "replay":
            if args.replay_command == "cve":
                result = engine.replay_cve(args.target, args.cve_id)
                _print_scan_summary(result.run_id, len(result.records), Path(result.run_dir))
                return 0
            if args.replay_command == "manifest":
                result = engine.replay_manifest(args.target, args.manifest)
                _print_scan_summary(result.run_id, len(result.records), Path(result.run_dir))
                return 0
        if args.command == "ui":
            if args.ui_command == "build":
                output_path = write_dashboard(config.runs_dir, args.output_dir or None, config.corpus_dir)
                print(f"Dashboard: {output_path}")
                return 0
            if args.ui_command == "serve":
                serve_dashboard(config.runs_dir, args.host, args.port, config.corpus_dir)
                return 0
        if args.command == "batch":
            if args.batch_command == "run":
                batch = batch_runner.run_manifest(args.manifest)
                _print_batch_summary(batch)
                return 0
            if args.batch_command == "list":
                _print_batch_list(config.runs_dir)
                return 0
            if args.batch_command == "show":
                batch = load_batch_result(args.batch_id, config.runs_dir)
                _print_batch_detail(batch)
                return 0
        if args.command == "schedule":
            if args.schedule_command == "once":
                when = _parse_when(args.at)
                result = schedule_runner.run_once(args.manifest, now=when)
                _print_schedule_summary(result)
                return 0
            if args.schedule_command == "run":
                results = schedule_runner.run_loop(
                    args.manifest,
                    iterations=args.iterations,
                    poll_seconds=args.poll_seconds,
                )
                for item in results:
                    _print_schedule_summary(item)
                return 0
            if args.schedule_command == "show":
                state = schedule_runner.show_state(args.manifest)
                _print_schedule_state(state)
                return 0
        if args.command == "impact":
            if args.impact_command == "plan":
                plan = impact_runner.plan_manifest(args.manifest, allow_network=args.allow_network)
                _print_impact_plan(plan)
                return 0
            if args.impact_command == "assess":
                report = impact_runner.assess_manifest(
                    args.manifest,
                    allow_network=args.allow_network,
                    execute_discovered_poc=args.execute_discovered_poc,
                    execute_generated_poc=args.execute_generated_poc,
                )
                _print_impact_summary(report, config.runs_dir)
                return 0
            if args.impact_command == "list":
                _print_impact_list(config.runs_dir)
                return 0
            if args.impact_command == "show":
                report = load_impact_report(args.impact_id, config.runs_dir)
                _print_impact_detail(report, config.runs_dir)
                return 0
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1

    parser.error(f"Unhandled command: {args.command}")
    return 2


def _print_scan_summary(run_id: str, finding_count: int, run_dir: Path) -> None:
    print(f"Run ID: {run_id}")
    print(f"Findings: {finding_count}")
    print(f"Artifacts: {run_dir}")


def _print_batch_summary(batch) -> None:
    completed = sum(1 for item in batch.jobs if item.status == "completed")
    failed = sum(1 for item in batch.jobs if item.status == "failed")
    print(f"Batch ID: {batch.batch_id}")
    print(f"Name: {batch.name}")
    print(f"Jobs: {len(batch.jobs)}")
    print(f"Completed: {completed}")
    print(f"Failed: {failed}")
    dedup = dict(batch.metadata.get("dedup", {}))
    comparison = dict(batch.metadata.get("comparison", {}))
    if dedup:
        print(f"Unique Findings: {dedup.get('unique_findings', 0)}")
        print(f"Duplicate Findings: {dedup.get('duplicate_findings', 0)}")
    if comparison:
        print(f"Previous Batch: {comparison.get('previous_batch_id') or 'n/a'}")
        print(f"New Findings: {comparison.get('new_count', 0)}")
        print(f"Resolved Findings: {comparison.get('resolved_count', 0)}")
        print(f"Repeated Findings: {comparison.get('repeated_count', 0)}")


def _print_batch_list(runs_dir: str) -> None:
    batches = list_batches(runs_dir)
    if not batches:
        print("No batch runs found.")
        return
    for batch in batches:
        completed = sum(1 for item in batch.jobs if item.status == "completed")
        failed = sum(1 for item in batch.jobs if item.status == "failed")
        print(f"{batch.batch_id}\t{batch.name}\t{completed}/{len(batch.jobs)} completed\t{failed} failed")


def _print_batch_detail(batch) -> None:
    _print_batch_summary(batch)
    for job in batch.jobs:
        print(f"- {job.name}: {job.mode} -> {job.status} ({job.run_id or job.error or 'n/a'})")
        for finding in job.findings[:3]:
            print(f"  finding {finding['signature'][:12]} {finding['status']} {finding['title']}")


def _print_corpus_list(store: CorpusStore) -> None:
    records = store.list_records()
    if not records:
        print("No corpus records found.")
        return
    for record in records:
        print(f"{record.cve_id}\t{record.project}\t{record.language.value}\t{record.summary}")


def _print_corpus_record(record) -> None:
    print(f"CVE: {record.cve_id}")
    print(f"Project: {record.project}")
    print(f"Language: {record.language.value}")
    print(f"Family: {record.vuln_family}")
    print(f"Summary: {record.summary}")
    print(f"Replay: {record.replay.repro_command}")
    if record.references:
        print("References:")
        for ref in record.references:
            print(f"- {ref}")


def _load_known_artifact(args: argparse.Namespace) -> tuple[str, str, ArtifactEncoding]:
    if getattr(args, "artifact_file", None):
        path = Path(args.artifact_file)
        name = args.artifact_name or path.name
        content = path.read_bytes()
        try:
            return name, content.decode("utf-8"), ArtifactEncoding.TEXT
        except UnicodeDecodeError:
            import base64

            return name, base64.b64encode(content).decode("ascii"), ArtifactEncoding.BASE64
    if getattr(args, "artifact_text", None) is not None:
        return args.artifact_name or "payload.txt", args.artifact_text, ArtifactEncoding.TEXT
    if getattr(args, "artifact_base64", None) is not None:
        if not args.artifact_name:
            _die("--artifact-name is required with --artifact-base64")
        return args.artifact_name, args.artifact_base64, ArtifactEncoding.BASE64
    _die("one artifact source must be supplied")


def _die(message: str) -> NoReturn:
    raise SystemExit(message)


def _parse_when(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _print_schedule_summary(result) -> None:
    print(f"Schedule: {result.schedule_name}")
    print(f"Evaluated: {result.evaluated_at}")
    print(f"Due Tasks: {len(result.due_tasks)}")
    if result.due_tasks:
        print("Tasks:")
        for task in result.due_tasks:
            print(f"- {task}")
    if result.batch_result:
        print(f"Batch ID: {result.batch_result.batch_id}")
    else:
        print("Batch ID: n/a")


def _print_schedule_state(state: dict[str, object]) -> None:
    if not state:
        print("No schedule state found.")
        return
    print(f"Schedule: {state.get('schedule_name', 'unknown')}")
    print(f"Evaluated: {state.get('evaluated_at', 'unknown')}")
    tasks = state.get("tasks", {})
    if not tasks:
        print("No task state recorded.")
        return
    print("Tasks:")
    for name, payload in dict(tasks).items():
        info = dict(payload)
        print(f"- {name}: last_run_at={info.get('last_run_at', 'never')} last_batch_id={info.get('last_batch_id', 'n/a')}")


def _print_impact_plan(plan) -> None:
    print(f"Impact: {plan.manifest.name}")
    print(f"Advisory: {plan.manifest.advisory.id}")
    print(f"Versions: {len(plan.targets)}")
    for target in plan.targets:
        print(f"- {target.version}\t{target.ref}\t{target.role or 'n/a'}\t{target.source}")


def _print_impact_summary(report, runs_dir: str) -> None:
    counts = _impact_status_counts(report)
    print(f"Impact ID: {report.impact_id}")
    print(f"Name: {report.name}")
    print(f"Advisory: {report.advisory.id}")
    print(f"Versions: {len(report.versions)}")
    for status, count in sorted(counts.items()):
        print(f"{status}: {count}")
    print(f"Artifacts: {Path(runs_dir).expanduser().resolve() / 'impacts' / report.impact_id}")


def _print_impact_list(runs_dir: str) -> None:
    reports = list_impact_reports(runs_dir)
    if not reports:
        print("No impact reports found.")
        return
    for report in reports:
        counts = _impact_status_counts(report)
        count_text = ", ".join(f"{status}={count}" for status, count in sorted(counts.items())) or "no versions"
        print(f"{report.impact_id}\t{report.name}\t{report.advisory.id}\t{count_text}")


def _print_impact_detail(report, runs_dir: str) -> None:
    _print_impact_summary(report, runs_dir)
    print("Version Matrix:")
    for version in report.versions:
        run = version.run_id or "n/a"
        print(f"- {version.version}: {version.status.value} ref={version.ref} role={version.role or 'n/a'} run={run}")


def _impact_status_counts(report) -> dict[str, int]:
    counts: dict[str, int] = {}
    for version in report.versions:
        counts[version.status.value] = counts.get(version.status.value, 0) + 1
    return counts
