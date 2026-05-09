from __future__ import annotations

from collections import Counter
from functools import partial
from html import escape
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any

from oss_vuln_digger.automation import BATCHES_DIR_NAME, BATCH_STATE_FILE
from oss_vuln_digger.corpus import CorpusStore
from oss_vuln_digger.models import ensure_directory
from oss_vuln_digger.storage import REPORT_JSON, STATE_FILE


def load_run_reports(runs_dir: str) -> list[dict[str, Any]]:
    base_dir = Path(runs_dir).expanduser().resolve()
    if not base_dir.exists():
        return []
    reports: list[dict[str, Any]] = []
    for path in sorted(base_dir.iterdir(), reverse=True):
        if not path.is_dir() or path.name == BATCHES_DIR_NAME:
            continue
        state_path = path / STATE_FILE
        report_path = path / REPORT_JSON
        if not state_path.exists():
            continue
        data = json.loads(state_path.read_text(encoding="utf-8"))
        findings = list(data.get("records", []))
        status_counts = Counter(item.get("final", {}).get("status", "unknown") for item in findings)
        reports.append(
            {
                "run_id": data["run_id"],
                "created_at": data["created_at"],
                "target": data["target"]["resolved_path"],
                "language": data["project"]["language_profiles"][0]["name"]
                if data["project"].get("language_profiles")
                else data["project"].get("metadata", {}).get("language", "unknown"),
                "adapter_name": data["project"]["adapter_name"],
                "finding_count": len(findings),
                "status_counts": dict(status_counts),
                "findings": [_extract_run_finding(item) for item in findings],
                "report_json": f"../{path.name}/{REPORT_JSON}",
                "report_md": f"../{path.name}/report.md",
                "run_json": f"../{path.name}/{STATE_FILE}",
            }
        )
    return sorted(reports, key=lambda item: item["created_at"], reverse=True)


def load_batch_reports(runs_dir: str) -> list[dict[str, Any]]:
    batches_dir = Path(runs_dir).expanduser().resolve() / BATCHES_DIR_NAME
    if not batches_dir.exists():
        return []
    reports: list[dict[str, Any]] = []
    for path in sorted(batches_dir.iterdir(), reverse=True):
        if not path.is_dir():
            continue
        state_path = path / BATCH_STATE_FILE
        if not state_path.exists():
            continue
        data = json.loads(state_path.read_text(encoding="utf-8"))
        job_statuses = Counter(item.get("status", "unknown") for item in data.get("jobs", []))
        dedup = dict(data.get("metadata", {}).get("dedup", {}))
        comparison = dict(data.get("metadata", {}).get("comparison", {}))
        reports.append(
            {
                "batch_id": data["batch_id"],
                "created_at": data["created_at"],
                "name": data["name"],
                "job_count": len(data.get("jobs", [])),
                "job_statuses": dict(job_statuses),
                "jobs": list(data.get("jobs", [])),
                "dedup": dedup,
                "comparison": comparison,
                "batch_json": f"../{BATCHES_DIR_NAME}/{path.name}/{BATCH_STATE_FILE}",
                "batch_md": f"../{BATCHES_DIR_NAME}/{path.name}/batch.md",
            }
        )
    return sorted(reports, key=lambda item: item["created_at"], reverse=True)


def render_dashboard_html(runs_dir: str, corpus_dir: str = "") -> str:
    runs = load_run_reports(runs_dir)
    batches = load_batch_reports(runs_dir)
    corpus = load_corpus_summaries(corpus_dir) if corpus_dir else []
    return "\n".join(
        [
            "<!doctype html>",
            "<html lang='en'>",
            "<head>",
            "  <meta charset='utf-8'>",
            "  <meta name='viewport' content='width=device-width, initial-scale=1'>",
            "  <title>oss-vuln-digger dashboard</title>",
            "  <style>",
            "    :root { color-scheme: light; --bg: #f6f4ee; --fg: #202124; --muted: #5f6368; --card: #ffffff; --line: #d9d2c4; --accent: #126b52; --warn: #8b3a1e; }",
            "    body { margin: 0; font-family: 'Iowan Old Style', 'Palatino Linotype', serif; background: radial-gradient(circle at top left, #fff8e7 0, var(--bg) 45%, #ece9de 100%); color: var(--fg); }",
            "    main { max-width: 1180px; margin: 0 auto; padding: 32px 20px 60px; }",
            "    h1, h2 { margin: 0; }",
            "    p { color: var(--muted); }",
            "    .hero { display: grid; gap: 12px; margin-bottom: 28px; }",
            "    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 18px 0 30px; }",
            "    .stat, .card { background: color-mix(in srgb, var(--card) 92%, #fff 8%); border: 1px solid var(--line); border-radius: 18px; padding: 16px; box-shadow: 0 10px 30px rgba(30, 25, 15, 0.06); }",
            "    .section { margin-top: 28px; }",
            "    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; margin-top: 12px; }",
            "    .eyebrow { text-transform: uppercase; letter-spacing: 0.08em; font-size: 12px; color: var(--accent); font-weight: 700; }",
            "    .meta { display: flex; flex-wrap: wrap; gap: 8px 12px; margin: 12px 0; color: var(--muted); font-size: 14px; }",
            "    .badge { display: inline-block; border-radius: 999px; padding: 4px 10px; background: #e8efe9; color: var(--accent); font-size: 12px; margin-right: 6px; margin-bottom: 6px; }",
            "    .badge.warn { background: #f6e9e3; color: var(--warn); }",
            "    a { color: var(--accent); text-decoration: none; }",
            "    a:hover { text-decoration: underline; }",
            "    .links { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 12px; }",
            "    details { margin-top: 14px; border-top: 1px dashed var(--line); padding-top: 12px; }",
            "    summary { cursor: pointer; font-weight: 700; color: var(--accent); }",
            "    .finding { margin-top: 12px; padding: 12px; border: 1px solid var(--line); border-radius: 14px; background: #fcfbf7; }",
            "    .finding h3 { margin: 0 0 8px; font-size: 17px; }",
            "    .finding p { margin: 8px 0; }",
            "    .finding pre { margin: 8px 0 0; padding: 10px; background: #1c1b1a; color: #f8f6f0; border-radius: 10px; overflow-x: auto; white-space: pre-wrap; }",
            "  </style>",
            "</head>",
            "<body>",
            "<main>",
            "  <section class='hero'>",
            "    <div class='eyebrow'>Local Dashboard</div>",
            "    <h1>oss-vuln-digger</h1>",
            "    <p>Run inspection for the local research kernel, local UI, and batch automation layers.</p>",
            "  </section>",
            "  <section class='stats'>",
            f"    <div class='stat'><div class='eyebrow'>Runs</div><h2>{len(runs)}</h2><p>Recorded kernel runs under the local runs directory.</p></div>",
            f"    <div class='stat'><div class='eyebrow'>Batches</div><h2>{len(batches)}</h2><p>Batch and schedule executions captured for local automation.</p></div>",
            f"    <div class='stat'><div class='eyebrow'>Findings</div><h2>{sum(item['finding_count'] for item in runs)}</h2><p>Total findings across the visible run set.</p></div>",
            f"    <div class='stat'><div class='eyebrow'>Corpus</div><h2>{len(corpus)}</h2><p>Local corpus records available for replay-backed inspection.</p></div>",
            "  </section>",
            "  <section class='section'>",
            "    <div class='eyebrow'>Runs</div>",
            "    <div class='grid'>",
            *(_render_run_card(item) for item in runs),
            "    </div>",
            "  </section>",
            "  <section class='section'>",
            "    <div class='eyebrow'>Batches</div>",
            "    <div class='grid'>",
            *(_render_batch_card(item) for item in batches),
            "    </div>",
            "  </section>",
            "  <section class='section'>",
            "    <div class='eyebrow'>Corpus</div>",
            "    <div class='grid'>",
            *(_render_corpus_card(item) for item in corpus),
            "    </div>",
            "  </section>",
            "</main>",
            "</body>",
            "</html>",
        ]
    )


def write_dashboard(runs_dir: str, output_dir: str | None = None, corpus_dir: str = "") -> Path:
    base_dir = Path(runs_dir).expanduser().resolve()
    target_dir = Path(output_dir).expanduser().resolve() if output_dir else ensure_directory(base_dir / "dashboard")
    ensure_directory(target_dir)
    output_path = target_dir / "index.html"
    output_path.write_text(render_dashboard_html(runs_dir, corpus_dir), encoding="utf-8")
    return output_path


def serve_dashboard(runs_dir: str, host: str, port: int, corpus_dir: str = "") -> None:
    base_dir = Path(runs_dir).expanduser().resolve()
    write_dashboard(str(base_dir), corpus_dir=corpus_dir)
    handler = partial(SimpleHTTPRequestHandler, directory=str(base_dir))
    with ThreadingHTTPServer((host, port), handler) as server:
        print(f"Serving dashboard at http://{host}:{port}/dashboard/index.html")
        server.serve_forever()


def load_corpus_summaries(corpus_dir: str) -> list[dict[str, Any]]:
    records = CorpusStore(corpus_dir).list_records()
    return [
        {
            "cve_id": record.cve_id,
            "project": record.project,
            "language": record.language.value,
            "vuln_family": record.vuln_family,
            "summary": record.summary,
            "replay_command": record.replay.repro_command,
        }
        for record in sorted(records, key=lambda item: item.cve_id)
    ]


def _render_run_card(item: dict[str, Any]) -> str:
    badges = "".join(
        f"<span class='badge'>{escape(name)}: {count}</span>"
        for name, count in sorted(item["status_counts"].items())
    ) or "<span class='badge warn'>No findings</span>"
    return "\n".join(
        [
            "      <article class='card'>",
            f"        <div class='eyebrow'>{escape(item['language'])}</div>",
            f"        <h2>{escape(item['run_id'])}</h2>",
            "        <div class='meta'>",
            f"          <span>{escape(item['created_at'])}</span>",
            f"          <span>{escape(item['adapter_name'])}</span>",
            f"          <span>{escape(str(item['finding_count']))} findings</span>",
            "        </div>",
            f"        <p>{escape(item['target'])}</p>",
            f"        <div>{badges}</div>",
            "        <div class='links'>",
            f"          <a href='{escape(item['report_md'])}'>Markdown</a>",
            f"          <a href='{escape(item['report_json'])}'>JSON</a>",
            f"          <a href='{escape(item['run_json'])}'>State</a>",
            "        </div>",
            _render_run_details(item["findings"]),
            "      </article>",
        ]
    )


def _render_batch_card(item: dict[str, Any]) -> str:
    badges = "".join(
        f"<span class='badge'>{escape(name)}: {count}</span>"
        for name, count in sorted(item["job_statuses"].items())
    ) or "<span class='badge warn'>No jobs</span>"
    return "\n".join(
        [
            "      <article class='card'>",
            "        <div class='eyebrow'>Batch</div>",
            f"        <h2>{escape(item['name'])}</h2>",
            "        <div class='meta'>",
            f"          <span>{escape(item['created_at'])}</span>",
            f"          <span>{escape(str(item['job_count']))} jobs</span>",
            "        </div>",
            f"        <p>{escape(item['batch_id'])}</p>",
            f"        <div>{badges}</div>",
            "        <div class='links'>",
            f"          <a href='{escape(item['batch_md'])}'>Markdown</a>",
            f"          <a href='{escape(item['batch_json'])}'>JSON</a>",
            "        </div>",
            _render_batch_details(item),
            "      </article>",
        ]
    )


def _render_corpus_card(item: dict[str, Any]) -> str:
    return "\n".join(
        [
            "      <article class='card'>",
            f"        <div class='eyebrow'>{escape(item['language'])}</div>",
            f"        <h2>{escape(item['cve_id'])}</h2>",
            "        <div class='meta'>",
            f"          <span>{escape(item['project'])}</span>",
            f"          <span>{escape(item['vuln_family'])}</span>",
            "        </div>",
            f"        <p>{escape(item['summary'])}</p>",
            f"        <div class='links'><span>{escape(item['replay_command'])}</span></div>",
            "      </article>",
        ]
    )


def _extract_run_finding(record: dict[str, Any]) -> dict[str, Any]:
    final = dict(record.get("final", {}))
    validations = list(record.get("validations", []))
    return {
        "title": final.get("title", "unknown"),
        "status": final.get("status", "unknown"),
        "poc_status": final.get("poc_status", "not_run"),
        "vuln_family": final.get("vuln_family", "unknown"),
        "location": _finding_location(final),
        "function_or_sink": final.get("function_or_sink", ""),
        "evidence": final.get("evidence", ""),
        "validations": [
            {
                "validator_name": item.get("validator_name", "unknown"),
                "status": item.get("status", "unknown"),
                "summary": item.get("summary", ""),
                "evidence_labels": [entry.get("label", "") for entry in item.get("evidence_items", [])],
            }
            for item in validations
        ],
    }


def _finding_location(final: dict[str, Any]) -> str:
    location = str(final.get("file", ""))
    if final.get("line") is not None:
        location = f"{location}:{final['line']}"
    return location


def _render_run_details(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return ""
    blocks = ["        <details>", f"          <summary>Findings and evidence ({len(findings)})</summary>"]
    for finding in findings:
        validations = "".join(
            f"<div class='badge'>{escape(item['validator_name'])}: {escape(item['status'])}</div>"
            for item in finding["validations"]
        ) or "<div class='badge warn'>No validator details</div>"
        validation_notes = "".join(
            f"<p>{escape(item['summary'])}</p>"
            for item in finding["validations"][:3]
        )
        blocks.extend(
            [
                "          <div class='finding'>",
                f"            <h3>{escape(finding['title'])}</h3>",
                f"            <div class='meta'><span>{escape(finding['status'])}</span><span>{escape(finding['poc_status'])}</span><span>{escape(finding['vuln_family'])}</span></div>",
                f"            <p>{escape(finding['location'])} · {escape(finding['function_or_sink'])}</p>",
                f"            <div>{validations}</div>",
                validation_notes,
                f"            <pre>{escape((finding['evidence'] or 'No evidence captured.')[:480])}</pre>",
                "          </div>",
            ]
        )
    blocks.append("        </details>")
    return "\n".join(blocks)


def _render_batch_details(item: dict[str, Any]) -> str:
    dedup = dict(item.get("dedup", {}))
    comparison = dict(item.get("comparison", {}))
    jobs = list(item.get("jobs", []))
    blocks = ["        <details>", "          <summary>Review batch details</summary>"]
    if comparison:
        blocks.extend(
            [
                "          <div class='finding'>",
                "            <h3>Regression comparison</h3>",
                f"            <p>Previous batch: {escape(comparison.get('previous_batch_id') or 'none')}</p>",
                f"            <div class='meta'><span>new {comparison.get('new_count', 0)}</span><span>resolved {comparison.get('resolved_count', 0)}</span><span>repeated {comparison.get('repeated_count', 0)}</span></div>",
                "          </div>",
            ]
        )
    if dedup:
        blocks.extend(
            [
                "          <div class='finding'>",
                "            <h3>Deduplication</h3>",
                f"            <div class='meta'><span>unique {dedup.get('unique_findings', 0)}</span><span>duplicates {dedup.get('duplicate_findings', 0)}</span></div>",
                "          </div>",
            ]
        )
        for group in dedup.get("groups", [])[:4]:
            blocks.extend(
                [
                    "          <div class='finding'>",
                    f"            <h3>{escape(group['signature'][:12])}</h3>",
                    f"            <p>count={group['count']} jobs={escape(', '.join(group['jobs']))}</p>",
                    f"            <p>{escape(', '.join(group['titles']))}</p>",
                    "          </div>",
                ]
            )
    for job in jobs[:4]:
        findings = list(job.get("findings", []))
        blocks.extend(
            [
                "          <div class='finding'>",
                f"            <h3>{escape(job.get('name', 'job'))}</h3>",
                f"            <div class='meta'><span>{escape(job.get('mode', 'unknown'))}</span><span>{escape(job.get('status', 'unknown'))}</span><span>{len(findings)} findings</span></div>",
            ]
        )
        if findings:
            blocks.extend(
                f"            <p>{escape(finding['status'])} · {escape(finding['title'])} · {escape(finding['signature'][:12])}</p>"
                for finding in findings[:3]
            )
        elif job.get("error"):
            blocks.append(f"            <pre>{escape(job['error'])}</pre>")
        blocks.append("          </div>")
    blocks.append("        </details>")
    return "\n".join(blocks)
