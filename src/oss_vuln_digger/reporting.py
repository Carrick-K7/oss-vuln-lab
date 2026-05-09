from __future__ import annotations

from pathlib import Path

from oss_vuln_digger.models import ScanResult
from oss_vuln_digger.storage import REPORT_MD


def render_markdown_report(result: ScanResult) -> str:
    lines = [
        "# Scan Report",
        "",
        f"- Run ID: `{result.run_id}`",
        f"- Target: `{result.target.resolved_path}`",
        f"- Adapter: `{result.project.adapter_name}`",
        f"- Build System: `{result.project.build_system}`",
        f"- Language: `{result.project.primary_language.value}`",
        "",
        "## Findings",
        "",
    ]

    if not result.records:
        lines.extend(["No findings were produced.", ""])
        return "\n".join(lines)

    for record in result.records:
        finding = record.final
        location = finding.file
        if finding.line:
            location = f"{location}:{finding.line}"
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- ID: `{finding.id}`",
                f"- Family: `{finding.vuln_family}`",
                f"- Status: `{finding.status.value}`",
                f"- PoC Source: `{finding.poc_source.value}`",
                f"- Validation Status: `{finding.poc_status}`",
                f"- Confidence: `{finding.confidence}`",
                f"- Location: `{location}`",
                f"- Function/Sink: `{finding.function_or_sink}`",
                f"- Trigger: {finding.trigger_condition}",
                f"- Attack Path: {finding.attack_path}",
                f"- Repro Command: `{finding.repro_command}`",
                f"- Fix: {finding.fix_recommendation}",
                "",
                "Evidence:",
                "",
                "```text",
                finding.evidence or "No validator evidence captured.",
                "```",
                "",
            ]
        )

    return "\n".join(lines)


def write_markdown_report(result: ScanResult) -> Path:
    report_path = Path(result.run_dir) / REPORT_MD
    report_path.write_text(render_markdown_report(result), encoding="utf-8")
    return report_path
