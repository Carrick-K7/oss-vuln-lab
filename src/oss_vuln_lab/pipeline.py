from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha1
from pathlib import Path
from typing import Any

from oss_vuln_lab.config import AppConfig
from oss_vuln_lab.corpus import CorpusStore
from oss_vuln_lab.loader import stage_target
from oss_vuln_lab.models import (
    AnalysisResult,
    ArtifactEncoding,
    ArtifactSpec,
    Candidate,
    CveCorpusRecord,
    FinalFinding,
    FindingRecord,
    FindingStatus,
    PocSource,
    PocSpec,
    ProjectContext,
    ScanResult,
    ValidationResult,
    ValidationStatus,
    ensure_directory,
)
from oss_vuln_lab.registry import Registry
from oss_vuln_lab.reporting import write_markdown_report
from oss_vuln_lab.safety import validate_simple_filename
from oss_vuln_lab.storage import create_run_dir, load_scan_result, write_scan_result


class ScanEngine:
    def __init__(self, config: AppConfig, registry: Registry):
        self.config = config
        self.registry = registry

    def scan(self, target_spec: str) -> ScanResult:
        label = Path(target_spec).name or "target"
        run_dir = create_run_dir(self.config.runs_dir, label)
        target = stage_target(target_spec, run_dir / "checkout")
        project = self.registry.resolve_project_adapter(target).prepare(target)
        provider = self.registry.build_provider(self.config.llm)

        records: list[FindingRecord] = []
        for plugin in self.registry.vuln_plugins_for_mode(target.mode):
            for candidate in plugin.extract_candidates(project):
                llm_context = plugin.build_llm_context(candidate, project)
                analysis = provider.analyze_candidate(llm_context)
                llm_context["analysis"] = analysis.to_dict()
                poc = provider.generate_poc(llm_context)
                fix = provider.suggest_fix(llm_context)
                artifact_dir = _write_poc_artifacts(run_dir, candidate, poc)
                validations = self._run_validators(plugin.suggest_validation_kinds(candidate), project, candidate, poc, artifact_dir)
                final = _make_final_finding(candidate, analysis, poc, validations, fix)
                records.append(FindingRecord(candidate=candidate, analysis=analysis, poc=poc, validations=validations, final=final))

        result = ScanResult(
            run_id=run_dir.name,
            created_at=datetime.now(timezone.utc).isoformat(),
            run_dir=str(run_dir),
            target=target,
            project=project,
            records=records,
        )
        write_scan_result(result)
        write_markdown_report(result)
        return result

    def verify_known(
        self,
        target_spec: str,
        title: str,
        vuln_family: str,
        repro_command: str,
        artifact_name: str = "",
        artifact_content: str = "",
        artifact_encoding: ArtifactEncoding = ArtifactEncoding.TEXT,
        *,
        artifacts: list[ArtifactSpec] | None = None,
        severity_hint: str = "high",
        file_path: str = "",
        line: int | None = None,
        function_or_sink: str = "known_poc",
        notes: str = "",
        configure_extra_args: list[str] | None = None,
        runtime_env: dict[str, str] | None = None,
        validation_hints: list[str] | None = None,
        result_metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        label = Path(target_spec).name or "target"
        run_dir = create_run_dir(self.config.runs_dir, f"known-{label}")
        target = stage_target(target_spec, run_dir / "checkout")
        project = self.registry.resolve_project_adapter(target).prepare(target)
        if configure_extra_args:
            project.metadata["configure_extra_args"] = list(configure_extra_args)
        known_artifacts = list(artifacts or [])
        if not known_artifacts:
            if not artifact_name:
                raise ValueError("verify_known requires either artifacts or artifact_name/artifact_content inputs")
            known_artifacts = [ArtifactSpec(name=artifact_name, content=artifact_content, encoding=artifact_encoding)]
        primary_artifact = known_artifacts[0]
        candidate = _make_known_candidate(
            title=title,
            vuln_family=vuln_family,
            project=project,
            severity_hint=severity_hint,
            file_path=file_path or (project.source_files[0] if project.source_files else project.root),
            line=line,
            function_or_sink=function_or_sink,
            notes=notes,
        )
        analysis = AnalysisResult(
            root_cause=notes or "Imported known PoC replay.",
            trigger_condition="Replay the supplied known PoC against the selected target.",
            input_shape=f"External artifact `{primary_artifact.name}` supplied by the operator.",
            reachability_reason="Known-PoC verification mode bypasses candidate discovery and replays a supplied trigger.",
            exploit_strategy="Use the supplied PoC artifact and explicit repro command to validate impact.",
            confidence="high",
            patch_direction="Fix guidance is not inferred automatically in known-PoC verification mode.",
        )
        poc = PocSpec(
            description="Imported known PoC replay",
            repro_command=repro_command,
            input_payload=f"<{primary_artifact.encoding.value} artifact:{primary_artifact.name}>",
            source=PocSource.KNOWN,
            artifacts=known_artifacts,
            validation_hints=validation_hints or ["docker_build", "sanitizer_runtime", "host_build", "host_sanitizer_runtime", "direct_runtime"],
            runtime_env=dict(runtime_env or {}),
        )
        artifact_dir = _write_poc_artifacts(run_dir, candidate, poc)
        validations = self._run_validators(poc.validation_hints, project, candidate, poc, artifact_dir)
        final = _make_final_finding(
            candidate=candidate,
            analysis=analysis,
            poc=poc,
            validations=validations,
            fix="Fix guidance is not inferred automatically in known-PoC verification mode.",
        )
        result = ScanResult(
            run_id=run_dir.name,
            created_at=datetime.now(timezone.utc).isoformat(),
            run_dir=str(run_dir),
            target=target,
            project=project,
            records=[FindingRecord(candidate=candidate, analysis=analysis, poc=poc, validations=validations, final=final)],
            metadata=dict(result_metadata or {}),
        )
        write_scan_result(result)
        write_markdown_report(result)
        return result

    def replay_cve(self, target_spec: str, cve_id: str) -> ScanResult:
        record = CorpusStore(self.config.corpus_dir).load_record(cve_id)
        return self.replay_record(target_spec, record)

    def replay_manifest(self, target_spec: str, manifest_ref: str) -> ScanResult:
        record = CorpusStore(self.config.corpus_dir).load_manifest(manifest_ref)
        return self.replay_record(target_spec, record)

    def replay_record(self, target_spec: str, record: CveCorpusRecord) -> ScanResult:
        replay = record.replay
        return self.verify_known(
            target_spec=target_spec,
            title=replay.title,
            vuln_family=replay.vuln_family,
            repro_command=replay.repro_command,
            artifacts=replay.artifacts,
            severity_hint=replay.severity,
            file_path=replay.candidate_file,
            line=replay.candidate_line,
            function_or_sink=replay.function_or_sink,
            notes=replay.notes or record.summary,
            configure_extra_args=replay.configure_args,
            runtime_env=replay.runtime_env,
            validation_hints=["docker_build", "sanitizer_runtime", "host_build", "host_sanitizer_runtime", "direct_runtime"],
            result_metadata={"corpus_record": record.to_dict()},
        )

    def triage(self, run_ref: str, finding_id: str) -> ScanResult:
        result = load_scan_result(run_ref, self.config.runs_dir)
        record = _find_record(result, finding_id)
        plugin = self.registry.vuln_families[record.candidate.vuln_family]
        provider = self.registry.build_provider(self.config.llm)
        llm_context = plugin.build_llm_context(record.candidate, result.project)
        analysis = provider.analyze_candidate(llm_context)
        llm_context["analysis"] = analysis.to_dict()
        poc = provider.generate_poc(llm_context)
        fix = provider.suggest_fix(llm_context)
        updated = replace(
            record,
            analysis=analysis,
            poc=poc,
            final=_make_final_finding(record.candidate, analysis, poc, record.validations, fix),
        )
        _write_triage_event(result.run_dir, record, updated)
        _replace_record(result, updated)
        write_scan_result(result)
        write_markdown_report(result)
        return result

    def repro(self, run_ref: str, finding_id: str) -> ScanResult:
        result = load_scan_result(run_ref, self.config.runs_dir)
        record = _find_record(result, finding_id)
        plugin = self.registry.vuln_families[record.candidate.vuln_family]
        artifact_dir = _write_poc_artifacts(Path(result.run_dir), record.candidate, record.poc)
        validations = self._run_validators(
            plugin.suggest_validation_kinds(record.candidate),
            result.project,
            record.candidate,
            record.poc,
            artifact_dir,
        )
        updated = replace(
            record,
            validations=validations,
            final=_make_final_finding(
                record.candidate,
                record.analysis,
                record.poc,
                validations,
                record.final.fix_recommendation,
            ),
        )
        _replace_record(result, updated)
        write_scan_result(result)
        write_markdown_report(result)
        return result

    def report(self, run_ref: str) -> ScanResult:
        result = load_scan_result(run_ref, self.config.runs_dir)
        write_scan_result(result)
        write_markdown_report(result)
        return result

    def _run_validators(
        self,
        suggested: list[str],
        project: ProjectContext,
        candidate: Candidate,
        poc: PocSpec,
        artifact_dir: Path,
    ) -> list[ValidationResult]:
        names = [name for name in suggested if name in self.config.enabled_validators]
        validators = self.registry.resolve_validators(names)
        results: list[ValidationResult] = []
        for validator in validators:
            if validator.supports(project, candidate, poc):
                result = validator.run(project, candidate, poc, artifact_dir)
                if not result.validator_name:
                    result.validator_name = validator.name
                results.append(result)
        return results


def _write_poc_artifacts(run_dir: Path, candidate: Candidate, poc: PocSpec) -> Path:
    artifact_dir = ensure_directory(run_dir / "artifacts" / candidate.id)
    (artifact_dir / "payload.txt").write_text(poc.input_payload, encoding="utf-8")
    for artifact in poc.artifacts:
        artifact_name = validate_simple_filename(artifact.name, label="artifact name")
        path = artifact_dir / artifact_name
        if artifact.encoding is ArtifactEncoding.BASE64:
            path.write_bytes(base64.b64decode(artifact.content))
        else:
            path.write_text(artifact.content, encoding="utf-8")
    return artifact_dir


def _write_triage_event(run_dir: str, previous: FindingRecord, updated: FindingRecord) -> None:
    events_dir = ensure_directory(Path(run_dir) / "triage")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = events_dir / f"{stamp}-{previous.final.id}.json"
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "finding_id": previous.final.id,
        "previous_final": previous.final.to_dict(),
        "updated_final": updated.final.to_dict(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _make_final_finding(
    candidate: Candidate,
    analysis: AnalysisResult,
    poc: PocSpec,
    validations: list[ValidationResult],
    fix: str,
) -> FinalFinding:
    best_validation = _best_validation(validations)
    status = _finding_status(candidate, analysis, poc, best_validation)
    evidence = best_validation.evidence if best_validation else analysis.root_cause
    poc_status = best_validation.status.value if best_validation else "not_run"
    return FinalFinding(
        id=candidate.id,
        title=candidate.title,
        file=candidate.file_path,
        function_or_sink=candidate.function_or_sink,
        vuln_family=candidate.vuln_family,
        severity_estimate=_severity(candidate, analysis, status),
        confidence=analysis.confidence,
        reachability=analysis.reachability_reason,
        trigger_condition=analysis.trigger_condition,
        attack_path=analysis.exploit_strategy,
        poc_status=poc_status,
        poc_source=poc.source,
        repro_command=poc.repro_command,
        evidence=evidence,
        fix_recommendation=fix,
        status=status,
        line=candidate.line,
        snippet=candidate.metadata.get("snippet", ""),
    )


def _best_validation(validations: list[ValidationResult]) -> ValidationResult | None:
    if not validations:
        return None
    rank = {
        ValidationStatus.CONFIRMED: 3,
        ValidationStatus.HYPOTHESIS: 2,
        ValidationStatus.FAILED: 1,
        ValidationStatus.UNSUPPORTED: 0,
    }
    return max(validations, key=lambda item: rank[item.status])


def _finding_status(
    candidate: Candidate,
    analysis: AnalysisResult,
    poc: PocSpec,
    best_validation: ValidationResult | None,
) -> FindingStatus:
    if best_validation and best_validation.status is ValidationStatus.CONFIRMED:
        if poc.source is PocSource.KNOWN:
            return FindingStatus.CONFIRMED_KNOWN_POC
        return FindingStatus.CONFIRMED_GENERATED_POC
    if best_validation and best_validation.status in {ValidationStatus.HYPOTHESIS, ValidationStatus.FAILED}:
        return FindingStatus.MANUAL_REVIEW
    if poc.source is PocSource.GENERATED and poc.artifacts:
        return FindingStatus.POC_SYNTHESIZED
    if analysis.confidence in {"high", "medium"} and poc.source is PocSource.KNOWN:
        return FindingStatus.MANUAL_REVIEW
    if candidate.candidate_only:
        return FindingStatus.CANDIDATE
    return FindingStatus.CANDIDATE


def _severity(candidate: Candidate, analysis: AnalysisResult, status: FindingStatus) -> str:
    if status in {FindingStatus.CONFIRMED_GENERATED_POC, FindingStatus.CONFIRMED_KNOWN_POC} and candidate.severity_hint == "high":
        return "critical"
    if candidate.severity_hint == "high":
        return "high"
    if analysis.confidence == "high":
        return "high"
    return "medium"


def _find_record(result: ScanResult, finding_id: str) -> FindingRecord:
    for record in result.records:
        if record.final.id == finding_id:
            return record
    raise KeyError(f"Finding {finding_id} not found in run {result.run_id}")


def _replace_record(result: ScanResult, updated: FindingRecord) -> None:
    for index, record in enumerate(result.records):
        if record.final.id == updated.final.id:
            result.records[index] = updated
            return
    raise KeyError(f"Finding {updated.final.id} not found in run {result.run_id}")


def _make_known_candidate(
    *,
    title: str,
    vuln_family: str,
    project: ProjectContext,
    severity_hint: str,
    file_path: str,
    line: int | None,
    function_or_sink: str,
    notes: str,
) -> Candidate:
    digest = sha1(
        f"{project.root}:{title}:{vuln_family}:{file_path}:{line}:{function_or_sink}".encode("utf-8")
    ).hexdigest()[:12]
    return Candidate(
        id=digest,
        title=title,
        vuln_family=vuln_family,
        target_mode=project.target.mode,
        file_path=file_path,
        line=line,
        function_or_sink=function_or_sink,
        evidence_seed=notes or "Imported known PoC",
        severity_hint=severity_hint,
        candidate_only=False,
        metadata={"snippet": notes or "Imported known PoC"},
    )
