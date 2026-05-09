from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class TargetMode(str, Enum):
    SOURCE_REPO = "source_repo"
    BINARY_ARTIFACT = "binary_artifact"


class ValidationStatus(str, Enum):
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    HYPOTHESIS = "hypothesis"
    CONFIRMED = "confirmed"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    POC_SYNTHESIZED = "poc_synthesized"
    MANUAL_REVIEW = "manual_review"
    CONFIRMED_GENERATED_POC = "confirmed_generated_poc"
    CONFIRMED_KNOWN_POC = "confirmed_known_poc"


class PocSource(str, Enum):
    GENERATED = "generated"
    KNOWN = "known"


class ArtifactEncoding(str, Enum):
    TEXT = "text"
    BASE64 = "base64"


class LanguageName(str, Enum):
    C_CPP = "c_cpp"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    RUST = "rust"
    BINARY = "binary"
    UNKNOWN = "unknown"


class CandidateKind(str, Enum):
    MEMORY_OPERATION = "memory_operation"
    SIZE_VALIDATION = "size_validation"
    COMMAND_EXECUTION = "command_execution"
    FILESYSTEM_PATH = "filesystem_path"
    DESERIALIZATION = "deserialization"
    SQL_QUERY = "sql_query"
    NETWORK_REQUEST = "network_request"
    XML_PARSER = "xml_parser"
    TEMPLATE_RENDER = "template_render"
    REGEX_ENGINE = "regex_engine"
    BINARY_SYMBOL = "binary_symbol"
    UNKNOWN = "unknown"


class EvidenceKind(str, Enum):
    COMMAND_OUTPUT = "command_output"
    SANITIZER = "sanitizer"
    TRACEBACK = "traceback"
    ARTIFACT = "artifact"
    LOG = "log"
    METADATA = "metadata"


@dataclass(slots=True)
class LanguageProfile:
    name: LanguageName
    manifests: list[str] = field(default_factory=list)
    source_suffixes: list[str] = field(default_factory=list)
    build_system: str = "unknown"
    test_command: str = ""
    run_command: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "manifests": self.manifests,
            "source_suffixes": self.source_suffixes,
            "build_system": self.build_system,
            "test_command": self.test_command,
            "run_command": self.run_command,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LanguageProfile":
        return cls(
            name=_coerce_language_name(data.get("name", LanguageName.UNKNOWN.value)),
            manifests=list(data.get("manifests", [])),
            source_suffixes=list(data.get("source_suffixes", [])),
            build_system=data.get("build_system", "unknown"),
            test_command=data.get("test_command", ""),
            run_command=data.get("run_command", ""),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(slots=True)
class ScanTarget:
    spec: str
    resolved_path: str
    mode: TargetMode
    origin: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec": self.spec,
            "resolved_path": self.resolved_path,
            "mode": self.mode.value,
            "origin": self.origin,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanTarget":
        return cls(
            spec=data["spec"],
            resolved_path=data["resolved_path"],
            mode=TargetMode(data["mode"]),
            origin=data["origin"],
        )


@dataclass(slots=True)
class ProjectContext:
    target: ScanTarget
    adapter_name: str
    root: str
    build_system: str
    source_files: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    language_profiles: list[LanguageProfile] = field(default_factory=list)

    @property
    def primary_language(self) -> LanguageName:
        if self.language_profiles:
            return self.language_profiles[0].name
        if "language" in self.metadata:
            return _coerce_language_name(self.metadata["language"])
        return LanguageName.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "adapter_name": self.adapter_name,
            "root": self.root,
            "build_system": self.build_system,
            "source_files": self.source_files,
            "entrypoints": self.entrypoints,
            "metadata": self.metadata,
            "language_profiles": [profile.to_dict() for profile in self.language_profiles],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProjectContext":
        profiles = [
            LanguageProfile.from_dict(item)
            for item in data.get("language_profiles", [])
        ]
        metadata = dict(data.get("metadata", {}))
        if not profiles and "language" in metadata:
            profiles = [
                LanguageProfile(
                    name=_coerce_language_name(metadata["language"]),
                    build_system=data.get("build_system", "unknown"),
                    metadata={"legacy": True},
                )
            ]
        return cls(
            target=ScanTarget.from_dict(data["target"]),
            adapter_name=data["adapter_name"],
            root=data["root"],
            build_system=data["build_system"],
            source_files=list(data.get("source_files", [])),
            entrypoints=list(data.get("entrypoints", [])),
            metadata=metadata,
            language_profiles=profiles,
        )


@dataclass(slots=True)
class Candidate:
    id: str
    title: str
    vuln_family: str
    target_mode: TargetMode
    file_path: str
    line: int | None
    function_or_sink: str
    evidence_seed: str
    severity_hint: str
    kind: CandidateKind = CandidateKind.UNKNOWN
    candidate_only: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "vuln_family": self.vuln_family,
            "target_mode": self.target_mode.value,
            "file_path": self.file_path,
            "line": self.line,
            "function_or_sink": self.function_or_sink,
            "evidence_seed": self.evidence_seed,
            "severity_hint": self.severity_hint,
            "kind": self.kind.value,
            "candidate_only": self.candidate_only,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Candidate":
        return cls(
            id=data["id"],
            title=data["title"],
            vuln_family=data["vuln_family"],
            target_mode=TargetMode(data["target_mode"]),
            file_path=data["file_path"],
            line=data.get("line"),
            function_or_sink=data["function_or_sink"],
            evidence_seed=data["evidence_seed"],
            severity_hint=data["severity_hint"],
            kind=_coerce_candidate_kind(data.get("kind", CandidateKind.UNKNOWN.value)),
            candidate_only=bool(data.get("candidate_only", False)),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(slots=True)
class AnalysisResult:
    root_cause: str
    trigger_condition: str
    input_shape: str
    reachability_reason: str
    exploit_strategy: str
    confidence: str
    patch_direction: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_cause": self.root_cause,
            "trigger_condition": self.trigger_condition,
            "input_shape": self.input_shape,
            "reachability_reason": self.reachability_reason,
            "exploit_strategy": self.exploit_strategy,
            "confidence": self.confidence,
            "patch_direction": self.patch_direction,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalysisResult":
        return cls(**data)


@dataclass(slots=True)
class ArtifactSpec:
    name: str
    content: str
    encoding: ArtifactEncoding = ArtifactEncoding.TEXT

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "content": self.content,
            "encoding": self.encoding.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArtifactSpec":
        return cls(
            name=data["name"],
            content=data["content"],
            encoding=ArtifactEncoding(data.get("encoding", ArtifactEncoding.TEXT.value)),
        )


@dataclass(slots=True)
class PocSpec:
    description: str
    repro_command: str
    input_payload: str
    source: PocSource = PocSource.GENERATED
    artifacts: list[ArtifactSpec] = field(default_factory=list)
    validation_hints: list[str] = field(default_factory=list)
    runtime_env: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "repro_command": self.repro_command,
            "input_payload": self.input_payload,
            "source": self.source.value,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "validation_hints": self.validation_hints,
            "runtime_env": self.runtime_env,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PocSpec":
        artifacts_data = data.get("artifacts", [])
        if isinstance(artifacts_data, dict):
            artifacts = [
                ArtifactSpec(name=name, content=content, encoding=ArtifactEncoding.TEXT)
                for name, content in artifacts_data.items()
            ]
        else:
            artifacts = [ArtifactSpec.from_dict(item) for item in artifacts_data]
        return cls(
            description=data["description"],
            repro_command=data["repro_command"],
            input_payload=data["input_payload"],
            source=PocSource(data.get("source", PocSource.GENERATED.value)),
            artifacts=artifacts,
            validation_hints=list(data.get("validation_hints", [])),
            runtime_env={str(key): str(value) for key, value in dict(data.get("runtime_env", {})).items()},
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(slots=True)
class EvidenceSpec:
    kind: EvidenceKind
    label: str
    value: str
    path: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "label": self.label,
            "value": self.value,
            "path": self.path,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceSpec":
        return cls(
            kind=EvidenceKind(data.get("kind", EvidenceKind.LOG.value)),
            label=data["label"],
            value=data["value"],
            path=data.get("path", ""),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(slots=True)
class ValidationResult:
    validator_name: str
    status: ValidationStatus
    summary: str
    command: str = ""
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence_items: list[EvidenceSpec] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "validator_name": self.validator_name,
            "status": self.status.value,
            "summary": self.summary,
            "command": self.command,
            "evidence": self.evidence,
            "metadata": self.metadata,
            "evidence_items": [item.to_dict() for item in self.evidence_items],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ValidationResult":
        evidence_items = [
            EvidenceSpec.from_dict(item)
            for item in data.get("evidence_items", [])
        ]
        if not evidence_items and data.get("evidence"):
            evidence_items = [
                EvidenceSpec(
                    kind=EvidenceKind.LOG,
                    label="validator-output",
                    value=data["evidence"],
                )
            ]
        return cls(
            validator_name=data["validator_name"],
            status=ValidationStatus(data["status"]),
            summary=data["summary"],
            command=data.get("command", ""),
            evidence=data.get("evidence", ""),
            metadata=dict(data.get("metadata", {})),
            evidence_items=evidence_items,
        )


@dataclass(slots=True)
class ReplaySpec:
    title: str
    vuln_family: str
    repro_command: str
    artifacts: list[ArtifactSpec] = field(default_factory=list)
    severity: str = "high"
    candidate_file: str = ""
    candidate_line: int | None = None
    function_or_sink: str = "known_poc"
    notes: str = ""
    configure_args: list[str] = field(default_factory=list)
    runtime_env: dict[str, str] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "vuln_family": self.vuln_family,
            "repro_command": self.repro_command,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "severity": self.severity,
            "candidate_file": self.candidate_file,
            "candidate_line": self.candidate_line,
            "function_or_sink": self.function_or_sink,
            "notes": self.notes,
            "configure_args": self.configure_args,
            "runtime_env": self.runtime_env,
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReplaySpec":
        return cls(
            title=data["title"],
            vuln_family=data["vuln_family"],
            repro_command=data["repro_command"],
            artifacts=[
                item if isinstance(item, ArtifactSpec) else ArtifactSpec.from_dict(item)
                for item in data.get("artifacts", [])
            ],
            severity=data.get("severity", "high"),
            candidate_file=data.get("candidate_file", ""),
            candidate_line=data.get("candidate_line"),
            function_or_sink=data.get("function_or_sink", "known_poc"),
            notes=data.get("notes", ""),
            configure_args=list(data.get("configure_args", [])),
            runtime_env={str(key): str(value) for key, value in dict(data.get("runtime_env", {})).items()},
            references=list(data.get("references", [])),
        )


@dataclass(slots=True)
class CveCorpusRecord:
    cve_id: str
    summary: str
    project: str
    language: LanguageName
    vuln_family: str
    replay: ReplaySpec
    references: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "summary": self.summary,
            "project": self.project,
            "language": self.language.value,
            "vuln_family": self.vuln_family,
            "replay": self.replay.to_dict(),
            "references": self.references,
            "aliases": self.aliases,
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CveCorpusRecord":
        return cls(
            cve_id=data["cve_id"],
            summary=data["summary"],
            project=data.get("project", ""),
            language=_coerce_language_name(data.get("language", LanguageName.UNKNOWN.value)),
            vuln_family=data.get("vuln_family", data["replay"]["vuln_family"]),
            replay=ReplaySpec.from_dict(data["replay"]),
            references=list(data.get("references", [])),
            aliases=list(data.get("aliases", [])),
            affected_versions=list(data.get("affected_versions", [])),
            fixed_versions=list(data.get("fixed_versions", [])),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(slots=True)
class FinalFinding:
    id: str
    title: str
    file: str
    function_or_sink: str
    vuln_family: str
    severity_estimate: str
    confidence: str
    reachability: str
    trigger_condition: str
    attack_path: str
    poc_status: str
    poc_source: PocSource
    repro_command: str
    evidence: str
    fix_recommendation: str
    status: FindingStatus
    line: int | None = None
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "file": self.file,
            "function_or_sink": self.function_or_sink,
            "vuln_family": self.vuln_family,
            "severity_estimate": self.severity_estimate,
            "confidence": self.confidence,
            "reachability": self.reachability,
            "trigger_condition": self.trigger_condition,
            "attack_path": self.attack_path,
            "poc_status": self.poc_status,
            "poc_source": self.poc_source.value,
            "repro_command": self.repro_command,
            "evidence": self.evidence,
            "fix_recommendation": self.fix_recommendation,
            "status": self.status.value,
            "line": self.line,
            "snippet": self.snippet,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FinalFinding":
        return cls(
            id=data["id"],
            title=data["title"],
            file=data["file"],
            function_or_sink=data["function_or_sink"],
            vuln_family=data["vuln_family"],
            severity_estimate=data["severity_estimate"],
            confidence=data["confidence"],
            reachability=data["reachability"],
            trigger_condition=data["trigger_condition"],
            attack_path=data["attack_path"],
            poc_status=data["poc_status"],
            poc_source=PocSource(data.get("poc_source", PocSource.GENERATED.value)),
            repro_command=data["repro_command"],
            evidence=data["evidence"],
            fix_recommendation=data["fix_recommendation"],
            status=_coerce_finding_status(data["status"]),
            line=data.get("line"),
            snippet=data.get("snippet", ""),
        )


@dataclass(slots=True)
class FindingRecord:
    candidate: Candidate
    analysis: AnalysisResult
    poc: PocSpec
    validations: list[ValidationResult]
    final: FinalFinding

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate.to_dict(),
            "analysis": self.analysis.to_dict(),
            "poc": self.poc.to_dict(),
            "validations": [result.to_dict() for result in self.validations],
            "final": self.final.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FindingRecord":
        return cls(
            candidate=Candidate.from_dict(data["candidate"]),
            analysis=AnalysisResult.from_dict(data["analysis"]),
            poc=PocSpec.from_dict(data["poc"]),
            validations=[ValidationResult.from_dict(item) for item in data.get("validations", [])],
            final=FinalFinding.from_dict(data["final"]),
        )


@dataclass(slots=True)
class ScanResult:
    run_id: str
    created_at: str
    run_dir: str
    target: ScanTarget
    project: ProjectContext
    records: list[FindingRecord]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "created_at": self.created_at,
            "run_dir": self.run_dir,
            "target": self.target.to_dict(),
            "project": self.project.to_dict(),
            "records": [record.to_dict() for record in self.records],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        return cls(
            run_id=data["run_id"],
            created_at=data["created_at"],
            run_dir=data["run_dir"],
            target=ScanTarget.from_dict(data["target"]),
            project=ProjectContext.from_dict(data["project"]),
            records=[FindingRecord.from_dict(item) for item in data.get("records", [])],
            metadata=dict(data.get("metadata", {})),
        )


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _coerce_finding_status(value: str) -> FindingStatus:
    legacy = {
        "hypothesis": FindingStatus.MANUAL_REVIEW,
        "confirmed": FindingStatus.CONFIRMED_GENERATED_POC,
    }
    return legacy.get(value, FindingStatus(value))


def _coerce_language_name(value: str) -> LanguageName:
    try:
        return LanguageName(value)
    except ValueError:
        return LanguageName.UNKNOWN


def _coerce_candidate_kind(value: str) -> CandidateKind:
    try:
        return CandidateKind(value)
    except ValueError:
        return CandidateKind.UNKNOWN
