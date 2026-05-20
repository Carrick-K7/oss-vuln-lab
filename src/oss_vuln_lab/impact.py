from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from fnmatch import fnmatch
from hashlib import sha1
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from oss_vuln_lab.corpus import CorpusStore
from oss_vuln_lab.intelligence import IntelResult, WebIntelProvider
from oss_vuln_lab.models import FindingStatus, ValidationStatus, ensure_directory
from oss_vuln_lab.pipeline import ScanEngine


IMPACTS_DIR_NAME = "impacts"
IMPACT_STATE_FILE = "impact.json"
IMPACT_REPORT_MD = "impact.md"
INTEL_STATE_FILE = "intel.json"


class ImpactValidationError(ValueError):
    pass


class ImpactStatus(str, Enum):
    CONFIRMED_AFFECTED = "confirmed_affected"
    NOT_REPRODUCED = "not_reproduced"
    LIKELY_AFFECTED = "likely_affected"
    LIKELY_FIXED = "likely_fixed"
    UNKNOWN = "unknown"
    NOT_BUILDABLE = "not_buildable"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


@dataclass(slots=True)
class ImpactSourceHint:
    file: str = ""
    function_or_sink: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "function_or_sink": self.function_or_sink,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImpactSourceHint":
        return cls(
            file=str(data.get("file", "")),
            function_or_sink=str(data.get("function_or_sink", "")),
            description=str(data.get("description", "")),
        )


@dataclass(slots=True)
class ImpactAdvisory:
    id: str
    project: str
    summary: str
    vuln_family: str = ""
    references: list[str] = field(default_factory=list)
    source_hints: list[ImpactSourceHint] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "project": self.project,
            "summary": self.summary,
            "vuln_family": self.vuln_family,
            "references": self.references,
            "source_hints": [item.to_dict() for item in self.source_hints],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImpactAdvisory":
        return cls(
            id=str(data["id"]),
            project=str(data["project"]),
            summary=str(data["summary"]),
            vuln_family=str(data.get("vuln_family", "")),
            references=[str(item) for item in data.get("references", [])],
            source_hints=[
                ImpactSourceHint.from_dict(item)
                for item in data.get("source_hints", [])
                if isinstance(item, dict)
            ],
        )


@dataclass(slots=True)
class ImpactVersionTarget:
    version: str
    ref: str
    role: str = ""
    source: str = "explicit"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "ref": self.ref,
            "role": self.role,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, source: str = "explicit") -> "ImpactVersionTarget":
        return cls(
            version=str(data["version"]),
            ref=str(data["ref"]),
            role=str(data.get("role", "")),
            source=source,
        )


@dataclass(slots=True)
class ImpactDiscovery:
    enabled: bool = False
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    limit: int = 20

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "include": self.include,
            "exclude": self.exclude,
            "limit": self.limit,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ImpactDiscovery":
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", False)),
            include=[str(item) for item in data.get("include", [])],
            exclude=[str(item) for item in data.get("exclude", [])],
            limit=int(data.get("limit", 20)),
        )


@dataclass(slots=True)
class ImpactVersionSource:
    type: str
    repository: str
    explicit: list[ImpactVersionTarget] = field(default_factory=list)
    discover: ImpactDiscovery = field(default_factory=ImpactDiscovery)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "repository": self.repository,
            "explicit": [item.to_dict() for item in self.explicit],
            "discover": self.discover.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImpactVersionSource":
        return cls(
            type=str(data["type"]),
            repository=str(data["repository"]),
            explicit=[
                ImpactVersionTarget.from_dict(item, source="explicit")
                for item in data.get("explicit", [])
                if isinstance(item, dict)
            ],
            discover=ImpactDiscovery.from_dict(data.get("discover")),
        )


@dataclass(slots=True)
class ImpactReplay:
    corpus_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"corpus_ref": self.corpus_ref}

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ImpactReplay":
        data = data or {}
        return cls(corpus_ref=str(data.get("corpus_ref", "")))


@dataclass(slots=True)
class ImpactIntelligence:
    enabled: bool = False
    queries: list[str] = field(default_factory=list)
    max_results: int = 10

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "queries": self.queries,
            "max_results": self.max_results,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ImpactIntelligence":
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", False)),
            queries=[str(item) for item in data.get("queries", [])],
            max_results=int(data.get("max_results", 10)),
        )


@dataclass(slots=True)
class ImpactSourceSignature:
    name: str
    classification: str
    file: str
    contains_all: list[str] = field(default_factory=list)
    contains_any: list[str] = field(default_factory=list)
    absent_all: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "classification": self.classification,
            "file": self.file,
            "contains_all": self.contains_all,
            "contains_any": self.contains_any,
            "absent_all": self.absent_all,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImpactSourceSignature":
        return cls(
            name=str(data["name"]),
            classification=str(data["classification"]),
            file=str(data["file"]),
            contains_all=[str(item) for item in data.get("contains_all", [])],
            contains_any=[str(item) for item in data.get("contains_any", [])],
            absent_all=[str(item) for item in data.get("absent_all", [])],
        )


@dataclass(slots=True)
class ImpactManifest:
    schema_version: str
    name: str
    advisory: ImpactAdvisory
    version_source: ImpactVersionSource
    replay: ImpactReplay = field(default_factory=ImpactReplay)
    intelligence: ImpactIntelligence = field(default_factory=ImpactIntelligence)
    source_signatures: list[ImpactSourceSignature] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "advisory": self.advisory.to_dict(),
            "version_source": self.version_source.to_dict(),
            "replay": self.replay.to_dict(),
            "intelligence": self.intelligence.to_dict(),
            "source_signatures": [item.to_dict() for item in self.source_signatures],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImpactManifest":
        return cls(
            schema_version=str(data["schema_version"]),
            name=str(data["name"]),
            advisory=ImpactAdvisory.from_dict(data["advisory"]),
            version_source=ImpactVersionSource.from_dict(data["version_source"]),
            replay=ImpactReplay.from_dict(data.get("replay")),
            intelligence=ImpactIntelligence.from_dict(data.get("intelligence")),
            source_signatures=[
                ImpactSourceSignature.from_dict(item)
                for item in data.get("source_signatures", [])
                if isinstance(item, dict)
            ],
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(slots=True)
class ImpactIntelResult:
    query: str
    title: str
    url: str
    snippet: str = ""
    fetched_path: str = ""
    sha256: str = ""
    size: int = 0
    status: str = "search_result"
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "title": self.title,
            "url": self.url,
            "snippet": self.snippet,
            "fetched_path": self.fetched_path,
            "sha256": self.sha256,
            "size": self.size,
            "status": self.status,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImpactIntelResult":
        return cls(
            query=str(data.get("query", "")),
            title=str(data.get("title", "")),
            url=str(data.get("url", "")),
            snippet=str(data.get("snippet", "")),
            fetched_path=str(data.get("fetched_path", "")),
            sha256=str(data.get("sha256", "")),
            size=int(data.get("size", 0)),
            status=str(data.get("status", "search_result")),
            error=str(data.get("error", "")),
        )


@dataclass(slots=True)
class ImpactVersionResult:
    version: str
    ref: str
    role: str
    status: ImpactStatus
    checkout_path: str = ""
    run_id: str = ""
    run_dir: str = ""
    evidence: str = ""
    source_matches: list[dict[str, Any]] = field(default_factory=list)
    validations: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "ref": self.ref,
            "role": self.role,
            "status": self.status.value,
            "checkout_path": self.checkout_path,
            "run_id": self.run_id,
            "run_dir": self.run_dir,
            "evidence": self.evidence,
            "source_matches": self.source_matches,
            "validations": self.validations,
            "error": self.error,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImpactVersionResult":
        return cls(
            version=str(data["version"]),
            ref=str(data["ref"]),
            role=str(data.get("role", "")),
            status=ImpactStatus(data["status"]),
            checkout_path=str(data.get("checkout_path", "")),
            run_id=str(data.get("run_id", "")),
            run_dir=str(data.get("run_dir", "")),
            evidence=str(data.get("evidence", "")),
            source_matches=list(data.get("source_matches", [])),
            validations=list(data.get("validations", [])),
            error=str(data.get("error", "")),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(slots=True)
class ImpactReport:
    impact_id: str
    created_at: str
    manifest_ref: str
    name: str
    advisory: ImpactAdvisory
    versions: list[ImpactVersionResult]
    intel: list[ImpactIntelResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "impact_id": self.impact_id,
            "created_at": self.created_at,
            "manifest_ref": self.manifest_ref,
            "name": self.name,
            "advisory": self.advisory.to_dict(),
            "versions": [item.to_dict() for item in self.versions],
            "intel": [item.to_dict() for item in self.intel],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImpactReport":
        return cls(
            impact_id=str(data["impact_id"]),
            created_at=str(data["created_at"]),
            manifest_ref=str(data.get("manifest_ref", "")),
            name=str(data["name"]),
            advisory=ImpactAdvisory.from_dict(data["advisory"]),
            versions=[ImpactVersionResult.from_dict(item) for item in data.get("versions", [])],
            intel=[ImpactIntelResult.from_dict(item) for item in data.get("intel", [])],
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(slots=True)
class ImpactPlan:
    manifest: ImpactManifest
    targets: list[ImpactVersionTarget]


class ImpactRunner:
    def __init__(self, engine: ScanEngine):
        self.engine = engine

    def plan_manifest(self, manifest_ref: str, *, allow_network: bool = False) -> ImpactPlan:
        manifest_path = Path(manifest_ref).expanduser().resolve()
        manifest = load_impact_manifest(manifest_path)
        _enforce_network_policy(manifest, allow_network)
        targets = resolve_version_targets(manifest)
        return ImpactPlan(manifest=manifest, targets=targets)

    def assess_manifest(
        self,
        manifest_ref: str,
        *,
        allow_network: bool = False,
        execute_discovered_poc: bool = False,
        execute_generated_poc: bool = False,
    ) -> ImpactReport:
        manifest_path = Path(manifest_ref).expanduser().resolve()
        manifest = load_impact_manifest(manifest_path)
        _enforce_network_policy(manifest, allow_network)
        targets = resolve_version_targets(manifest)

        impact_dir = create_impact_dir(self.engine.config.runs_dir, manifest.name)
        workspace_dir = ensure_directory(impact_dir / "workspace")
        intel_results = self._collect_intelligence(manifest, workspace_dir, allow_network)
        (impact_dir / INTEL_STATE_FILE).write_text(
            json.dumps([item.to_dict() for item in intel_results], indent=2, sort_keys=True),
            encoding="utf-8",
        )

        repo_dir = clone_repository(manifest.version_source.repository, workspace_dir / "repository")
        corpus_record = None
        if manifest.replay.corpus_ref:
            corpus_record = CorpusStore(self.engine.config.corpus_dir).load_record(manifest.replay.corpus_ref)

        version_results: list[ImpactVersionResult] = []
        for target in targets:
            try:
                checkout_dir = checkout_version(repo_dir, target, workspace_dir / "checkouts")
                result = self._assess_checkout(
                    manifest=manifest,
                    target=target,
                    checkout_dir=checkout_dir,
                    corpus_record=corpus_record,
                    execute_discovered_poc=execute_discovered_poc,
                    execute_generated_poc=execute_generated_poc,
                    intel_results=intel_results,
                )
                version_results.append(result)
            except subprocess.CalledProcessError as exc:
                version_results.append(
                    ImpactVersionResult(
                        version=target.version,
                        ref=target.ref,
                        role=target.role,
                        status=ImpactStatus.ERROR,
                        error=_subprocess_error(exc),
                    )
                )
            except Exception as exc:
                version_results.append(
                    ImpactVersionResult(
                        version=target.version,
                        ref=target.ref,
                        role=target.role,
                        status=ImpactStatus.ERROR,
                        error=str(exc),
                    )
                )

        report = ImpactReport(
            impact_id=impact_dir.name,
            created_at=_utc_now(),
            manifest_ref=str(manifest_path),
            name=manifest.name,
            advisory=manifest.advisory,
            versions=version_results,
            intel=intel_results,
            metadata={
                "manifest": manifest.to_dict(),
                "workspace": str(workspace_dir),
                "execute_discovered_poc": execute_discovered_poc,
                "execute_generated_poc": execute_generated_poc,
            },
        )
        write_impact_report(report, impact_dir)
        return report

    def _collect_intelligence(
        self,
        manifest: ImpactManifest,
        workspace_dir: Path,
        allow_network: bool,
    ) -> list[ImpactIntelResult]:
        if not manifest.intelligence.enabled:
            return []
        provider = WebIntelProvider(self.engine.config.intel)
        results = provider.collect(
            manifest.intelligence.queries,
            max_results=manifest.intelligence.max_results,
            workspace_dir=workspace_dir / "intel",
            allow_network=allow_network,
        )
        return [_to_impact_intel(item) for item in results]

    def _assess_checkout(
        self,
        *,
        manifest: ImpactManifest,
        target: ImpactVersionTarget,
        checkout_dir: Path,
        corpus_record,
        execute_discovered_poc: bool,
        execute_generated_poc: bool,
        intel_results: list[ImpactIntelResult],
    ) -> ImpactVersionResult:
        runtime_status = ImpactStatus.UNKNOWN
        run_id = ""
        run_dir = ""
        evidence = ""
        validations: list[dict[str, Any]] = []
        metadata: dict[str, Any] = {"target_source": target.source}

        if corpus_record is not None:
            replay_result = self.engine.replay_record(str(checkout_dir), corpus_record)
            run_id = replay_result.run_id
            run_dir = replay_result.run_dir
            runtime_status, evidence, validations = _impact_from_scan_result(replay_result)

        if execute_generated_poc and runtime_status is not ImpactStatus.CONFIRMED_AFFECTED:
            generated = self.engine.scan(str(checkout_dir))
            metadata["generated_run_id"] = generated.run_id
            generated_status, generated_evidence, generated_validations = _impact_from_scan_result(generated)
            if generated_status is ImpactStatus.CONFIRMED_AFFECTED:
                runtime_status = generated_status
                run_id = generated.run_id
                run_dir = generated.run_dir
                evidence = generated_evidence
                validations = generated_validations
            elif runtime_status is ImpactStatus.UNKNOWN and generated_validations:
                runtime_status = generated_status
                evidence = generated_evidence
                validations = generated_validations

        if execute_discovered_poc and intel_results:
            metadata["discovered_poc_execution"] = "no_supported_command_templates"

        source_matches = evaluate_source_signatures(checkout_dir, manifest.source_signatures)
        status = _derive_impact_status(runtime_status, source_matches, target.role)
        if not evidence and source_matches:
            evidence = _source_evidence(source_matches)

        return ImpactVersionResult(
            version=target.version,
            ref=target.ref,
            role=target.role,
            status=status,
            checkout_path=str(checkout_dir),
            run_id=run_id,
            run_dir=run_dir,
            evidence=evidence,
            source_matches=source_matches,
            validations=validations,
            metadata=metadata,
        )


def load_impact_manifest(manifest_ref: str | Path) -> ImpactManifest:
    path = Path(manifest_ref).expanduser().resolve()
    data = _load_json_object(path)
    _validate_manifest_shape(path, data)
    try:
        return ImpactManifest.from_dict(data)
    except (KeyError, TypeError, ValueError) as exc:
        raise ImpactValidationError(f"{path}: invalid impact manifest: {exc}") from exc


def resolve_version_targets(manifest: ImpactManifest) -> list[ImpactVersionTarget]:
    if manifest.version_source.type != "git":
        raise ImpactValidationError("impact version_source.type currently supports only git")
    targets: list[ImpactVersionTarget] = []
    seen: set[str] = set()
    for target in manifest.version_source.explicit:
        normalized = _normalize_ref(target.ref)
        if normalized in seen:
            continue
        targets.append(target)
        seen.add(normalized)
    discover = manifest.version_source.discover
    if discover.enabled:
        discovered = discover_git_tags(
            manifest.version_source.repository,
            include=discover.include,
            exclude=discover.exclude,
            limit=discover.limit,
        )
        for target in discovered:
            normalized = _normalize_ref(target.ref)
            if normalized in seen:
                continue
            targets.append(target)
            seen.add(normalized)
    if not targets:
        raise ImpactValidationError("impact manifest selected no version targets")
    return targets


def discover_git_tags(
    repository: str,
    *,
    include: list[str],
    exclude: list[str],
    limit: int,
) -> list[ImpactVersionTarget]:
    proc = _run_git(["ls-remote", "--tags", "--refs", repository])
    tags: list[str] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        ref = parts[1]
        if not ref.startswith("refs/tags/"):
            continue
        tag = ref.removeprefix("refs/tags/")
        if include and not any(fnmatch(tag, pattern) for pattern in include):
            continue
        if exclude and any(fnmatch(tag, pattern) for pattern in exclude):
            continue
        tags.append(tag)
    tags = sorted(set(tags), key=_semver_like_key)
    selected = tags[: max(1, limit)]
    return [
        ImpactVersionTarget(
            version=_version_from_tag(tag),
            ref=tag,
            source="discovered",
        )
        for tag in selected
    ]


def clone_repository(repository: str, repo_dir: Path) -> Path:
    if repo_dir.exists():
        return repo_dir
    ensure_directory(repo_dir.parent)
    _run_git(["clone", "--no-checkout", repository, str(repo_dir)])
    return repo_dir


def checkout_version(repo_dir: Path, target: ImpactVersionTarget, checkouts_dir: Path) -> Path:
    ensure_directory(checkouts_dir)
    checkout_dir = checkouts_dir / _safe_checkout_name(target)
    _run_git(["-C", str(repo_dir), "worktree", "add", "--detach", str(checkout_dir), target.ref])
    return checkout_dir


def evaluate_source_signatures(
    checkout_dir: Path,
    signatures: list[ImpactSourceSignature],
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for signature in signatures:
        path = _resolve_relative_path(checkout_dir, signature.file, label=f"source signature {signature.name}")
        if not path.exists() or not path.is_file():
            matches.append(
                {
                    "name": signature.name,
                    "classification": signature.classification,
                    "file": signature.file,
                    "matched": False,
                    "reason": "file_not_found",
                }
            )
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            matches.append(
                {
                    "name": signature.name,
                    "classification": signature.classification,
                    "file": signature.file,
                    "matched": False,
                    "reason": str(exc),
                }
            )
            continue
        matched = _signature_matches(content, signature)
        matches.append(
            {
                "name": signature.name,
                "classification": signature.classification,
                "file": signature.file,
                "matched": matched,
                "reason": "matched" if matched else "content_mismatch",
            }
        )
    return matches


def create_impact_dir(base_dir: str, label: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    root = ensure_directory(Path(base_dir).expanduser().resolve() / IMPACTS_DIR_NAME)
    safe = _safe_label(label)
    directory = root / f"{stamp}-{safe}"
    if not directory.exists():
        return ensure_directory(directory)
    suffix = 1
    while True:
        candidate = root / f"{stamp}-{safe}-{suffix}"
        if not candidate.exists():
            return ensure_directory(candidate)
        suffix += 1


def write_impact_report(report: ImpactReport, impact_dir: Path) -> None:
    ensure_directory(impact_dir)
    (impact_dir / IMPACT_STATE_FILE).write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (impact_dir / IMPACT_REPORT_MD).write_text(render_impact_markdown(report), encoding="utf-8")


def load_impact_report(impact_ref: str, runs_dir: str) -> ImpactReport:
    candidate = Path(impact_ref)
    if candidate.is_dir():
        impact_dir = candidate
    else:
        impact_dir = Path(runs_dir).expanduser().resolve() / IMPACTS_DIR_NAME / impact_ref
    data = json.loads((impact_dir / IMPACT_STATE_FILE).read_text(encoding="utf-8"))
    return ImpactReport.from_dict(data)


def list_impact_reports(runs_dir: str) -> list[ImpactReport]:
    base_dir = Path(runs_dir).expanduser().resolve() / IMPACTS_DIR_NAME
    if not base_dir.exists():
        return []
    reports: list[ImpactReport] = []
    for path in sorted(base_dir.iterdir(), reverse=True):
        if path.is_dir() and (path / IMPACT_STATE_FILE).exists():
            reports.append(load_impact_report(str(path), runs_dir))
    return sorted(reports, key=lambda item: item.created_at, reverse=True)


def render_impact_markdown(report: ImpactReport) -> str:
    counts: dict[str, int] = {}
    for version in report.versions:
        counts[version.status.value] = counts.get(version.status.value, 0) + 1
    lines = [
        "# Impact Report",
        "",
        f"- Impact ID: `{report.impact_id}`",
        f"- Name: `{report.name}`",
        f"- Advisory: `{report.advisory.id}`",
        f"- Project: `{report.advisory.project}`",
        f"- Created: `{report.created_at}`",
        f"- Manifest: `{report.manifest_ref}`",
        "",
        "## Status Counts",
        "",
    ]
    for status, count in sorted(counts.items()):
        lines.append(f"- `{status}`: `{count}`")
    lines.extend(
        [
            "",
            "## Versions",
            "",
            "| Version | Ref | Role | Status | Run | Evidence |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for version in report.versions:
        evidence = (version.evidence or version.error or "").replace("\n", " ")[:160]
        lines.append(
            f"| `{version.version}` | `{version.ref}` | `{version.role or 'n/a'}` | "
            f"`{version.status.value}` | `{version.run_id or 'n/a'}` | {evidence} |"
        )
    if report.intel:
        lines.extend(["", "## Public Intelligence", ""])
        for item in report.intel:
            title = item.title or item.url or "result"
            lines.append(f"- `{item.status}` {title} {item.url}")
    lines.append("")
    return "\n".join(lines)


def _impact_from_scan_result(result) -> tuple[ImpactStatus, str, list[dict[str, Any]]]:
    validations = [
        validation.to_dict()
        for record in result.records
        for validation in record.validations
    ]
    evidence = ""
    for record in result.records:
        if record.final.evidence:
            evidence = record.final.evidence
            break
    if any(record.final.status in {FindingStatus.CONFIRMED_KNOWN_POC, FindingStatus.CONFIRMED_GENERATED_POC} for record in result.records):
        return ImpactStatus.CONFIRMED_AFFECTED, evidence, validations
    if validations:
        statuses = {item["status"] for item in validations}
        if statuses and statuses <= {ValidationStatus.UNSUPPORTED.value}:
            return ImpactStatus.UNSUPPORTED, evidence, validations
        if any("build failed" in str(item.get("summary", "")).lower() for item in validations):
            return ImpactStatus.NOT_BUILDABLE, evidence, validations
        return ImpactStatus.NOT_REPRODUCED, evidence, validations
    if result.records:
        return ImpactStatus.UNKNOWN, evidence, validations
    return ImpactStatus.UNKNOWN, "", validations


def _derive_impact_status(
    runtime_status: ImpactStatus,
    source_matches: list[dict[str, Any]],
    role: str,
) -> ImpactStatus:
    if runtime_status is ImpactStatus.CONFIRMED_AFFECTED:
        return runtime_status
    matched = [item for item in source_matches if item.get("matched")]
    if any(item.get("classification") == "vulnerable" for item in matched):
        return ImpactStatus.LIKELY_AFFECTED
    if any(item.get("classification") == "fixed" for item in matched):
        return ImpactStatus.LIKELY_FIXED
    if role == "fixed_control" and runtime_status in {
        ImpactStatus.NOT_REPRODUCED,
        ImpactStatus.UNKNOWN,
        ImpactStatus.UNSUPPORTED,
    }:
        return ImpactStatus.LIKELY_FIXED
    return runtime_status


def _signature_matches(content: str, signature: ImpactSourceSignature) -> bool:
    if signature.contains_all and not all(token in content for token in signature.contains_all):
        return False
    if signature.contains_any and not any(token in content for token in signature.contains_any):
        return False
    if signature.absent_all and not all(token not in content for token in signature.absent_all):
        return False
    return bool(signature.contains_all or signature.contains_any or signature.absent_all)


def _source_evidence(matches: list[dict[str, Any]]) -> str:
    matched = [item for item in matches if item.get("matched")]
    if not matched:
        return ""
    return "; ".join(
        f"{item['classification']} source signature {item['name']} matched {item['file']}"
        for item in matched
    )


def _to_impact_intel(result: IntelResult) -> ImpactIntelResult:
    return ImpactIntelResult.from_dict(result.to_dict())


def _validate_manifest_shape(path: Path, data: dict[str, Any]) -> None:
    schema_version = _required_string(data, "schema_version", path)
    if schema_version != "0.1":
        raise ImpactValidationError(f"{path}: schema_version must be 0.1")
    _required_string(data, "name", path)
    advisory = _required_mapping(data, "advisory", path)
    _required_string(advisory, "id", path, prefix="advisory.")
    _required_string(advisory, "project", path, prefix="advisory.")
    _required_string(advisory, "summary", path, prefix="advisory.")
    for index, hint in enumerate(advisory.get("source_hints", [])):
        if not isinstance(hint, dict):
            raise ImpactValidationError(f"{path}: advisory.source_hints[{index}] must be an object")
        file_name = str(hint.get("file", ""))
        if file_name:
            _validate_relative_manifest_path(path, file_name, f"advisory.source_hints[{index}].file")

    version_source = _required_mapping(data, "version_source", path)
    source_type = _required_string(version_source, "type", path, prefix="version_source.")
    if source_type != "git":
        raise ImpactValidationError(f"{path}: version_source.type currently supports only git")
    _required_string(version_source, "repository", path, prefix="version_source.")
    explicit = version_source.get("explicit", [])
    if explicit is not None and not isinstance(explicit, list):
        raise ImpactValidationError(f"{path}: version_source.explicit must be a list")
    for index, item in enumerate(explicit or []):
        if not isinstance(item, dict):
            raise ImpactValidationError(f"{path}: version_source.explicit[{index}] must be an object")
        _required_string(item, "version", path, prefix=f"version_source.explicit[{index}].")
        _required_string(item, "ref", path, prefix=f"version_source.explicit[{index}].")

    discover = version_source.get("discover", {})
    if discover is not None and not isinstance(discover, dict):
        raise ImpactValidationError(f"{path}: version_source.discover must be an object")
    if isinstance(discover, dict) and "limit" in discover:
        limit = discover["limit"]
        if not isinstance(limit, int) or limit <= 0:
            raise ImpactValidationError(f"{path}: version_source.discover.limit must be a positive integer")

    replay = data.get("replay", {})
    if replay is not None and not isinstance(replay, dict):
        raise ImpactValidationError(f"{path}: replay must be an object")
    intelligence = data.get("intelligence", {})
    if intelligence is not None and not isinstance(intelligence, dict):
        raise ImpactValidationError(f"{path}: intelligence must be an object")
    if isinstance(intelligence, dict) and "max_results" in intelligence:
        max_results = intelligence["max_results"]
        if not isinstance(max_results, int) or max_results <= 0:
            raise ImpactValidationError(f"{path}: intelligence.max_results must be a positive integer")
        if max_results > 100:
            raise ImpactValidationError(f"{path}: intelligence.max_results must be less than or equal to 100")

    signatures = data.get("source_signatures", [])
    if signatures is not None and not isinstance(signatures, list):
        raise ImpactValidationError(f"{path}: source_signatures must be a list")
    for index, item in enumerate(signatures or []):
        if not isinstance(item, dict):
            raise ImpactValidationError(f"{path}: source_signatures[{index}] must be an object")
        _required_string(item, "name", path, prefix=f"source_signatures[{index}].")
        classification = _required_string(item, "classification", path, prefix=f"source_signatures[{index}].")
        if classification not in {"vulnerable", "fixed"}:
            raise ImpactValidationError(
                f"{path}: source_signatures[{index}].classification must be vulnerable or fixed"
            )
        file_name = _required_string(item, "file", path, prefix=f"source_signatures[{index}].")
        _validate_relative_manifest_path(path, file_name, f"source_signatures[{index}].file")
        for field_name in ("contains_all", "contains_any", "absent_all"):
            tokens = item.get(field_name, [])
            if tokens is not None and not isinstance(tokens, list):
                raise ImpactValidationError(f"{path}: source_signatures[{index}].{field_name} must be a list")


def _enforce_network_policy(manifest: ImpactManifest, allow_network: bool) -> None:
    if allow_network:
        return
    if manifest.intelligence.enabled:
        raise ImpactValidationError("impact intelligence requires --allow-network")
    if _looks_like_network_repository(manifest.version_source.repository):
        raise ImpactValidationError("network Git repositories require --allow-network")


def _looks_like_network_repository(repository: str) -> bool:
    if repository.startswith("file://"):
        return False
    if "://" in repository:
        return True
    if re.match(r"^[A-Za-z0-9_.-]+@[^:\s]+:.+", repository):
        return True
    return bool(re.match(r"^[A-Za-z0-9_.-]+:.+", repository))


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as exc:
        raise ImpactValidationError(f"{path}: invalid JSON manifest: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise ImpactValidationError(f"{path}: manifest must be a JSON object")
    return raw


def _required_mapping(data: dict[str, Any], key: str, path: Path) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ImpactValidationError(f"{path}: {key} must be an object")
    return value


def _required_string(
    data: dict[str, Any],
    key: str,
    path: Path,
    *,
    prefix: str = "",
) -> str:
    if key not in data:
        raise ImpactValidationError(f"{path}: missing required field {prefix}{key}")
    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise ImpactValidationError(f"{path}: {prefix}{key} must be a non-empty string")
    return value.strip()


def _validate_relative_manifest_path(manifest_path: Path, value: str, label: str) -> None:
    if "\\" in value:
        raise ImpactValidationError(f"{manifest_path}: {label} must use forward-slash relative paths")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ImpactValidationError(f"{manifest_path}: {label} must stay relative and cannot contain ..")


def _resolve_relative_path(base_dir: Path, value: str, *, label: str) -> Path:
    _validate_relative_manifest_path(base_dir, value, label)
    base = base_dir.resolve()
    path = (base / value).resolve()
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise ImpactValidationError(f"{label} must stay inside checkout") from exc
    return path


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise ImpactValidationError(f"git command failed: {_subprocess_error(exc)}") from exc


def _subprocess_error(exc: subprocess.CalledProcessError) -> str:
    output = "\n".join(part for part in [exc.stdout or "", exc.stderr or ""] if part).strip()
    return output or str(exc)


def _normalize_ref(ref: str) -> str:
    return ref.removeprefix("refs/tags/")


def _version_from_tag(tag: str) -> str:
    if re.match(r"^v\d", tag):
        return tag[1:]
    return tag


def _semver_like_key(value: str) -> tuple[Any, ...]:
    normalized = _version_from_tag(value)
    parts = re.split(r"([0-9]+)", normalized)
    key: list[tuple[int, Any]] = []
    for part in parts:
        if part == "":
            continue
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part))
    return tuple(key) if key else ((1, normalized),)


def _safe_checkout_name(target: ImpactVersionTarget) -> str:
    digest = sha1(f"{target.version}:{target.ref}".encode("utf-8")).hexdigest()[:8]
    return f"{_safe_label(target.version)}-{digest}"


def _safe_label(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "-" for ch in value.strip())
    return safe.strip(".-") or "impact"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
