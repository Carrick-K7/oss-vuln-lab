from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from oss_vuln_digger.models import Candidate, CandidateKind, ProjectContext, TargetMode
from oss_vuln_digger.plugins.base import VulnFamilyPlugin


CPP_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
PYTHON_SUFFIXES = {".py"}
JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
JAVA_SUFFIXES = {".java"}
RUST_SUFFIXES = {".rs"}
ALL_SOURCE_SUFFIXES = CPP_SUFFIXES | PYTHON_SUFFIXES | JAVASCRIPT_SUFFIXES | JAVA_SUFFIXES | RUST_SUFFIXES

CPP_FUNCTION_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_:<>~]*)\s*\([^;]*\)\s*\{?\s*$")
PYTHON_FUNCTION_RE = re.compile(r"def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
JAVASCRIPT_FUNCTION_RE = re.compile(
    r"(?:function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)"
)
RUST_FUNCTION_RE = re.compile(r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
CONTROL_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch"}


@dataclass(frozen=True, slots=True)
class TokenRule:
    suffixes: frozenset[str]
    tokens: tuple[str, ...]
    title: str
    severity: str
    kind: CandidateKind
    candidate_only: bool = False
    required_fragments: tuple[str, ...] = ()


class MemorySafetyPlugin(VulnFamilyPlugin):
    name = "memory_safety"
    _patterns = (
        (re.compile(r"\bgets\s*\("), "Unbounded input sink", "high"),
        (re.compile(r"\bstrcpy\s*\("), "Unbounded copy sink", "high"),
        (re.compile(r"\bstrcat\s*\("), "Unbounded append sink", "high"),
        (re.compile(r"\bsprintf\s*\("), "Potential format and overflow sink", "high"),
        (re.compile(r"\b(?:_TIFF)?memcpy\s*\("), "Copy using caller-controlled length", "high"),
        (re.compile(r"\b(?:_TIFF)?memmove\s*\("), "Move using caller-controlled length", "high"),
        (re.compile(r"\b(?:_TIFF)?memset\s*\("), "Memory fill using caller-controlled length", "medium"),
        (re.compile(r"\bfree\s*\("), "Manual lifetime management sink", "medium"),
        (re.compile(r"\bget_unchecked(?:_mut)?\s*\("), "Unchecked slice access", "high"),
    )

    def supports_mode(self, target_mode: str) -> bool:
        return target_mode == TargetMode.SOURCE_REPO.value

    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        candidates: list[Candidate] = []
        for file_path in project.source_files:
            suffix = Path(file_path).suffix.lower()
            if suffix not in CPP_SUFFIXES | RUST_SUFFIXES:
                continue
            lines = Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
            for index, line in enumerate(lines, start=1):
                for pattern, title, severity in self._patterns:
                    if pattern.search(line):
                        function_name = _guess_function_name(lines, index - 1, suffix)
                        candidates.append(
                            _make_candidate(
                                vuln_family=self.name,
                                title=title,
                                target_mode=TargetMode.SOURCE_REPO,
                                file_path=file_path,
                                line=index,
                                function_or_sink=function_name or _sink_name_from_line(line),
                                evidence_seed=line.strip(),
                                severity_hint=severity,
                                kind=CandidateKind.MEMORY_OPERATION,
                                candidate_only=False,
                            )
                        )
        return candidates

    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, object]:
        return _base_context(candidate, project)

    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        return ["docker_build", "sanitizer_runtime", "host_build", "host_sanitizer_runtime"]


class BoundaryValidationPlugin(VulnFamilyPlugin):
    name = "boundary_validation"
    _interesting_tokens = ("atoi(", "strtol(", "sscanf(", "malloc(", "realloc(", "memcpy(", "read(", "Vec::with_capacity(")
    _size_names = ("len", "size", "count", "n", "argc", "length", "capacity")

    def supports_mode(self, target_mode: str) -> bool:
        return target_mode == TargetMode.SOURCE_REPO.value

    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        candidates: list[Candidate] = []
        for file_path in project.source_files:
            suffix = Path(file_path).suffix.lower()
            if suffix not in CPP_SUFFIXES | RUST_SUFFIXES:
                continue
            lines = Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
            for index, line in enumerate(lines, start=1):
                if not any(token in line for token in self._interesting_tokens):
                    continue
                if not any(name in line for name in self._size_names):
                    continue
                function_name = _guess_function_name(lines, index - 1, suffix)
                candidates.append(
                    _make_candidate(
                        vuln_family=self.name,
                        title="Length or bounds-sensitive operation",
                        target_mode=TargetMode.SOURCE_REPO,
                        file_path=file_path,
                        line=index,
                        function_or_sink=function_name or "length-sensitive-operation",
                        evidence_seed=line.strip(),
                        severity_hint="medium",
                        kind=CandidateKind.SIZE_VALIDATION,
                        candidate_only=False,
                    )
                )
        return candidates

    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, object]:
        return _base_context(candidate, project)

    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        return ["docker_build", "sanitizer_runtime", "host_build", "host_sanitizer_runtime"]


class CommandExecutionPlugin(VulnFamilyPlugin):
    name = "command_execution"
    _rules = (
        TokenRule(frozenset(CPP_SUFFIXES), ("system(", "popen(", "execl(", "execv(", "execve("), "Command execution sink", "high", CandidateKind.COMMAND_EXECUTION, True),
        TokenRule(frozenset(PYTHON_SUFFIXES), ("os.system(", "subprocess.run(", "subprocess.Popen(", "subprocess.call(", "os.popen("), "Command execution sink", "high", CandidateKind.COMMAND_EXECUTION, True),
        TokenRule(frozenset(JAVASCRIPT_SUFFIXES), ("exec(", "execSync(", "spawn(", "spawnSync("), "Command execution sink", "high", CandidateKind.COMMAND_EXECUTION, True, ("child_process",)),
        TokenRule(frozenset(JAVA_SUFFIXES), ("Runtime.getRuntime().exec(", "new ProcessBuilder("), "Command execution sink", "high", CandidateKind.COMMAND_EXECUTION, True),
        TokenRule(frozenset(RUST_SUFFIXES), ("Command::new(",), "Command execution sink", "high", CandidateKind.COMMAND_EXECUTION, True),
    )

    def supports_mode(self, target_mode: str) -> bool:
        return target_mode == TargetMode.SOURCE_REPO.value

    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        return _extract_rule_candidates(project, self.name, self._rules)

    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, object]:
        return _base_context(candidate, project)

    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        return ["direct_runtime"]


class PathTraversalPlugin(VulnFamilyPlugin):
    name = "path_traversal"
    _rules = (
        TokenRule(frozenset(CPP_SUFFIXES), ("fopen(", "open(", "ifstream", "ofstream", "access("), "Filesystem path sink", "medium", CandidateKind.FILESYSTEM_PATH, True, ("path", "file", "name", "argv", "input")),
        TokenRule(frozenset(PYTHON_SUFFIXES), ("open(", "Path(", "send_file(", "FileResponse("), "Filesystem path sink", "medium", CandidateKind.FILESYSTEM_PATH, True, ("path", "file", "name", "request", "input")),
        TokenRule(frozenset(JAVASCRIPT_SUFFIXES), ("fs.readFile", "fs.writeFile", "fs.open", "sendFile(", "readFileSync("), "Filesystem path sink", "medium", CandidateKind.FILESYSTEM_PATH, True, ("path", "file", "name", "req", "input")),
        TokenRule(frozenset(JAVA_SUFFIXES), ("Files.readString(", "Files.newInputStream(", "new FileInputStream(", "Paths.get("), "Filesystem path sink", "medium", CandidateKind.FILESYSTEM_PATH, True, ("path", "file", "name", "request")),
        TokenRule(frozenset(RUST_SUFFIXES), ("File::open(", "fs::read(", "fs::write(", "fs::read_to_string("), "Filesystem path sink", "medium", CandidateKind.FILESYSTEM_PATH, True, ("path", "file", "name", "input")),
    )

    def supports_mode(self, target_mode: str) -> bool:
        return target_mode == TargetMode.SOURCE_REPO.value

    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        return _extract_rule_candidates(project, self.name, self._rules)

    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, object]:
        return _base_context(candidate, project)

    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        return ["direct_runtime"]


class DeserializationPlugin(VulnFamilyPlugin):
    name = "deserialization"
    _rules = (
        TokenRule(frozenset(PYTHON_SUFFIXES), ("pickle.loads(", "pickle.load(", "yaml.load(", "marshal.loads("), "Unsafe deserialization sink", "high", CandidateKind.DESERIALIZATION, True),
        TokenRule(frozenset(JAVA_SUFFIXES), ("new ObjectInputStream(", ".readObject("), "Unsafe deserialization sink", "high", CandidateKind.DESERIALIZATION, True),
        TokenRule(frozenset(RUST_SUFFIXES), ("bincode::deserialize(", "rmp_serde::from_read("), "Unsafe deserialization sink", "medium", CandidateKind.DESERIALIZATION, True),
    )

    def supports_mode(self, target_mode: str) -> bool:
        return target_mode == TargetMode.SOURCE_REPO.value

    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        return _extract_rule_candidates(project, self.name, self._rules)

    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, object]:
        return _base_context(candidate, project)

    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        return ["direct_runtime"]


class SqlInjectionPlugin(VulnFamilyPlugin):
    name = "sql_injection"
    _query_tokens = (".execute(", ".executemany(", ".query(", ".executeQuery(", ".executeUpdate(", "createStatement(")
    _dynamic_fragments = (" + ", ".format(", "%s", "%(", "f\"", "f'", "`SELECT", "`INSERT", "`UPDATE", "format!(")

    def supports_mode(self, target_mode: str) -> bool:
        return target_mode == TargetMode.SOURCE_REPO.value

    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        candidates: list[Candidate] = []
        for file_path in project.source_files:
            suffix = Path(file_path).suffix.lower()
            if suffix not in PYTHON_SUFFIXES | JAVASCRIPT_SUFFIXES | JAVA_SUFFIXES | RUST_SUFFIXES:
                continue
            lines = Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
            for index, line in enumerate(lines, start=1):
                if not any(token in line for token in self._query_tokens):
                    continue
                if not any(fragment in line for fragment in self._dynamic_fragments):
                    continue
                function_name = _guess_function_name(lines, index - 1, suffix)
                candidates.append(
                    _make_candidate(
                        vuln_family=self.name,
                        title="Dynamically constructed SQL query",
                        target_mode=TargetMode.SOURCE_REPO,
                        file_path=file_path,
                        line=index,
                        function_or_sink=function_name or "query-execution",
                        evidence_seed=line.strip(),
                        severity_hint="high",
                        kind=CandidateKind.SQL_QUERY,
                        candidate_only=True,
                    )
                )
        return candidates

    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, object]:
        return _base_context(candidate, project)

    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        return ["direct_runtime"]


class SsrfPlugin(VulnFamilyPlugin):
    name = "ssrf"
    _rules = (
        TokenRule(frozenset(PYTHON_SUFFIXES), ("requests.get(", "requests.post(", "urllib.request.urlopen("), "Outbound network request sink", "medium", CandidateKind.NETWORK_REQUEST, True, ("url", "uri", "request", "input")),
        TokenRule(frozenset(JAVASCRIPT_SUFFIXES), ("fetch(", "axios.get(", "axios.post(", "http.get(", "https.get("), "Outbound network request sink", "medium", CandidateKind.NETWORK_REQUEST, True, ("url", "uri", "req", "input")),
        TokenRule(frozenset(JAVA_SUFFIXES), ("new URL(", "HttpClient.newHttpClient(", ".send("), "Outbound network request sink", "medium", CandidateKind.NETWORK_REQUEST, True, ("url", "uri", "request")),
        TokenRule(frozenset(RUST_SUFFIXES), ("reqwest::get(", ".get(", ".post("), "Outbound network request sink", "medium", CandidateKind.NETWORK_REQUEST, True, ("url", "uri", "request")),
    )

    def supports_mode(self, target_mode: str) -> bool:
        return target_mode == TargetMode.SOURCE_REPO.value

    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        return _extract_rule_candidates(project, self.name, self._rules)

    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, object]:
        return _base_context(candidate, project)

    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        return ["direct_runtime"]


class XxePlugin(VulnFamilyPlugin):
    name = "xxe"
    _rules = (
        TokenRule(frozenset(PYTHON_SUFFIXES), ("lxml.etree.fromstring(", "etree.parse(",), "XML parser sink", "medium", CandidateKind.XML_PARSER, True),
        TokenRule(frozenset(JAVA_SUFFIXES), ("DocumentBuilderFactory.newInstance(", "SAXParserFactory.newInstance(", "XMLInputFactory.newFactory("), "XML parser sink", "high", CandidateKind.XML_PARSER, True),
    )

    def supports_mode(self, target_mode: str) -> bool:
        return target_mode == TargetMode.SOURCE_REPO.value

    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        return _extract_rule_candidates(project, self.name, self._rules)

    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, object]:
        return _base_context(candidate, project)

    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        return ["direct_runtime"]


class TemplateInjectionPlugin(VulnFamilyPlugin):
    name = "template_injection"
    _rules = (
        TokenRule(frozenset(PYTHON_SUFFIXES), ("Template(", "render_template_string("), "Template rendering sink", "medium", CandidateKind.TEMPLATE_RENDER, True),
        TokenRule(frozenset(JAVASCRIPT_SUFFIXES), ("handlebars.compile(", "ejs.render(", "nunjucks.renderString("), "Template rendering sink", "medium", CandidateKind.TEMPLATE_RENDER, True),
        TokenRule(frozenset(JAVA_SUFFIXES), ("Velocity.evaluate(", "processTemplate(", "TemplateEngine.process("), "Template rendering sink", "medium", CandidateKind.TEMPLATE_RENDER, True),
    )

    def supports_mode(self, target_mode: str) -> bool:
        return target_mode == TargetMode.SOURCE_REPO.value

    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        return _extract_rule_candidates(project, self.name, self._rules)

    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, object]:
        return _base_context(candidate, project)

    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        return ["direct_runtime"]


class BinarySurfacePlugin(VulnFamilyPlugin):
    name = "binary_surface"
    _byte_patterns = (b"strcpy", b"memcpy", b"system", b"popen", b"malloc")

    def supports_mode(self, target_mode: str) -> bool:
        return target_mode == TargetMode.BINARY_ARTIFACT.value

    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        binary_path = Path(project.source_files[0])
        payload = binary_path.read_bytes()
        candidates: list[Candidate] = []
        for token in self._byte_patterns:
            if token in payload:
                candidates.append(
                    _make_candidate(
                        vuln_family=self.name,
                        title="Binary exports or references risky symbol",
                        target_mode=TargetMode.BINARY_ARTIFACT,
                        file_path=str(binary_path),
                        line=None,
                        function_or_sink=token.decode("ascii"),
                        evidence_seed=f"Binary references symbol {token.decode('ascii')}",
                        severity_hint="medium",
                        kind=CandidateKind.BINARY_SYMBOL,
                        candidate_only=True,
                    )
                )
        return candidates

    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, object]:
        return _base_context(candidate, project)

    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        return []


def _extract_rule_candidates(
    project: ProjectContext,
    vuln_family: str,
    rules: Iterable[TokenRule],
) -> list[Candidate]:
    candidates: list[Candidate] = []
    compiled_rules = list(rules)
    for file_path in project.source_files:
        suffix = Path(file_path).suffix.lower()
        if suffix not in ALL_SOURCE_SUFFIXES:
            continue
        lines = Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
        for index, line in enumerate(lines, start=1):
            for rule in compiled_rules:
                if suffix not in rule.suffixes:
                    continue
                if not any(token in line for token in rule.tokens):
                    continue
                if rule.required_fragments and not any(fragment in line for fragment in rule.required_fragments):
                    continue
                function_name = _guess_function_name(lines, index - 1, suffix)
                candidates.append(
                    _make_candidate(
                        vuln_family=vuln_family,
                        title=rule.title,
                        target_mode=TargetMode.SOURCE_REPO,
                        file_path=file_path,
                        line=index,
                        function_or_sink=function_name or rule.title.lower().replace(" ", "-"),
                        evidence_seed=line.strip(),
                        severity_hint=rule.severity,
                        kind=rule.kind,
                        candidate_only=rule.candidate_only,
                    )
                )
    return candidates


def _guess_function_name(lines: list[str], index: int, suffix: str) -> str:
    for cursor in range(index, -1, -1):
        line = lines[cursor].strip()
        if not line or line.startswith(("#", "//")):
            continue
        if suffix in PYTHON_SUFFIXES:
            match = PYTHON_FUNCTION_RE.search(line)
            if match:
                return match.group(1)
        elif suffix in JAVASCRIPT_SUFFIXES:
            match = JAVASCRIPT_FUNCTION_RE.search(line)
            if match:
                return next(group for group in match.groups() if group)
        elif suffix in RUST_SUFFIXES:
            match = RUST_FUNCTION_RE.search(line)
            if match:
                return match.group(1)
        else:
            match = CPP_FUNCTION_RE.search(line)
            if match and match.group(1) not in CONTROL_KEYWORDS:
                return match.group(1)
    return ""


def _make_candidate(
    vuln_family: str,
    title: str,
    target_mode: TargetMode,
    file_path: str,
    line: int | None,
    function_or_sink: str,
    evidence_seed: str,
    severity_hint: str,
    kind: CandidateKind,
    candidate_only: bool,
) -> Candidate:
    digest = hashlib.sha1(
        f"{vuln_family}:{file_path}:{line}:{function_or_sink}:{evidence_seed}".encode("utf-8")
    ).hexdigest()[:12]
    return Candidate(
        id=digest,
        title=title,
        vuln_family=vuln_family,
        target_mode=target_mode,
        file_path=file_path,
        line=line,
        function_or_sink=function_or_sink,
        evidence_seed=evidence_seed,
        severity_hint=severity_hint,
        kind=kind,
        candidate_only=candidate_only,
        metadata={"snippet": evidence_seed},
    )


def _base_context(candidate: Candidate, project: ProjectContext) -> dict[str, object]:
    return {
        "candidate": candidate.to_dict(),
        "project": project.to_dict(),
        "primary_language": project.primary_language.value,
        "language_profiles": [profile.to_dict() for profile in project.language_profiles],
    }


def _sink_name_from_line(line: str) -> str:
    token = line.strip().split("(", maxsplit=1)[0]
    return token.split()[-1] if token else "sink"
