from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from oss_vuln_digger.config import LLMConfig
from oss_vuln_digger.models import (
    AnalysisResult,
    Candidate,
    PocSpec,
    ProjectContext,
    ScanTarget,
    ValidationResult,
)


class ProjectAdapter(ABC):
    name: str

    def match_score(self, target: ScanTarget) -> int:
        return 100 if self.supports_target(target) else 0

    @abstractmethod
    def supports_target(self, target: ScanTarget) -> bool:
        raise NotImplementedError

    @abstractmethod
    def prepare(self, target: ScanTarget) -> ProjectContext:
        raise NotImplementedError


class VulnFamilyPlugin(ABC):
    name: str

    @abstractmethod
    def supports_mode(self, target_mode: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def extract_candidates(self, project: ProjectContext) -> list[Candidate]:
        raise NotImplementedError

    @abstractmethod
    def build_llm_context(self, candidate: Candidate, project: ProjectContext) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def suggest_validation_kinds(self, candidate: Candidate) -> list[str]:
        raise NotImplementedError


class Validator(ABC):
    name: str

    @abstractmethod
    def supports(self, project: ProjectContext, candidate: Candidate, poc: PocSpec) -> bool:
        raise NotImplementedError

    @abstractmethod
    def run(
        self,
        project: ProjectContext,
        candidate: Candidate,
        poc: PocSpec,
        run_dir: Path,
    ) -> ValidationResult:
        raise NotImplementedError


class LLMProvider(ABC):
    name: str

    def __init__(self, config: LLMConfig):
        self.config = config

    @abstractmethod
    def analyze_candidate(self, context: dict[str, Any]) -> AnalysisResult:
        raise NotImplementedError

    @abstractmethod
    def generate_poc(self, context: dict[str, Any]) -> PocSpec:
        raise NotImplementedError

    @abstractmethod
    def suggest_fix(self, context: dict[str, Any]) -> str:
        raise NotImplementedError
