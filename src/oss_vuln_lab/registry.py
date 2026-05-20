from __future__ import annotations

from collections import OrderedDict
from typing import Callable

from oss_vuln_lab.config import LLMConfig
from oss_vuln_lab.models import ScanTarget, TargetMode
from oss_vuln_lab.plugins.base import LLMProvider, ProjectAdapter, Validator, VulnFamilyPlugin
from oss_vuln_lab.plugins.llm import LocalHeuristicProvider, OpenAICompatibleProvider, OpenAIProvider
from oss_vuln_lab.plugins.project_adapters import CppSourceAdapter, ElfBinaryAdapter
from oss_vuln_lab.plugins.validators import (
    DirectRuntimeValidator,
    DockerBuildValidator,
    HostBuildValidator,
    HostSanitizerRuntimeValidator,
    SanitizerRuntimeValidator,
)
from oss_vuln_lab.plugins.vuln_families import (
    BinarySurfacePlugin,
    BoundaryValidationPlugin,
    CommandExecutionPlugin,
    DeserializationPlugin,
    MemorySafetyPlugin,
    PathTraversalPlugin,
    SqlInjectionPlugin,
    SsrfPlugin,
    TemplateInjectionPlugin,
    XxePlugin,
)
from oss_vuln_lab.plugins.project_adapters import (
    JavaScriptSourceAdapter,
    JavaSourceAdapter,
    PythonSourceAdapter,
    RustSourceAdapter,
)


ProviderFactory = Callable[[LLMConfig], LLMProvider]


class Registry:
    def __init__(self) -> None:
        self.project_adapters: "OrderedDict[str, ProjectAdapter]" = OrderedDict()
        self.vuln_families: "OrderedDict[str, VulnFamilyPlugin]" = OrderedDict()
        self.validators: "OrderedDict[str, Validator]" = OrderedDict()
        self.provider_factories: dict[str, ProviderFactory] = {}

    def register_project_adapter(self, adapter: ProjectAdapter) -> None:
        self.project_adapters[adapter.name] = adapter

    def register_vuln_family(self, plugin: VulnFamilyPlugin) -> None:
        self.vuln_families[plugin.name] = plugin

    def register_validator(self, validator: Validator) -> None:
        self.validators[validator.name] = validator

    def register_provider(self, name: str, factory: ProviderFactory) -> None:
        self.provider_factories[name] = factory

    def resolve_project_adapter(self, target: ScanTarget) -> ProjectAdapter:
        best_match: ProjectAdapter | None = None
        best_score = 0
        for adapter in self.project_adapters.values():
            score = adapter.match_score(target)
            if score > best_score:
                best_match = adapter
                best_score = score
        if best_match is not None:
            return best_match
        for adapter in self.project_adapters.values():
            if adapter.supports_target(target):
                return adapter
        raise ValueError(f"No project adapter supports target mode {target.mode.value}: {target.resolved_path}")

    def vuln_plugins_for_mode(self, target_mode: TargetMode) -> list[VulnFamilyPlugin]:
        return [
            plugin
            for plugin in self.vuln_families.values()
            if plugin.supports_mode(target_mode.value)
        ]

    def build_provider(self, config: LLMConfig) -> LLMProvider:
        try:
            return self.provider_factories[config.provider](config)
        except KeyError as exc:
            raise ValueError(f"Unsupported LLM provider: {config.provider}") from exc

    def resolve_validators(self, names: list[str]) -> list[Validator]:
        resolved: list[Validator] = []
        for name in names:
            validator = self.validators.get(name)
            if validator:
                resolved.append(validator)
        return resolved


def build_default_registry() -> Registry:
    registry = Registry()
    registry.register_project_adapter(PythonSourceAdapter())
    registry.register_project_adapter(JavaScriptSourceAdapter())
    registry.register_project_adapter(JavaSourceAdapter())
    registry.register_project_adapter(RustSourceAdapter())
    registry.register_project_adapter(CppSourceAdapter())
    registry.register_project_adapter(ElfBinaryAdapter())

    registry.register_vuln_family(MemorySafetyPlugin())
    registry.register_vuln_family(BoundaryValidationPlugin())
    registry.register_vuln_family(CommandExecutionPlugin())
    registry.register_vuln_family(PathTraversalPlugin())
    registry.register_vuln_family(DeserializationPlugin())
    registry.register_vuln_family(SqlInjectionPlugin())
    registry.register_vuln_family(SsrfPlugin())
    registry.register_vuln_family(XxePlugin())
    registry.register_vuln_family(TemplateInjectionPlugin())
    registry.register_vuln_family(BinarySurfacePlugin())

    registry.register_validator(DockerBuildValidator())
    registry.register_validator(SanitizerRuntimeValidator())
    registry.register_validator(HostBuildValidator())
    registry.register_validator(HostSanitizerRuntimeValidator())
    registry.register_validator(DirectRuntimeValidator())

    registry.register_provider("local", LocalHeuristicProvider)
    registry.register_provider("openai", OpenAIProvider)
    registry.register_provider("openai_compatible", OpenAICompatibleProvider)
    return registry
