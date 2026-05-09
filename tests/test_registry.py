import unittest
from pathlib import Path
import tempfile

from oss_vuln_digger.config import LLMConfig
from oss_vuln_digger.models import ScanTarget, TargetMode
from oss_vuln_digger.plugins.base import LLMProvider, ProjectAdapter
from oss_vuln_digger.registry import Registry, build_default_registry


class DummyProvider(LLMProvider):
    name = "dummy"

    def analyze_candidate(self, context):
        raise NotImplementedError

    def generate_poc(self, context):
        raise NotImplementedError

    def suggest_fix(self, context):
        return "fix"


class DummyAdapter(ProjectAdapter):
    name = "dummy"

    def supports_target(self, target: ScanTarget) -> bool:
        return target.mode is TargetMode.SOURCE_REPO

    def prepare(self, target):
        raise NotImplementedError


class RegistryTests(unittest.TestCase):
    def test_default_registry_contains_builtin_extension_points(self) -> None:
        registry = build_default_registry()
        self.assertIn("cpp_source", registry.project_adapters)
        self.assertIn("python_source", registry.project_adapters)
        self.assertIn("javascript_source", registry.project_adapters)
        self.assertIn("elf_binary", registry.project_adapters)
        self.assertIn("memory_safety", registry.vuln_families)
        self.assertIn("sql_injection", registry.vuln_families)
        self.assertIn("binary_surface", registry.vuln_families)
        self.assertIn("docker_build", registry.validators)
        self.assertIn("direct_runtime", registry.validators)
        self.assertIn("local", registry.provider_factories)

    def test_registry_accepts_custom_provider_and_adapter(self) -> None:
        registry = Registry()
        registry.register_project_adapter(DummyAdapter())
        registry.register_provider("dummy", DummyProvider)

        target = ScanTarget(spec="x", resolved_path="/tmp/x", mode=TargetMode.SOURCE_REPO, origin="local_path")
        adapter = registry.resolve_project_adapter(target)
        provider = registry.build_provider(LLMConfig(provider="dummy"))

        self.assertEqual(adapter.name, "dummy")
        self.assertIsInstance(provider, DummyProvider)

    def test_registry_picks_python_adapter_for_python_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import os\nif __name__ == '__main__':\n    os.system(input())\n",
                encoding="utf-8",
            )
            registry = build_default_registry()
            target = ScanTarget(spec=str(root), resolved_path=str(root), mode=TargetMode.SOURCE_REPO, origin="local_path")
            adapter = registry.resolve_project_adapter(target)
            context = adapter.prepare(target)

            self.assertEqual(adapter.name, "python_source")
            self.assertEqual(context.primary_language.value, "python")
