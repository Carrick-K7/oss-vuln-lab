import tempfile
import unittest
from pathlib import Path

from oss_vuln_digger.models import ScanTarget, TargetMode
from oss_vuln_digger.registry import build_default_registry


class AdapterTests(unittest.TestCase):
    def test_javascript_java_and_rust_projects_select_expected_adapters(self) -> None:
        registry = build_default_registry()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            js_root = root / "js"
            js_root.mkdir()
            (js_root / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
            (js_root / "index.js").write_text(
                "if (require.main === module) { console.log(process.argv[2]); }\n",
                encoding="utf-8",
            )
            js_target = ScanTarget(spec=str(js_root), resolved_path=str(js_root), mode=TargetMode.SOURCE_REPO, origin="local_path")
            js_context = registry.resolve_project_adapter(js_target).prepare(js_target)
            self.assertEqual(js_context.adapter_name, "javascript_source")
            self.assertEqual(js_context.primary_language.value, "javascript")

            java_root = root / "java"
            java_root.mkdir()
            (java_root / "pom.xml").write_text("<project />\n", encoding="utf-8")
            (java_root / "Main.java").write_text(
                "class Main { public static void main(String[] args) {} }\n",
                encoding="utf-8",
            )
            java_target = ScanTarget(spec=str(java_root), resolved_path=str(java_root), mode=TargetMode.SOURCE_REPO, origin="local_path")
            java_context = registry.resolve_project_adapter(java_target).prepare(java_target)
            self.assertEqual(java_context.adapter_name, "java_source")
            self.assertEqual(java_context.primary_language.value, "java")

            rust_root = root / "rust"
            rust_root.mkdir()
            (rust_root / "Cargo.toml").write_text("[package]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
            (rust_root / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
            rust_target = ScanTarget(spec=str(rust_root), resolved_path=str(rust_root), mode=TargetMode.SOURCE_REPO, origin="local_path")
            rust_context = registry.resolve_project_adapter(rust_target).prepare(rust_target)
            self.assertEqual(rust_context.adapter_name, "rust_source")
            self.assertEqual(rust_context.primary_language.value, "rust")
