import importlib
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ProjectRenameTests(unittest.TestCase):
    def test_new_package_name_is_primary_import(self) -> None:
        cli = importlib.import_module("oss_vuln_lab.cli")

        self.assertTrue(callable(cli.main))

    def test_legacy_package_name_remains_importable(self) -> None:
        cli = importlib.import_module("oss_vuln_digger.cli")

        self.assertTrue(callable(cli.main))

    def test_legacy_package_aliases_public_modules(self) -> None:
        legacy_package = importlib.import_module("oss_vuln_digger")
        new_models = importlib.import_module("oss_vuln_lab.models")
        old_models = importlib.import_module("oss_vuln_digger.models")
        old_cli = importlib.import_module("oss_vuln_digger.cli")

        self.assertIs(old_models, new_models)
        self.assertIs(old_models.ScanResult, new_models.ScanResult)
        self.assertIs(legacy_package.models, new_models)
        self.assertIs(legacy_package.cli, old_cli)

    def test_module_entrypoints_show_primary_program_name(self) -> None:
        for module in ("oss_vuln_lab", "oss_vuln_digger"):
            with self.subTest(module=module):
                proc = subprocess.run(
                    [sys.executable, "-m", module, "--help"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertIn("usage: ovl", proc.stdout)
                self.assertIn("Local-first OSS vulnerability research lab", proc.stdout)

    def test_console_scripts_declare_new_and_legacy_names(self) -> None:
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual(pyproject["project"]["scripts"]["ovl"], "oss_vuln_lab.cli:main")
        self.assertEqual(pyproject["project"]["scripts"]["ovd"], "oss_vuln_lab.cli:main")
