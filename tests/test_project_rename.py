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

    def test_module_entrypoints_show_primary_program_name(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "oss_vuln_lab", "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )

        self.assertIn("usage: ovl", proc.stdout)
        self.assertIn("Local-first OSS vulnerability research lab", proc.stdout)

    def test_console_scripts_declare_only_canonical_name(self) -> None:
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual(pyproject["project"]["scripts"]["ovl"], "oss_vuln_lab.cli:main")
        self.assertEqual(set(pyproject["project"]["scripts"]), {"ovl"})
