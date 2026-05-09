import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oss_vuln_digger.automation import BatchRunner
from oss_vuln_digger.cli import main
from oss_vuln_digger.config import AppConfig
from oss_vuln_digger.dashboard import write_dashboard
from oss_vuln_digger.pipeline import ScanEngine
from oss_vuln_digger.registry import build_default_registry


class DashboardTests(unittest.TestCase):
    def test_write_dashboard_includes_runs_and_batches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            corpus = root / "corpus"
            runs = root / "runs"
            batch_manifest = root / "batch.json"
            project.mkdir()
            corpus.mkdir()

            (project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            (project / "app.py").write_text(
                "\n".join(
                    [
                        "import os",
                        "",
                        "def candidate(cmd):",
                        "    os.system(cmd)",
                    ]
                ),
                encoding="utf-8",
            )
            (corpus / "CVE-2099-1020.json").write_text(
                json.dumps(
                    {
                        "cve_id": "CVE-2099-1020",
                        "summary": "Dashboard corpus demo",
                        "project": "demo-app",
                        "language": "python",
                        "vuln_family": "command_execution",
                        "replay": {
                            "title": "Dashboard corpus",
                            "vuln_family": "command_execution",
                            "repro_command": "python3 app.py @payload_path@",
                            "artifacts": [{"name": "payload.txt", "content": "boom\n"}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            engine = ScanEngine(AppConfig(runs_dir=str(runs), corpus_dir=str(corpus)), build_default_registry())
            scan_result = engine.scan(str(project))
            batch_manifest.write_text(
                json.dumps(
                    {
                        "name": "dashboard-batch",
                        "jobs": [
                            {"name": "scan-demo-a", "mode": "scan", "target": str(project)},
                            {"name": "scan-demo-b", "mode": "scan", "target": str(project)},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            batch_result = BatchRunner(engine).run_manifest(str(batch_manifest))

            output_path = write_dashboard(str(runs), corpus_dir=str(corpus))
            html = output_path.read_text(encoding="utf-8")

            self.assertIn(scan_result.run_id, html)
            self.assertIn(batch_result.batch_id, html)
            self.assertIn("CVE-2099-1020", html)
            self.assertIn("Findings and evidence", html)
            self.assertIn("Review batch details", html)
            self.assertIn("Deduplication", html)
            self.assertIn("Local Dashboard", html)

    def test_cli_ui_build_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            runs = root / "runs"
            output_dir = root / "ui"
            config = root / "config.toml"
            project.mkdir()
            (project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            (project / "app.py").write_text(
                "\n".join(
                    [
                        "import os",
                        "",
                        "def candidate(cmd):",
                        "    os.system(cmd)",
                    ]
                ),
                encoding="utf-8",
            )
            engine = ScanEngine(AppConfig(runs_dir=str(runs)), build_default_registry())
            engine.scan(str(project))
            config.write_text("\n".join(["[app]", f'runs_dir = "{runs}"']), encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["--config", str(config), "ui", "build", "--output-dir", str(output_dir)])

            self.assertEqual(exit_code, 0)
            self.assertTrue((output_dir / "index.html").exists())
            self.assertIn("Dashboard:", stdout.getvalue())
