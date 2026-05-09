import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from oss_vuln_digger.automation import (
    BatchJobSpec,
    BatchRunner,
    BatchSpec,
    ScheduleRunner,
    load_batch_result,
    schedule_state_path,
)
from oss_vuln_digger.cli import main
from oss_vuln_digger.config import AppConfig
from oss_vuln_digger.pipeline import ScanEngine
from oss_vuln_digger.registry import build_default_registry


class AutomationTests(unittest.TestCase):
    def test_batch_runner_executes_scan_and_replay_jobs(self) -> None:
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
                        "import pathlib",
                        "import sys",
                        "",
                        "def candidate(cmd):",
                        "    os.system(cmd)",
                        "",
                        "if __name__ == '__main__':",
                        "    payload = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').strip()",
                        "    if payload == 'boom':",
                        "        raise RuntimeError('boom')",
                    ]
                ),
                encoding="utf-8",
            )
            (corpus / "CVE-2099-1010.json").write_text(
                json.dumps(
                    {
                        "cve_id": "CVE-2099-1010",
                        "summary": "Batch replay demo",
                        "project": "demo-app",
                        "language": "python",
                        "vuln_family": "command_execution",
                        "replay": {
                            "title": "Batch replay",
                            "vuln_family": "command_execution",
                            "repro_command": "python3 app.py @payload_path@",
                            "artifacts": [{"name": "payload.txt", "content": "boom\n"}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            batch_manifest.write_text(
                json.dumps(
                    {
                        "name": "local-batch",
                        "jobs": [
                            {"name": "scan-demo", "mode": "scan", "target": str(project)},
                            {
                                "name": "replay-demo",
                                "mode": "replay_cve",
                                "target": str(project),
                                "cve_id": "CVE-2099-1010",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            engine = ScanEngine(
                AppConfig(runs_dir=str(runs), corpus_dir=str(corpus), enabled_validators=["direct_runtime"]),
                build_default_registry(),
            )
            batch = BatchRunner(engine).run_manifest(str(batch_manifest))

            self.assertEqual(len(batch.jobs), 2)
            self.assertTrue(all(item.status == "completed" for item in batch.jobs))
            self.assertNotEqual(batch.jobs[0].run_id, batch.jobs[1].run_id)
            loaded = load_batch_result(batch.batch_id, str(runs))
            self.assertEqual(loaded.batch_id, batch.batch_id)
            self.assertEqual(loaded.jobs[1].status, "completed")
            self.assertGreaterEqual(loaded.metadata["dedup"]["unique_findings"], 1)
            self.assertGreaterEqual(loaded.metadata["comparison"]["new_count"], 1)

    def test_batch_runner_computes_dedup_and_regression_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            runs = root / "runs"
            project.mkdir()
            (project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            app = project / "app.py"
            app.write_text(
                "\n".join(
                    [
                        "import os",
                        "",
                        "def alpha(cmd):",
                        "    os.system(cmd)",
                    ]
                ),
                encoding="utf-8",
            )
            engine = ScanEngine(AppConfig(runs_dir=str(runs)), build_default_registry())
            runner = BatchRunner(engine)

            first = runner.run_spec(
                BatchSpec(
                    name="compare-batch",
                    jobs=[
                        BatchJobSpec(name="scan-a", mode="scan", target=str(project)),
                        BatchJobSpec(name="scan-b", mode="scan", target=str(project)),
                    ],
                )
            )

            app.write_text(
                "\n".join(
                    [
                        "import os",
                        "",
                        "def alpha(cmd):",
                        "    os.system(cmd)",
                        "",
                        "def beta(cmd):",
                        "    os.system(cmd)",
                    ]
                ),
                encoding="utf-8",
            )
            second = runner.run_spec(
                BatchSpec(
                    name="compare-batch",
                    jobs=[BatchJobSpec(name="scan-c", mode="scan", target=str(project))],
                )
            )

            self.assertGreaterEqual(first.metadata["dedup"]["duplicate_findings"], 1)
            self.assertTrue(first.metadata["dedup"]["groups"])
            self.assertEqual(second.metadata["comparison"]["previous_batch_id"], first.batch_id)
            self.assertGreaterEqual(second.metadata["comparison"]["new_count"], 1)
            self.assertGreaterEqual(second.metadata["comparison"]["repeated_count"], 1)

    def test_schedule_runner_only_executes_due_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            runs = root / "runs"
            schedule_manifest = root / "schedule.json"
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
            schedule_manifest.write_text(
                json.dumps(
                    {
                        "name": "nightly-local",
                        "tasks": [
                            {
                                "name": "scan-demo",
                                "every_minutes": 60,
                                "job": {"name": "scan-demo", "mode": "scan", "target": str(project)},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            engine = ScanEngine(AppConfig(runs_dir=str(runs)), build_default_registry())
            runner = ScheduleRunner(engine)
            first_at = datetime(2026, 4, 18, 1, 0, tzinfo=timezone.utc)
            first = runner.run_once(str(schedule_manifest), now=first_at)
            second = runner.run_once(str(schedule_manifest), now=first_at + timedelta(minutes=30))
            third = runner.run_once(str(schedule_manifest), now=first_at + timedelta(minutes=61))

            self.assertEqual(first.due_tasks, ["scan-demo"])
            self.assertIsNotNone(first.batch_result)
            self.assertEqual(second.due_tasks, [])
            self.assertIsNone(second.batch_result)
            self.assertEqual(third.due_tasks, ["scan-demo"])
            state_path = schedule_state_path(str(runs), "nightly-local")
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["tasks"]["scan-demo"]["last_run_at"], third.evaluated_at)

    def test_cli_batch_and_schedule_commands_return_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            runs = root / "runs"
            config = root / "config.toml"
            batch_manifest = root / "batch.json"
            schedule_manifest = root / "schedule.json"
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
            config.write_text(
                "\n".join(["[app]", f'runs_dir = "{runs}"']),
                encoding="utf-8",
            )
            batch_manifest.write_text(
                json.dumps({"name": "cli-batch", "jobs": [{"name": "scan-demo", "mode": "scan", "target": str(project)}]}),
                encoding="utf-8",
            )
            schedule_manifest.write_text(
                json.dumps(
                    {
                        "name": "cli-schedule",
                        "tasks": [
                            {
                                "name": "scan-demo",
                                "every_minutes": 60,
                                "job": {"name": "scan-demo", "mode": "scan", "target": str(project)},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                run_code = main(["--config", str(config), "batch", "run", str(batch_manifest)])
                list_code = main(["--config", str(config), "batch", "list"])
                batch_id = next((runs / "batches").iterdir()).name
                show_code = main(["--config", str(config), "batch", "show", batch_id])
                once_code = main(["--config", str(config), "schedule", "once", str(schedule_manifest), "--at", "2026-04-18T01:00:00Z"])
                state_code = main(["--config", str(config), "schedule", "show", str(schedule_manifest)])

            self.assertEqual(run_code, 0)
            self.assertEqual(list_code, 0)
            self.assertEqual(show_code, 0)
            self.assertEqual(once_code, 0)
            self.assertEqual(state_code, 0)
            output = stdout.getvalue()
            self.assertIn("Batch ID:", output)
            self.assertIn("Schedule:", output)
            self.assertIn("Unique Findings:", output)
