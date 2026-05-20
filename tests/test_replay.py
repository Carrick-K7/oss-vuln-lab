import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from oss_vuln_digger.cli import main
from oss_vuln_digger.config import AppConfig
from oss_vuln_digger.pipeline import ScanEngine
from oss_vuln_digger.registry import build_default_registry


class ReplayTests(unittest.TestCase):
    def test_replay_cve_uses_corpus_record_and_confirms_python_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            runs = root / "runs"
            corpus = root / "corpus"
            project.mkdir()
            corpus.mkdir()

            (project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            (project / "app.py").write_text(
                "\n".join(
                    [
                        "import pathlib",
                        "import sys",
                        "",
                        "if __name__ == '__main__':",
                        "    payload = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').strip()",
                        "    if payload == 'boom':",
                        "        raise RuntimeError('boom')",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (corpus / "payload.txt").write_text("boom\n", encoding="utf-8")
            (corpus / "TEST-REPLAY-0002.json").write_text(
                json.dumps(
                    {
                        "cve_id": "TEST-REPLAY-0002",
                        "summary": "Demo runtime replay",
                        "project": "demo-app",
                        "language": "python",
                        "vuln_family": "command_execution",
                        "replay": {
                            "title": "Runtime replay",
                            "vuln_family": "command_execution",
                            "repro_command": "python3 app.py @payload_path@",
                            "candidate_file": "app.py",
                            "function_or_sink": "__main__",
                            "artifacts": [{"name": "payload.txt", "file_path": "payload.txt"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            engine = ScanEngine(
                AppConfig(runs_dir=str(runs), corpus_dir=str(corpus), enabled_validators=["direct_runtime"]),
                build_default_registry(),
            )
            result = engine.replay_cve(str(project), "TEST-REPLAY-0002")

            self.assertEqual(result.records[0].final.poc_status, "confirmed")
            self.assertEqual(result.records[0].final.status.value, "confirmed_known_poc")
            self.assertEqual(result.metadata["corpus_record"]["cve_id"], "TEST-REPLAY-0002")

    def test_cli_corpus_and_replay_commands_return_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            corpus = root / "corpus"
            runs = root / "runs"
            config = root / "config.toml"
            project.mkdir()
            corpus.mkdir()

            (project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            (project / "app.py").write_text(
                "\n".join(
                    [
                        "import pathlib",
                        "import sys",
                        "",
                        "if __name__ == '__main__':",
                        "    payload = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').strip()",
                        "    if payload == 'boom':",
                        "        raise RuntimeError('boom')",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (corpus / "payload.txt").write_text("boom\n", encoding="utf-8")
            (corpus / "TEST-REPLAY-0003.json").write_text(
                json.dumps(
                    {
                        "cve_id": "TEST-REPLAY-0003",
                        "summary": "CLI replay demo",
                        "project": "demo-app",
                        "language": "python",
                        "vuln_family": "command_execution",
                        "replay": {
                            "title": "CLI replay",
                            "vuln_family": "command_execution",
                            "repro_command": "python3 app.py @payload_path@",
                            "artifacts": [{"name": "payload.txt", "file_path": "payload.txt"}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            config.write_text(
                "\n".join(
                    [
                        "[app]",
                        f'runs_dir = "{runs}"',
                        f'corpus_dir = "{corpus}"',
                        'enabled_validators = ["direct_runtime"]',
                    ]
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                list_code = main(["--config", str(config), "corpus", "list"])
                show_code = main(["--config", str(config), "corpus", "show", "TEST-REPLAY-0003"])
                replay_code = main(["--config", str(config), "replay", "cve", str(project), "TEST-REPLAY-0003"])

            self.assertEqual(list_code, 0)
            self.assertEqual(show_code, 0)
            self.assertEqual(replay_code, 0)
            output = stdout.getvalue()
            self.assertIn("TEST-REPLAY-0003", output)
            self.assertIn("Run ID:", output)

    def test_replay_cve_confirms_multilanguage_direct_runtime_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus"
            runs = root / "runs"
            corpus.mkdir()
            bin_dir = root / "bin"
            bin_dir.mkdir()

            java_path = bin_dir / "java"
            java_path.write_text(
                "\n".join(
                    [
                        "#!/usr/bin/env bash",
                        'payload="${2:-}"',
                        'if [ -f "$payload" ] && grep -qx "boom" "$payload"; then',
                        '  echo \'Exception in thread "main" java.lang.RuntimeException: boom\' >&2',
                        "  exit 1",
                        "fi",
                        "exit 0",
                    ]
                ),
                encoding="utf-8",
            )
            java_path.chmod(0o755)

            cargo_path = bin_dir / "cargo"
            cargo_path.write_text(
                "\n".join(
                    [
                        "#!/usr/bin/env bash",
                        'payload="${3:-}"',
                        'if [ -f "$payload" ] && grep -qx "boom" "$payload"; then',
                        '  echo "thread \'main\' panicked at \'boom\', src/main.rs:1:1" >&2',
                        "  exit 101",
                        "fi",
                        "exit 0",
                    ]
                ),
                encoding="utf-8",
            )
            cargo_path.chmod(0o755)

            cases = [
                {
                    "cve_id": "TEST-REPLAY-1001",
                    "language": "javascript",
                    "project": root / "js-app",
                    "setup": self._setup_javascript_project,
                    "repro_command": "node app.js @payload_path@",
                    "runtime_env": {},
                },
                {
                    "cve_id": "TEST-REPLAY-1002",
                    "language": "java",
                    "project": root / "java-app",
                    "setup": self._setup_java_project,
                    "repro_command": "java Main @payload_path@",
                    "runtime_env": {"PATH": f"{bin_dir}:{os.environ['PATH']}"},
                },
                {
                    "cve_id": "TEST-REPLAY-1003",
                    "language": "rust",
                    "project": root / "rust-app",
                    "setup": self._setup_rust_project,
                    "repro_command": "cargo run -- @payload_path@",
                    "runtime_env": {"PATH": f"{bin_dir}:{os.environ['PATH']}"},
                },
            ]

            for case in cases:
                self._write_replay_manifest(
                    corpus,
                    cve_id=case["cve_id"],
                    language=case["language"],
                    repro_command=case["repro_command"],
                    runtime_env=case["runtime_env"],
                )
                case["setup"](case["project"])

            engine = ScanEngine(
                AppConfig(runs_dir=str(runs), corpus_dir=str(corpus), enabled_validators=["direct_runtime"]),
                build_default_registry(),
            )

            for case in cases:
                with self.subTest(language=case["language"]):
                    result = engine.replay_cve(str(case["project"]), case["cve_id"])
                    self.assertEqual(result.project.primary_language.value, case["language"])
                    self.assertEqual(result.records[0].final.poc_status, "confirmed")
                    self.assertEqual(result.records[0].final.status.value, "confirmed_known_poc")
                    self.assertEqual(result.records[0].validations[0].validator_name, "direct_runtime")

    @staticmethod
    def _write_replay_manifest(
        corpus_dir: Path,
        *,
        cve_id: str,
        language: str,
        repro_command: str,
        runtime_env: dict[str, str],
    ) -> None:
        (corpus_dir / f"{cve_id}.json").write_text(
            json.dumps(
                {
                    "cve_id": cve_id,
                    "summary": "Cross-language replay demo",
                    "project": f"{language}-demo",
                    "language": language,
                    "vuln_family": "command_execution",
                    "replay": {
                        "title": f"{language} replay",
                        "vuln_family": "command_execution",
                        "repro_command": repro_command,
                        "artifacts": [{"name": "payload.txt", "content": "boom\n"}],
                        "runtime_env": runtime_env,
                    },
                }
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _setup_javascript_project(project: Path) -> None:
        project.mkdir()
        (project / "package.json").write_text('{"name":"demo","type":"commonjs"}\n', encoding="utf-8")
        (project / "app.js").write_text(
            "\n".join(
                [
                    'const fs = require("fs");',
                    'const assert = require("assert");',
                    "",
                    "if (require.main === module) {",
                    '  const payload = fs.readFileSync(process.argv[2], "utf8").trim();',
                    '  if (payload === "boom") {',
                    '    assert.fail("boom");',
                    "  }",
                    "}",
                ]
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _setup_java_project(project: Path) -> None:
        project.mkdir()
        (project / "pom.xml").write_text("<project/>\n", encoding="utf-8")
        (project / "Main.java").write_text(
            "\n".join(
                [
                    "public class Main {",
                    "    public static void main(String[] args) {",
                    "    }",
                    "}",
                ]
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _setup_rust_project(project: Path) -> None:
        project.mkdir()
        (project / "Cargo.toml").write_text("[package]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
        src = project / "src"
        src.mkdir()
        (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
