import tempfile
import unittest
from pathlib import Path

from oss_vuln_digger.cli import main


class CliTests(unittest.TestCase):
    def test_scan_command_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            runs = root / "runs"
            project.mkdir()
            (project / "main.c").write_text(
                (
                    "#include <string.h>\n"
                    "int main(int argc, char **argv) {"
                    " char buf[8];"
                    " if (argc > 1) { memcpy(buf, argv[1], strlen(argv[1])); }"
                    " return 0; }\n"
                ),
                encoding="utf-8",
            )

            exit_code = main(["--runs-dir", str(runs), "scan", str(project)])
            self.assertEqual(exit_code, 0)
            created_runs = list(runs.iterdir())
            self.assertEqual(len(created_runs), 1)

    def test_verify_known_command_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            runs = root / "runs"
            project.mkdir()
            (project / "main.c").write_text(
                (
                    "#include <string.h>\n"
                    "int main(int argc, char **argv) {"
                    " char buf[8];"
                    " if (argc > 1) { strcpy(buf, argv[1]); }"
                    " return 0; }\n"
                ),
                encoding="utf-8",
            )
            (project / "Makefile").write_text("all:\n\tcc main.c -o main\n", encoding="utf-8")

            exit_code = main(
                [
                    "--runs-dir",
                    str(runs),
                    "verify-known",
                    str(project),
                    "--title",
                    "Known strcpy overflow",
                    "--vuln-family",
                    "memory_safety",
                    "--repro-command",
                    "./main $(cat @payload_path@)",
                    "--artifact-text",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ]
            )
            self.assertEqual(exit_code, 0)
            created_runs = list(runs.iterdir())
            self.assertEqual(len(created_runs), 1)

    def test_verify_known_rejects_unsafe_artifact_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            runs = root / "runs"
            project.mkdir()
            (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

            exit_code = main(
                [
                    "--runs-dir",
                    str(runs),
                    "verify-known",
                    str(project),
                    "--title",
                    "Unsafe artifact",
                    "--vuln-family",
                    "memory_safety",
                    "--repro-command",
                    "./main @payload_path@",
                    "--artifact-text",
                    "payload",
                    "--artifact-name",
                    "../payload.txt",
                ]
            )

            self.assertEqual(exit_code, 1)
            self.assertFalse((root / "payload.txt").exists())
