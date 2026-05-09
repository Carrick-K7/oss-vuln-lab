import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from oss_vuln_digger.config import AppConfig
from oss_vuln_digger.models import (
    ArtifactEncoding,
    Candidate,
    CandidateKind,
    FindingStatus,
    PocSource,
    PocSpec,
    ProjectContext,
    ScanTarget,
    TargetMode,
)
from oss_vuln_digger.pipeline import ScanEngine
from oss_vuln_digger.plugins.project_adapters import CppSourceAdapter
from oss_vuln_digger.plugins.validators import DockerBuildValidator
from oss_vuln_digger.registry import build_default_registry
from oss_vuln_digger.storage import REPORT_JSON, REPORT_MD, STATE_FILE


SOURCE_SAMPLE = """\
#include <stdio.h>
#include <string.h>

int parse(const char *input, size_t len) {
    char buf[16];
    memcpy(buf, input, len);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        return parse(argv[1], strlen(argv[1]));
    }
    return 0;
}
"""


class PipelineTests(unittest.TestCase):
    def test_scan_source_project_writes_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "sample"
            runs = root / "runs"
            project.mkdir()
            (project / "main.c").write_text(SOURCE_SAMPLE, encoding="utf-8")
            (project / "Makefile").write_text("all:\n\tcc main.c -o sample\n", encoding="utf-8")

            engine = ScanEngine(AppConfig(runs_dir=str(runs)), build_default_registry())
            result = engine.scan(str(project))

            self.assertEqual(result.project.adapter_name, "cpp_source")
            self.assertGreaterEqual(len(result.records), 2)
            self.assertTrue((Path(result.run_dir) / STATE_FILE).exists())
            self.assertTrue((Path(result.run_dir) / REPORT_JSON).exists())
            self.assertTrue((Path(result.run_dir) / REPORT_MD).exists())
            self.assertIn(
                result.records[0].final.status,
                {
                    FindingStatus.POC_SYNTHESIZED,
                    FindingStatus.MANUAL_REVIEW,
                    FindingStatus.CONFIRMED_GENERATED_POC,
                },
            )

            updated = engine.triage(result.run_id, result.records[0].final.id)
            self.assertEqual(updated.run_id, result.run_id)
            triage_events = list((Path(result.run_dir) / "triage").glob("*.json"))
            self.assertEqual(len(triage_events), 1)
            triage_payload = json.loads(triage_events[0].read_text(encoding="utf-8"))
            self.assertEqual(triage_payload["finding_id"], result.records[0].final.id)
            self.assertEqual(triage_payload["previous_final"]["id"], result.records[0].final.id)

            rerendered = engine.report(result.run_id)
            self.assertEqual(rerendered.run_id, result.run_id)

    def test_scan_binary_artifact_uses_binary_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runs = root / "runs"
            binary = root / "sample.bin"
            binary.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"padding system memcpy")

            engine = ScanEngine(AppConfig(runs_dir=str(runs)), build_default_registry())
            result = engine.scan(str(binary))

            self.assertEqual(result.project.adapter_name, "elf_binary")
            self.assertGreaterEqual(len(result.records), 1)
            self.assertEqual(result.records[0].candidate.vuln_family, "binary_surface")

    def test_scan_python_project_uses_python_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "py-project"
            runs = root / "runs"
            project.mkdir()
            (project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            (project / "app.py").write_text(
                "\n".join(
                    [
                        "import os",
                        "",
                        "if __name__ == '__main__':",
                        "    os.system(input())",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            engine = ScanEngine(AppConfig(runs_dir=str(runs)), build_default_registry())
            result = engine.scan(str(project))

            self.assertEqual(result.project.adapter_name, "python_source")
            self.assertEqual(result.project.primary_language.value, "python")
            self.assertGreaterEqual(len(result.records), 1)
            self.assertEqual(result.records[0].candidate.vuln_family, "command_execution")

    def test_detects_autotools_projects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "autotools"
            project.mkdir()
            (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (project / "configure.ac").write_text("AC_INIT([demo],[0.1])\n", encoding="utf-8")

            adapter = CppSourceAdapter()
            context = adapter.prepare(
                ScanTarget(
                    spec=str(project),
                    resolved_path=str(project),
                    mode=TargetMode.SOURCE_REPO,
                    origin="local_path",
                )
            )
            self.assertEqual(context.build_system, "autotools")
            self.assertEqual(context.metadata["default_binary"], "./main")

    def test_detects_configure_make_projects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "configure-make"
            project.mkdir()
            (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (project / "configure").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

            adapter = CppSourceAdapter()
            context = adapter.prepare(
                ScanTarget(
                    spec=str(project),
                    resolved_path=str(project),
                    mode=TargetMode.SOURCE_REPO,
                    origin="local_path",
                )
            )
            self.assertEqual(context.build_system, "configure_make")

    def test_host_validator_confirms_simple_memory_bug(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "host-sample"
            runs = root / "runs"
            project.mkdir()
            (project / "main.c").write_text(
                "\n".join(
                    [
                        "#include <string.h>",
                        "int main(int argc, char **argv) {",
                        "  char buf[8];",
                        "  if (argc > 1) { strcpy(buf, argv[1]); }",
                        "  return 0;",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (project / "Makefile").write_text("all:\n\tcc main.c -o main\n", encoding="utf-8")

            config = AppConfig(runs_dir=str(runs), enabled_validators=["host_sanitizer_runtime"])
            engine = ScanEngine(config, build_default_registry())
            result = engine.scan(str(project))

            statuses = {record.final.poc_status for record in result.records}
            self.assertIn("confirmed", statuses)

    def test_verify_known_confirms_imported_poc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "known-poc"
            runs = root / "runs"
            project.mkdir()
            (project / "main.c").write_text(
                "\n".join(
                    [
                        "#include <stdio.h>",
                        "#include <string.h>",
                        "int main(int argc, char **argv) {",
                        "  char buf[8];",
                        "  if (argc > 1) { strcpy(buf, argv[1]); }",
                        "  return 0;",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (project / "Makefile").write_text("all:\n\tcc main.c -o main\n", encoding="utf-8")

            config = AppConfig(runs_dir=str(runs), enabled_validators=["host_sanitizer_runtime"])
            engine = ScanEngine(config, build_default_registry())
            result = engine.verify_known(
                target_spec=str(project),
                title="Known stack overflow replay",
                vuln_family="memory_safety",
                repro_command="./main $(cat @payload_path@)",
                artifact_name="payload.txt",
                artifact_content="A" * 64,
                artifact_encoding=ArtifactEncoding.TEXT,
                file_path=str(project / "main.c"),
                line=4,
                function_or_sink="strcpy",
                notes="Imported regression PoC.",
            )

            record = result.records[0]
            self.assertEqual(record.final.status, FindingStatus.CONFIRMED_KNOWN_POC)
            self.assertEqual(record.final.poc_source.value, "known")
            self.assertEqual(record.final.poc_status, "confirmed")

    def test_verify_known_rejects_artifact_name_with_path_segments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "known-poc"
            runs = root / "runs"
            project.mkdir()
            (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

            engine = ScanEngine(AppConfig(runs_dir=str(runs)), build_default_registry())

            with self.assertRaisesRegex(ValueError, "simple filename"):
                engine.verify_known(
                    target_spec=str(project),
                    title="Invalid artifact",
                    vuln_family="memory_safety",
                    repro_command="./main @payload_path@",
                    artifact_name="../payload.txt",
                    artifact_content="boom",
                    artifact_encoding=ArtifactEncoding.TEXT,
                )

            self.assertFalse((root / "payload.txt").exists())

    def test_verify_known_with_relative_runs_dir_uses_absolute_payload_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "known-poc"
            project.mkdir()
            (project / "main.c").write_text(
                "\n".join(
                    [
                        "#include <string.h>",
                        "int main(int argc, char **argv) {",
                        "  char buf[8];",
                        "  if (argc > 1) { strcpy(buf, argv[1]); }",
                        "  return 0;",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (project / "Makefile").write_text("all:\n\tcc main.c -o main\n", encoding="utf-8")

            config = AppConfig(runs_dir="runs", enabled_validators=["host_sanitizer_runtime"])
            engine = ScanEngine(config, build_default_registry())
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                result = engine.verify_known(
                    target_spec="known-poc",
                    title="Known stack overflow replay",
                    vuln_family="memory_safety",
                    repro_command="./main $(cat @payload_path@)",
                    artifact_name="payload.txt",
                    artifact_content="A" * 64,
                    artifact_encoding=ArtifactEncoding.TEXT,
                    file_path=str(project / "main.c"),
                    line=4,
                    function_or_sink="strcpy",
                    notes="Imported regression PoC.",
                )
            finally:
                os.chdir(old_cwd)

            record = result.records[0]
            self.assertEqual(record.final.status, FindingStatus.CONFIRMED_KNOWN_POC)
            self.assertTrue(Path(result.run_dir).is_absolute())

    def test_docker_validator_uses_no_network_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = ProjectContext(
                target=ScanTarget(
                    spec=str(root),
                    resolved_path=str(root),
                    mode=TargetMode.SOURCE_REPO,
                    origin="local_path",
                ),
                adapter_name="cpp_source",
                root=str(root),
                build_system="make",
            )
            candidate = Candidate(
                id="finding-1",
                title="demo",
                vuln_family="memory_safety",
                target_mode=TargetMode.SOURCE_REPO,
                file_path="main.c",
                line=1,
                function_or_sink="main",
                evidence_seed="demo",
                severity_hint="high",
                kind=CandidateKind.MEMORY_OPERATION,
            )
            poc = PocSpec(
                description="demo",
                repro_command="./main @payload_path@",
                input_payload="AAAA",
                source=PocSource.GENERATED,
            )

            with mock.patch("oss_vuln_digger.plugins.validators.shutil.which", return_value="/usr/bin/docker"):
                result = DockerBuildValidator().run(project, candidate, poc, Path(tmp))

            self.assertIn("--network none", result.command)
