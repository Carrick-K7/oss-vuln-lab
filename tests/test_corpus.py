import json
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from oss_vuln_digger.cli import main
from oss_vuln_digger.corpus import CorpusStore, CorpusValidationError


class CorpusTests(unittest.TestCase):
    def test_repository_real_cve_manifest_loads(self) -> None:
        record = CorpusStore("corpus").load_record("CVE-2022-3598")

        self.assertEqual(record.project, "libtiff")
        self.assertEqual(record.language.value, "c_cpp")
        self.assertEqual(record.vuln_family, "memory_safety")
        self.assertEqual(record.affected_versions, ["through 4.4.0"])
        self.assertIn("tools/tiffcrop.c", record.replay.candidate_file)
        self.assertEqual(record.replay.candidate_line, 3604)
        self.assertIn("tiffcrop -Z 1:4,3:3", record.replay.repro_command)
        self.assertEqual(record.replay.artifacts[0].name, "cve-2022-3598-poc.tiff")
        payload = record.replay.artifacts[0].content.encode("ascii")
        digest = hashlib.sha256(base64.b64decode(payload)).hexdigest()
        self.assertEqual(digest, "28838a198cb8e5ebadcf624e0404fb36894845ad833edc23ca721c4c612bd630")

    def test_repository_recent_python_cve_manifest_loads(self) -> None:
        record = CorpusStore("corpus").load_record("CVE-2025-4565")

        self.assertEqual(record.project, "protobuf")
        self.assertEqual(record.language.value, "python")
        self.assertEqual(record.vuln_family, "deserialization")
        self.assertEqual(
            record.affected_versions,
            ["<4.25.8", ">=5.26.0,<5.29.5", ">=6.30.0,<6.31.1"],
        )
        self.assertIn("google/protobuf/internal/decoder.py", record.replay.candidate_file)
        self.assertIn("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python", record.replay.repro_command)
        self.assertEqual(record.replay.artifacts[0].name, "cve-2025-4565-replay.py")
        digest = hashlib.sha256(record.replay.artifacts[0].content.encode("utf-8")).hexdigest()
        self.assertEqual(digest, "113671d29bbaf9d31944fdf1190dd8119439212cf2afe4f47f69a9e4770e67e6")

    def test_loads_manifest_and_materializes_relative_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus_dir = root / "corpus"
            corpus_dir.mkdir()
            (corpus_dir / "payload.txt").write_text("boom\n", encoding="utf-8")
            manifest = corpus_dir / "TEST-CORPUS-0001.json"
            manifest.write_text(
                json.dumps(
                    {
                        "cve_id": "TEST-CORPUS-0001",
                        "summary": "Corpus fixture replay",
                        "project": "demo-app",
                        "language": "python",
                        "vuln_family": "command_execution",
                        "references": ["https://example.invalid/TEST-CORPUS-0001"],
                        "replay": {
                            "title": "Corpus fixture replay",
                            "vuln_family": "command_execution",
                            "repro_command": "python3 app.py @payload_path@",
                            "artifacts": [
                                {
                                    "name": "payload.txt",
                                    "file_path": "payload.txt",
                                }
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )

            store = CorpusStore(str(corpus_dir))
            records = store.list_records()

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].cve_id, "TEST-CORPUS-0001")
            self.assertEqual(records[0].replay.artifacts[0].content, "boom\n")

    def test_load_record_supports_alias_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            corpus_dir = Path(tmp)
            (corpus_dir / "payload.txt").write_text("boom\n", encoding="utf-8")
            (corpus_dir / "TEST-CORPUS-0004.json").write_text(
                json.dumps(
                    {
                        "cve_id": "TEST-CORPUS-0004",
                        "summary": "Alias replay",
                        "project": "demo-app",
                        "language": "python",
                        "vuln_family": "command_execution",
                        "aliases": ["GHSA-demo-0004"],
                        "replay": {
                            "title": "Alias replay",
                            "vuln_family": "command_execution",
                            "repro_command": "python3 app.py @payload_path@",
                            "artifacts": [{"name": "payload.txt", "file_path": "payload.txt"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            record = CorpusStore(str(corpus_dir)).load_record("ghsa-demo-0004")

            self.assertEqual(record.cve_id, "TEST-CORPUS-0004")

    def test_rejects_artifact_paths_that_escape_manifest_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus_dir = root / "corpus"
            corpus_dir.mkdir()
            escaped = root / "outside.txt"
            escaped.write_text("boom\n", encoding="utf-8")
            manifest = corpus_dir / "TEST-CORPUS-0005.json"
            manifest.write_text(
                json.dumps(
                    {
                        "cve_id": "TEST-CORPUS-0005",
                        "summary": "Escape attempt",
                        "project": "demo-app",
                        "language": "python",
                        "vuln_family": "command_execution",
                        "replay": {
                            "title": "Escape attempt",
                            "vuln_family": "command_execution",
                            "repro_command": "python3 app.py @payload_path@",
                            "artifacts": [{"name": "payload.txt", "file_path": "../outside.txt"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(CorpusValidationError, "must stay within the manifest directory"):
                CorpusStore(str(corpus_dir)).load_manifest(manifest)

    def test_rejects_missing_replay_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            corpus_dir = Path(tmp)
            manifest = corpus_dir / "TEST-CORPUS-0006.json"
            manifest.write_text(
                json.dumps(
                    {
                        "cve_id": "TEST-CORPUS-0006",
                        "summary": "Missing command",
                        "project": "demo-app",
                        "language": "python",
                        "vuln_family": "command_execution",
                        "replay": {
                            "title": "Missing command",
                            "vuln_family": "command_execution",
                        },
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(CorpusValidationError, "missing required field replay.repro_command"):
                CorpusStore(str(corpus_dir)).load_manifest(manifest)

    def test_cli_returns_error_for_invalid_corpus_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus_dir = root / "corpus"
            corpus_dir.mkdir()
            config = root / "config.toml"
            (corpus_dir / "TEST-CORPUS-0007.json").write_text(
                json.dumps(
                    {
                        "cve_id": "TEST-CORPUS-0007",
                        "summary": "Invalid artifact",
                        "project": "demo-app",
                        "language": "python",
                        "vuln_family": "command_execution",
                        "replay": {
                            "title": "Invalid artifact",
                            "vuln_family": "command_execution",
                            "repro_command": "python3 app.py @payload_path@",
                            "artifacts": [{"name": "../payload.txt", "content": "boom"}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            config.write_text(
                "\n".join(
                    [
                        "[app]",
                        f'corpus_dir = "{corpus_dir}"',
                    ]
                ),
                encoding="utf-8",
            )

            with tempfile.TemporaryFile(mode="w+") as capture:
                with mock.patch("sys.stdout", capture):
                    exit_code = main(["--config", str(config), "corpus", "list"])
                capture.seek(0)
                output = capture.read()

            self.assertEqual(exit_code, 1)
            self.assertIn("Error:", output)
