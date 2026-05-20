import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from oss_vuln_digger.cli import main
from oss_vuln_digger.config import AppConfig
from oss_vuln_digger.dashboard import write_dashboard
from oss_vuln_digger.impact import (
    ImpactRunner,
    ImpactValidationError,
    load_impact_manifest,
    resolve_version_targets,
)
from oss_vuln_digger.intelligence import IntelligenceError, safe_intel_artifact_path
from oss_vuln_digger.pipeline import ScanEngine
from oss_vuln_digger.registry import build_default_registry


class ImpactTests(unittest.TestCase):
    def test_manifest_validation_accepts_core_shape_and_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "impact.json"
            manifest.write_text(
                json.dumps(_impact_manifest_payload(str(root / "repo"))),
                encoding="utf-8",
            )

            loaded = load_impact_manifest(manifest)
            self.assertEqual(loaded.name, "demo-impact")
            self.assertEqual(loaded.advisory.id, "CVE-2099-2000")
            self.assertEqual(loaded.source_signatures[0].classification, "vulnerable")

            unsafe = _impact_manifest_payload(str(root / "repo"))
            unsafe["source_signatures"][0]["file"] = "../app.py"
            manifest.write_text(json.dumps(unsafe), encoding="utf-8")
            with self.assertRaises(ImpactValidationError):
                load_impact_manifest(manifest)

            too_many_results = _impact_manifest_payload(str(root / "repo"))
            too_many_results["intelligence"] = {"enabled": True, "queries": ["demo"], "max_results": 101}
            manifest.write_text(json.dumps(too_many_results), encoding="utf-8")
            with self.assertRaises(ImpactValidationError):
                load_impact_manifest(manifest)

    def test_version_discovery_filters_sorts_and_deduplicates_tags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            _init_git_repo(repo)
            _write_project(repo, vulnerable=True)
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "initial")
            _git(repo, "tag", "v1.0.0")
            _git(repo, "tag", "v1.0.1")
            _git(repo, "tag", "v1.0.2-rc1")
            _git(repo, "tag", "v2.0.0")

            manifest_path = root / "impact.json"
            payload = _impact_manifest_payload(str(repo))
            payload["version_source"]["explicit"] = [
                {"version": "1.0.0", "ref": "v1.0.0", "role": "suspected_affected"}
            ]
            payload["version_source"]["discover"] = {
                "enabled": True,
                "include": ["v1.0.*"],
                "exclude": ["*rc*"],
                "limit": 20,
            }
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")

            targets = resolve_version_targets(load_impact_manifest(manifest_path))

            self.assertEqual([target.ref for target in targets], ["v1.0.0", "v1.0.1"])
            self.assertEqual(targets[0].source, "explicit")
            self.assertEqual(targets[1].source, "discovered")

    def test_assess_manifest_maps_replay_and_source_signatures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            runs = root / "runs"
            corpus = root / "corpus"
            corpus.mkdir()
            _create_two_version_repo(repo)
            _write_corpus_record(corpus)

            manifest_path = root / "impact.json"
            manifest_path.write_text(
                json.dumps(_impact_manifest_payload(str(repo), include_fixed_signature=True)),
                encoding="utf-8",
            )
            engine = ScanEngine(
                AppConfig(runs_dir=str(runs), corpus_dir=str(corpus), enabled_validators=["direct_runtime"]),
                build_default_registry(),
            )

            report = ImpactRunner(engine).assess_manifest(str(manifest_path))

            statuses = {item.version: item.status.value for item in report.versions}
            self.assertEqual(statuses["1.0.0"], "confirmed_affected")
            self.assertEqual(statuses["1.0.1"], "likely_fixed")
            self.assertTrue((runs / "impacts" / report.impact_id / "impact.json").exists())
            self.assertTrue((runs / "impacts" / report.impact_id / "impact.md").exists())
            dashboard = write_dashboard(str(runs), corpus_dir=str(corpus)).read_text(encoding="utf-8")
            self.assertIn(report.impact_id, dashboard)
            self.assertIn("Review impact matrix", dashboard)

            not_reproduced_payload = _impact_manifest_payload(str(repo))
            not_reproduced_payload["version_source"]["explicit"][1]["role"] = ""
            manifest_path.write_text(json.dumps(not_reproduced_payload), encoding="utf-8")
            not_reproduced = ImpactRunner(engine).assess_manifest(str(manifest_path))
            not_reproduced_statuses = {item.version: item.status.value for item in not_reproduced.versions}
            self.assertEqual(not_reproduced_statuses["1.0.1"], "not_reproduced")

    def test_cli_impact_plan_assess_list_and_show_return_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            runs = root / "runs"
            corpus = root / "corpus"
            config = root / "config.toml"
            manifest = root / "impact.json"
            corpus.mkdir()
            _create_two_version_repo(repo)
            _write_corpus_record(corpus)
            manifest.write_text(
                json.dumps(_impact_manifest_payload(str(repo), include_fixed_signature=True)),
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
                plan_code = main(["--config", str(config), "impact", "plan", str(manifest)])
                assess_code = main(["--config", str(config), "impact", "assess", str(manifest)])
                impact_id = next((runs / "impacts").iterdir()).name
                list_code = main(["--config", str(config), "impact", "list"])
                show_code = main(["--config", str(config), "impact", "show", impact_id])

            self.assertEqual(plan_code, 0)
            self.assertEqual(assess_code, 0)
            self.assertEqual(list_code, 0)
            self.assertEqual(show_code, 0)
            output = stdout.getvalue()
            self.assertIn("Versions: 2", output)
            self.assertIn("confirmed_affected", output)
            self.assertIn("likely_fixed", output)
            self.assertIn("Version Matrix:", output)

    def test_network_enabled_manifest_requires_allow_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            _create_two_version_repo(repo)
            manifest = root / "impact.json"
            payload = _impact_manifest_payload(str(repo))
            payload["intelligence"] = {
                "enabled": True,
                "queries": ["CVE-2099-2000 demo PoC"],
                "max_results": 1,
            }
            payload.pop("replay")
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["impact", "plan", str(manifest)])

            self.assertEqual(exit_code, 1)
            self.assertIn("--allow-network", stdout.getvalue())

            engine = ScanEngine(AppConfig(runs_dir=str(root / "runs")), build_default_registry())
            report = ImpactRunner(engine).assess_manifest(str(manifest), allow_network=True)
            statuses = {item.version: item.status.value for item in report.versions}
            self.assertEqual(statuses["1.0.0"], "likely_affected")
            self.assertEqual(report.intel[0].status, "provider_not_configured")
            self.assertFalse(report.metadata["execute_discovered_poc"])

    def test_network_git_repositories_require_allow_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "impact.json"
            for repository in [
                "git://example.invalid/repo.git",
                "user@example.invalid:repo.git",
                "example.invalid:repo.git",
            ]:
                payload = _impact_manifest_payload(repository)
                payload.pop("replay")
                manifest.write_text(json.dumps(payload), encoding="utf-8")
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["impact", "plan", str(manifest)])
                self.assertEqual(exit_code, 1)
                self.assertIn("--allow-network", stdout.getvalue())

    def test_safe_intel_artifact_path_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises((IntelligenceError, ValueError)):
                safe_intel_artifact_path(Path(tmp), "../poc.py")


def _impact_manifest_payload(repository: str, *, include_fixed_signature: bool = False) -> dict[str, object]:
    signatures = [
        {
            "name": "vulnerable-marker",
            "classification": "vulnerable",
            "file": "app.py",
            "contains_all": ["VULNERABLE_MARKER"],
        }
    ]
    if include_fixed_signature:
        signatures.append(
            {
                "name": "fixed-marker",
                "classification": "fixed",
                "file": "app.py",
                "contains_all": ["FIXED_MARKER"],
            }
        )
    return {
        "schema_version": "0.1",
        "name": "demo-impact",
        "advisory": {
            "id": "CVE-2099-2000",
            "project": "demo",
            "summary": "Demo impact assessment",
            "vuln_family": "command_execution",
            "source_hints": [{"file": "app.py", "function_or_sink": "__main__"}],
        },
        "version_source": {
            "type": "git",
            "repository": repository,
            "explicit": [
                {"version": "1.0.0", "ref": "v1.0.0", "role": "suspected_affected"},
                {"version": "1.0.1", "ref": "v1.0.1", "role": "fixed_control"},
            ],
        },
        "replay": {"corpus_ref": "CVE-2099-2000"},
        "source_signatures": signatures,
    }


def _create_two_version_repo(repo: Path) -> None:
    _init_git_repo(repo)
    _write_project(repo, vulnerable=True)
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "vulnerable")
    _git(repo, "tag", "v1.0.0")
    _write_project(repo, vulnerable=False)
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "fixed")
    _git(repo, "tag", "v1.0.1")


def _init_git_repo(repo: Path) -> None:
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True, text=True)
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test User")


def _write_project(repo: Path, *, vulnerable: bool) -> None:
    (repo / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    marker = "VULNERABLE_MARKER" if vulnerable else "FIXED_MARKER"
    body = [
        "import pathlib",
        "import sys",
        "",
        f"{marker} = True",
        "",
        "if __name__ == '__main__':",
        "    payload = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').strip()",
    ]
    if vulnerable:
        body.extend(
            [
                "    if payload == 'boom':",
                "        raise RuntimeError('boom')",
            ]
        )
    else:
        body.append("    sys.exit(0)")
    (repo / "app.py").write_text("\n".join(body) + "\n", encoding="utf-8")


def _write_corpus_record(corpus: Path) -> None:
    (corpus / "CVE-2099-2000.json").write_text(
        json.dumps(
            {
                "cve_id": "CVE-2099-2000",
                "summary": "Demo replay",
                "project": "demo",
                "language": "python",
                "vuln_family": "command_execution",
                "replay": {
                    "title": "Demo runtime replay",
                    "vuln_family": "command_execution",
                    "repro_command": "python3 app.py @payload_path@",
                    "candidate_file": "app.py",
                    "function_or_sink": "__main__",
                    "artifacts": [{"name": "payload.txt", "content": "boom\n"}],
                },
            }
        ),
        encoding="utf-8",
    )


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
