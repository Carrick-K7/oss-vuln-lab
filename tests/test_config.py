import os
import tempfile
import unittest
from pathlib import Path

from oss_vuln_digger.config import AppConfig, load_config


class ConfigTests(unittest.TestCase):
    def test_default_config_does_not_enable_host_runtime_execution(self) -> None:
        config = AppConfig()

        self.assertNotIn("direct_runtime", config.enabled_validators)
        self.assertNotIn("host_sanitizer_runtime", config.enabled_validators)

    def test_loads_toml_and_env_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.toml"
            config_path.write_text(
                "\n".join(
                    [
                        "[app]",
                        'runs_dir = "runs-here"',
                        'corpus_dir = "corpus-here"',
                        'enabled_validators = ["sanitizer_runtime"]',
                        "",
                        "[llm]",
                        'provider = "openai_compatible"',
                        'base_url = "https://example.invalid/v1"',
                        'api_key_env = "TEST_OPENAI_KEY"',
                        'model = "demo-model"',
                        "temperature = 0.2",
                        "max_tokens = 222",
                        "timeout_seconds = 19",
                    ]
                ),
                encoding="utf-8",
            )
            os.environ["TEST_OPENAI_KEY"] = "secret"
            try:
                config = load_config(str(config_path))
                self.assertEqual(config.llm.api_key, "secret")
            finally:
                os.environ.pop("TEST_OPENAI_KEY", None)

        self.assertEqual(config.runs_dir, "runs-here")
        self.assertEqual(config.corpus_dir, "corpus-here")
        self.assertEqual(config.enabled_validators, ["sanitizer_runtime"])
        self.assertEqual(config.llm.provider, "openai_compatible")
        self.assertEqual(config.llm.base_url, "https://example.invalid/v1")
        self.assertEqual(config.llm.model, "demo-model")
        self.assertEqual(config.llm.max_tokens, 222)
