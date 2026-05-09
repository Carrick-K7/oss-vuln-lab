from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class LLMConfig:
    provider: str = "local"
    base_url: str = ""
    api_key_env: str = "OPENAI_API_KEY"
    model: str = "local-heuristic"
    temperature: float = 0.0
    max_tokens: int = 1200
    timeout_seconds: int = 30

    @property
    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "")


@dataclass(slots=True)
class AppConfig:
    runs_dir: str = ".ovd_runs"
    corpus_dir: str = "corpus"
    enabled_validators: list[str] = field(
        default_factory=lambda: ["docker_build", "sanitizer_runtime"]
    )
    llm: LLMConfig = field(default_factory=LLMConfig)


def load_config(config_path: str | None = None) -> AppConfig:
    config = AppConfig()
    if not config_path:
        return config

    path = Path(config_path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    app_data: dict[str, Any] = data.get("app", {})
    llm_data: dict[str, Any] = data.get("llm", {})

    if "runs_dir" in app_data:
        config.runs_dir = str(app_data["runs_dir"])
    if "corpus_dir" in app_data:
        config.corpus_dir = str(app_data["corpus_dir"])
    if "enabled_validators" in app_data:
        config.enabled_validators = list(app_data["enabled_validators"])

    config.llm = LLMConfig(
        provider=str(llm_data.get("provider", config.llm.provider)),
        base_url=str(llm_data.get("base_url", config.llm.base_url)),
        api_key_env=str(llm_data.get("api_key_env", config.llm.api_key_env)),
        model=str(llm_data.get("model", config.llm.model)),
        temperature=float(llm_data.get("temperature", config.llm.temperature)),
        max_tokens=int(llm_data.get("max_tokens", config.llm.max_tokens)),
        timeout_seconds=int(llm_data.get("timeout_seconds", config.llm.timeout_seconds)),
    )
    return config
