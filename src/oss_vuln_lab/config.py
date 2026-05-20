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
class IntelConfig:
    web_search_url: str = ""
    web_search_api_key_env: str = "OVL_WEB_SEARCH_API_KEY"
    timeout_seconds: int = 20
    max_fetch_bytes: int = 1024 * 1024

    @property
    def web_search_api_key(self) -> str:
        configured = os.environ.get(self.web_search_api_key_env, "")
        if configured:
            return configured
        if self.web_search_api_key_env == "OVL_WEB_SEARCH_API_KEY":
            return os.environ.get("OVD_WEB_SEARCH_API_KEY", "")
        return ""


@dataclass(slots=True)
class AppConfig:
    runs_dir: str = ".ovl_runs"
    corpus_dir: str = "corpus"
    enabled_validators: list[str] = field(
        default_factory=lambda: ["docker_build", "sanitizer_runtime"]
    )
    llm: LLMConfig = field(default_factory=LLMConfig)
    intel: IntelConfig = field(default_factory=IntelConfig)


def load_config(config_path: str | None = None) -> AppConfig:
    config = AppConfig()
    if not config_path:
        return config

    path = Path(config_path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    app_data: dict[str, Any] = data.get("app", {})
    llm_data: dict[str, Any] = data.get("llm", {})
    intel_data: dict[str, Any] = data.get("intel", {})

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
    config.intel = IntelConfig(
        web_search_url=str(intel_data.get("web_search_url", config.intel.web_search_url)),
        web_search_api_key_env=str(intel_data.get("web_search_api_key_env", config.intel.web_search_api_key_env)),
        timeout_seconds=int(intel_data.get("timeout_seconds", config.intel.timeout_seconds)),
        max_fetch_bytes=int(intel_data.get("max_fetch_bytes", config.intel.max_fetch_bytes)),
    )
    return config
