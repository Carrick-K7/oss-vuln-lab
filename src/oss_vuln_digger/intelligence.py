from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus
import urllib.error
import urllib.request

from oss_vuln_digger.config import IntelConfig
from oss_vuln_digger.models import ensure_directory
from oss_vuln_digger.safety import validate_simple_filename


class IntelligenceError(ValueError):
    pass


@dataclass(slots=True)
class IntelResult:
    query: str
    title: str
    url: str
    snippet: str = ""
    fetched_path: str = ""
    sha256: str = ""
    size: int = 0
    status: str = "search_result"
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "title": self.title,
            "url": self.url,
            "snippet": self.snippet,
            "fetched_path": self.fetched_path,
            "sha256": self.sha256,
            "size": self.size,
            "status": self.status,
            "error": self.error,
        }


class WebIntelProvider:
    def __init__(self, config: IntelConfig):
        self.config = config

    def collect(
        self,
        queries: list[str],
        *,
        max_results: int,
        workspace_dir: Path,
        allow_network: bool,
    ) -> list[IntelResult]:
        if not queries or max_results <= 0:
            return []
        if not allow_network:
            raise IntelligenceError("public intelligence collection requires --allow-network")
        if not self.config.web_search_url:
            return [
                IntelResult(
                    query=query,
                    title="web search disabled",
                    url="",
                    status="provider_not_configured",
                    error="intel.web_search_url is not configured",
                )
                for query in queries
            ]

        ensure_directory(workspace_dir)
        collected: list[IntelResult] = []
        remaining = max_results
        for query in queries:
            if remaining <= 0:
                break
            results = self._search(query, remaining)
            for result in results:
                if result.status == "search_result" and result.url:
                    fetched = self._fetch(result.url, workspace_dir)
                    result.fetched_path = fetched.fetched_path
                    result.sha256 = fetched.sha256
                    result.size = fetched.size
                    result.status = fetched.status
                    result.error = fetched.error
                collected.append(result)
                remaining -= 1
                if remaining <= 0:
                    break
        return collected

    def _search(self, query: str, limit: int) -> list[IntelResult]:
        url = _format_search_url(self.config.web_search_url, query, limit)
        headers = {"Accept": "application/json"}
        if self.config.web_search_api_key:
            headers["Authorization"] = f"Bearer {self.config.web_search_api_key}"
            headers["X-API-Key"] = self.config.web_search_api_key
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                payload = json.loads(response.read(self.config.max_fetch_bytes).decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            return [
                IntelResult(
                    query=query,
                    title="web search failed",
                    url=url,
                    status="search_error",
                    error=str(exc),
                )
            ]
        if not isinstance(payload, dict):
            return [
                IntelResult(
                    query=query,
                    title="web search failed",
                    url=url,
                    status="search_error",
                    error="search response must be a JSON object",
                )
            ]
        raw_results = payload.get("results", [])
        if not isinstance(raw_results, list):
            return [
                IntelResult(
                    query=query,
                    title="web search failed",
                    url=url,
                    status="search_error",
                    error="search response results must be a list",
                )
            ]
        results: list[IntelResult] = []
        for item in raw_results[:limit]:
            if not isinstance(item, dict):
                continue
            results.append(
                IntelResult(
                    query=query,
                    title=str(item.get("title", "")),
                    url=str(item.get("url", "")),
                    snippet=str(item.get("snippet", "")),
                )
            )
        return results

    def _fetch(self, url: str, workspace_dir: Path) -> IntelResult:
        if not url.startswith(("http://", "https://")):
            return IntelResult(
                query="",
                title="fetch skipped",
                url=url,
                status="fetch_skipped",
                error="only http and https URLs are fetched",
            )
        request = urllib.request.Request(url, headers={"Accept": "*/*"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                body = response.read(self.config.max_fetch_bytes + 1)
        except (urllib.error.URLError, TimeoutError) as exc:
            return IntelResult(
                query="",
                title="fetch failed",
                url=url,
                status="fetch_error",
                error=str(exc),
            )
        truncated = len(body) > self.config.max_fetch_bytes
        if truncated:
            body = body[: self.config.max_fetch_bytes]
        digest = sha256(body).hexdigest()
        path = safe_intel_artifact_path(workspace_dir, f"{digest[:16]}.bin")
        path.write_bytes(body)
        return IntelResult(
            query="",
            title="fetched",
            url=url,
            fetched_path=str(path),
            sha256=digest,
            size=len(body),
            status="fetched_truncated" if truncated else "fetched",
        )


def safe_intel_artifact_path(workspace_dir: Path, filename: str) -> Path:
    safe_name = validate_simple_filename(filename, label="intel artifact name")
    base = ensure_directory(workspace_dir).resolve()
    path = (base / safe_name).resolve()
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise IntelligenceError("intel artifact path must stay inside the impact workspace") from exc
    return path


def _format_search_url(template: str, query: str, limit: int) -> str:
    encoded = quote_plus(query)
    if "{query}" in template or "{limit}" in template:
        return template.format(query=encoded, limit=limit)
    separator = "&" if "?" in template else "?"
    return f"{template}{separator}q={encoded}&limit={limit}"
