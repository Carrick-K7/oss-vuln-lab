from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from oss_vuln_digger.config import LLMConfig
from oss_vuln_digger.models import AnalysisResult, ArtifactSpec, PocSource, PocSpec
from oss_vuln_digger.plugins.base import LLMProvider


REQUIRED_ANALYSIS_FIELDS = (
    "root_cause",
    "trigger_condition",
    "input_shape",
    "reachability_reason",
    "exploit_strategy",
    "confidence",
    "patch_direction",
)

REQUIRED_POC_FIELDS = ("description", "repro_command", "input_payload")


class LocalHeuristicProvider(LLMProvider):
    name = "local"

    def analyze_candidate(self, context: dict[str, Any]) -> AnalysisResult:
        candidate = context["candidate"]
        family = candidate["vuln_family"]
        snippet = candidate["evidence_seed"]
        confidence = _confidence_for_candidate(candidate)
        return AnalysisResult(
            root_cause=_root_cause_for_family(family, snippet),
            trigger_condition=_trigger_for_family(family, snippet),
            input_shape=_input_shape_for_family(family),
            reachability_reason=_reachability_reason(context),
            exploit_strategy=_exploit_strategy_for_family(family),
            confidence=confidence,
            patch_direction=_patch_direction_for_family(family),
        )

    def generate_poc(self, context: dict[str, Any]) -> PocSpec:
        candidate = context["candidate"]
        project = context["project"]
        family = candidate["vuln_family"]
        repro_command = _repro_command_for_candidate(project, candidate)
        if candidate["target_mode"] == "binary_artifact":
            repro_command = project["metadata"].get("suggested_repro_command", "<binary-artifact> < payload.bin")
        payload_name = _payload_name_for_candidate(candidate, repro_command)
        payload = _payload_for_family(family, payload_name)
        return PocSpec(
            description=f"Minimal payload intended to exercise {family}",
            repro_command=repro_command,
            input_payload=payload,
            source=PocSource.GENERATED,
            artifacts=[ArtifactSpec(name=payload_name, content=payload)],
            validation_hints=["docker_build", "sanitizer_runtime", "host_build", "host_sanitizer_runtime"],
        )

    def suggest_fix(self, context: dict[str, Any]) -> str:
        return _patch_direction_for_family(context["candidate"]["vuln_family"])


class OpenAICompatibleProvider(LLMProvider):
    name = "openai_compatible"

    def analyze_candidate(self, context: dict[str, Any]) -> AnalysisResult:
        payload = self._request_json(
            task="analysis",
            context=context,
            required_fields=REQUIRED_ANALYSIS_FIELDS,
        )
        return AnalysisResult(**payload)

    def generate_poc(self, context: dict[str, Any]) -> PocSpec:
        payload = self._request_json(
            task="poc",
            context=context,
            required_fields=REQUIRED_POC_FIELDS,
        )
        return PocSpec(
            description=payload["description"],
            repro_command=payload["repro_command"],
            input_payload=payload["input_payload"],
            source=PocSource(payload.get("source", PocSource.GENERATED.value)),
            artifacts=[
                ArtifactSpec.from_dict(item)
                for item in payload.get("artifacts", [])
            ] if isinstance(payload.get("artifacts", []), list) else [
                ArtifactSpec(name=name, content=content)
                for name, content in dict(payload.get("artifacts", {})).items()
            ],
            validation_hints=list(payload.get("validation_hints", [])),
        )

    def suggest_fix(self, context: dict[str, Any]) -> str:
        payload = self._request_json(
            task="fix",
            context=context,
            required_fields=("patch_direction",),
        )
        return payload["patch_direction"]

    def _request_json(
        self,
        task: str,
        context: dict[str, Any],
        required_fields: tuple[str, ...],
    ) -> dict[str, Any]:
        if not self.config.api_key:
            raise ValueError(f"Environment variable {self.config.api_key_env} is required for {self.name}")

        prompt = {
            "task": task,
            "return_json_only": True,
            "context": context,
        }
        endpoint = self._endpoint()
        body = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a software vulnerability analyst. "
                        "Return JSON only, with no markdown fences."
                    ),
                },
                {"role": "user", "content": json.dumps(prompt)},
            ],
        }

        last_error = ""
        for _ in range(2):
            try:
                response = _post_json(
                    endpoint=endpoint,
                    api_key=self.config.api_key,
                    body=body,
                    timeout_seconds=self.config.timeout_seconds,
                )
                content = response["choices"][0]["message"]["content"]
                payload = _extract_json_payload(content)
                _require_fields(payload, required_fields)
                return payload
            except (KeyError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
                last_error = str(exc)
        raise ValueError(f"{self.name} failed to produce valid JSON for task {task}: {last_error}")

    def _endpoint(self) -> str:
        base = self.config.base_url.rstrip("/") or "https://api.openai.com/v1"
        return f"{base}/chat/completions"


class OpenAIProvider(OpenAICompatibleProvider):
    name = "openai"


def _post_json(endpoint: str, api_key: str, body: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def _extract_json_payload(content: str) -> dict[str, Any]:
    content = content.strip()
    if content.startswith("```"):
        lines = [line for line in content.splitlines() if not line.startswith("```")]
        content = "\n".join(lines).strip()
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1:
            raise
        payload = json.loads(content[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("LLM response is not a JSON object")
    return payload


def _require_fields(payload: dict[str, Any], fields: tuple[str, ...]) -> None:
    missing = [field for field in fields if field not in payload]
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")


def _confidence_for_candidate(candidate: dict[str, Any]) -> str:
    if candidate["candidate_only"]:
        return "medium"
    if candidate["severity_hint"] == "high":
        return "high"
    return "medium"


def _root_cause_for_family(family: str, snippet: str) -> str:
    if family == "memory_safety":
        return f"Manual memory operation appears unsafe near `{snippet}`."
    if family == "boundary_validation":
        return f"Size-sensitive operation may trust unvalidated length data near `{snippet}`."
    if family == "command_execution":
        return f"External command execution may be influenced by attacker-controlled input near `{snippet}`."
    if family == "path_traversal":
        return f"Filesystem operation may consume unsanitized paths near `{snippet}`."
    if family == "deserialization":
        return f"Untrusted data may reach a deserializer near `{snippet}`."
    if family == "sql_injection":
        return f"SQL is constructed dynamically near `{snippet}`, which may allow injection."
    if family == "ssrf":
        return f"Attacker-controlled URLs may reach outbound network requests near `{snippet}`."
    if family == "xxe":
        return f"XML parsing appears reachable without hardened entity handling near `{snippet}`."
    if family == "template_injection":
        return f"Template rendering may evaluate attacker-controlled expressions near `{snippet}`."
    if family == "binary_surface":
        return f"Binary references a risky symbol and needs manual reachability review: `{snippet}`."
    return f"Potential vulnerability candidate near `{snippet}`."


def _trigger_for_family(family: str, snippet: str) -> str:
    if family in {"memory_safety", "boundary_validation"}:
        return f"Supply oversized or malformed input that reaches `{snippet}`."
    if family == "command_execution":
        return "Inject shell metacharacters or replace a trusted command argument."
    if family == "path_traversal":
        return "Use relative paths such as `../` or absolute paths if input reaches the sink."
    if family == "deserialization":
        return "Submit crafted serialized data that triggers unsafe object construction."
    if family == "sql_injection":
        return "Inject SQL syntax through an input that is concatenated into a query."
    if family == "ssrf":
        return "Provide an internal or attacker-controlled URL and observe outbound fetch behavior."
    if family == "xxe":
        return "Send XML with external entities and observe unexpected file or network access."
    if family == "template_injection":
        return "Inject template expressions that are evaluated during rendering."
    if family == "binary_surface":
        return "Exercise code paths that resolve the referenced risky symbol."
    return "Drive attacker-controlled input into the candidate sink."


def _input_shape_for_family(family: str) -> str:
    if family == "command_execution":
        return "CLI argument or configuration value containing shell metacharacters"
    if family == "path_traversal":
        return "Filename or path-like string"
    if family == "deserialization":
        return "Serialized object blob or parser input"
    if family == "sql_injection":
        return "String field interpolated into a SQL statement"
    if family == "ssrf":
        return "URL or URI-like string"
    if family == "xxe":
        return "XML document containing entity declarations"
    if family == "template_injection":
        return "Template source or expression fragment"
    if family == "binary_surface":
        return "Runtime input that reaches the imported risky routine"
    return "Oversized byte buffer or malformed structured input"


def _reachability_reason(context: dict[str, Any]) -> str:
    project = context["project"]
    entrypoints = project.get("entrypoints") or []
    if entrypoints:
        return f"Candidate is in a project with concrete entrypoints: {', '.join(entrypoints[:3])}."
    return "Candidate was selected from reachable source or binary surfaces using builtin heuristics."


def _exploit_strategy_for_family(family: str) -> str:
    if family == "memory_safety":
        return "Reach the unsafe sink with crafted length or content until sanitizer reports memory corruption."
    if family == "boundary_validation":
        return "Manipulate size fields so allocations and copies disagree."
    if family == "command_execution":
        return "Inject shell syntax or controlled command fragments to redirect execution."
    if family == "path_traversal":
        return "Traverse outside the intended directory and observe unauthorized file access."
    if family == "deserialization":
        return "Deliver a malicious serialized payload that causes unsafe object materialization."
    if family == "sql_injection":
        return "Inject query fragments that alter control flow or exfiltrate data."
    if family == "ssrf":
        return "Target internal services or metadata endpoints via attacker-supplied URLs."
    if family == "xxe":
        return "Resolve external entities to disclose files or induce outbound requests."
    if family == "template_injection":
        return "Inject template expressions that escape data context and execute helpers."
    if family == "binary_surface":
        return "Use runtime tracing or targeted harnessing to prove the risky symbol is reachable."
    return "Craft input that forces the suspicious code path."


def _patch_direction_for_family(family: str) -> str:
    if family == "memory_safety":
        return "Add strict bounds checks and replace unsafe copy routines with length-checked variants."
    if family == "boundary_validation":
        return "Validate lengths before allocation or copy, and reject inconsistent sizes."
    if family == "command_execution":
        return "Avoid shell invocation; use fixed command arrays and strict allowlists."
    if family == "path_traversal":
        return "Canonicalize paths, reject traversal sequences, and enforce a fixed root directory."
    if family == "deserialization":
        return "Reject untrusted serialized formats or switch to safe schema-validated decoding."
    if family == "sql_injection":
        return "Use parameterized queries and remove dynamic SQL concatenation."
    if family == "ssrf":
        return "Validate destinations against strict allowlists and block internal address ranges."
    if family == "xxe":
        return "Disable external entities and harden XML parser defaults."
    if family == "template_injection":
        return "Separate code from templates and avoid evaluating attacker-controlled expressions."
    if family == "binary_surface":
        return "Confirm symbol reachability before triage, then remove unsafe calls or add stronger guards."
    return "Constrain attacker-controlled input and add explicit validation."


def _payload_for_family(family: str, payload_name: str) -> str:
    if payload_name.endswith(".tif"):
        return "II*\x00\x08\x00\x00\x00BROKEN-TIFF-DATA"
    if family == "path_traversal":
        return "../../etc/passwd\n"
    if family == "command_execution":
        return "test;id\n"
    if family == "sql_injection":
        return "' OR '1'='1"
    if family == "ssrf":
        return "http://169.254.169.254/latest/meta-data/\n"
    if family == "xxe":
        return "<!DOCTYPE x [<!ENTITY leak SYSTEM 'file:///etc/passwd'>]><x>&leak;</x>"
    if family == "template_injection":
        return "{{7*7}}"
    return "A" * 512


def _repro_command_for_candidate(project: dict[str, Any], candidate: dict[str, Any]) -> str:
    if candidate["target_mode"] == "binary_artifact":
        return project["metadata"].get("suggested_repro_command", "<binary-artifact> < payload.bin")

    binary_path = _binary_for_candidate(project, candidate)
    if not binary_path:
        return project["metadata"].get("suggested_repro_command", "<build-artifact> @payload_path@")

    if binary_path.endswith("/tiffcrop"):
        return f"{binary_path} @payload_path@ @output_path@"
    return f"{binary_path} @payload_path@"


def _binary_for_candidate(project: dict[str, Any], candidate: dict[str, Any]) -> str:
    metadata = project.get("metadata", {})
    by_source = metadata.get("binary_candidates", {})
    root = project.get("root", "")
    file_path = candidate.get("file_path", "")
    if root and file_path.startswith(root):
        rel = file_path[len(root) :].lstrip("/")
        if rel in by_source:
            return by_source[rel]
    return metadata.get("default_binary", "")


def _payload_name_for_candidate(candidate: dict[str, Any], repro_command: str) -> str:
    file_path = candidate.get("file_path", "")
    if "tiffcrop" in file_path or "tiffcrop" in repro_command:
        return "payload.tif"
    if candidate["vuln_family"] == "xxe":
        return "payload.xml"
    if candidate["vuln_family"] == "path_traversal":
        return "payload.txt"
    return "payload.bin"
