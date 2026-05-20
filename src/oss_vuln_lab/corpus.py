from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from oss_vuln_lab.models import ArtifactEncoding, ArtifactSpec, CveCorpusRecord
from oss_vuln_lab.safety import validate_simple_filename


class CorpusValidationError(ValueError):
    pass


class CorpusStore:
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir).expanduser().resolve()

    def list_records(self) -> list[CveCorpusRecord]:
        if not self.base_dir.exists():
            return []
        records: list[CveCorpusRecord] = []
        for path in sorted(self.base_dir.rglob("*.json")):
            records.append(self.load_manifest(path))
        return sorted(records, key=lambda item: item.cve_id)

    def load_record(self, cve_id: str) -> CveCorpusRecord:
        needle = normalize_cve_id(cve_id)
        for record in self.list_records():
            keys = {normalize_cve_id(record.cve_id), *(normalize_cve_id(alias) for alias in record.aliases)}
            if needle in keys:
                return record
        raise FileNotFoundError(f"No corpus record found for {cve_id}")

    def load_manifest(self, manifest_ref: str | Path) -> CveCorpusRecord:
        path = Path(manifest_ref).expanduser()
        if not path.is_absolute():
            path = self.base_dir / path
        path = path.resolve()
        data = _load_manifest_data(path)
        _validate_manifest_shape(path, data)
        replay = dict(data.get("replay", {}))
        replay["artifacts"] = [
            materialize_artifact_from_path(path.parent, item)
            for item in replay.get("artifacts", [])
        ]
        data["replay"] = replay
        try:
            record = CveCorpusRecord.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise CorpusValidationError(f"{path}: invalid corpus record: {exc}") from exc
        return record


def normalize_cve_id(value: str) -> str:
    return value.strip().upper()


def materialize_artifact_from_path(base_dir: Path, payload: dict[str, object]) -> ArtifactSpec:
    name = str(payload["name"])
    file_path = payload.get("file_path")
    if not file_path:
        return ArtifactSpec.from_dict(payload)
    path = _resolve_artifact_path(base_dir, str(file_path))
    raw = path.read_bytes()
    try:
        content = raw.decode("utf-8")
        encoding = ArtifactEncoding.TEXT
    except UnicodeDecodeError:
        content = base64.b64encode(raw).decode("ascii")
        encoding = ArtifactEncoding.BASE64
    return ArtifactSpec(name=name, content=content, encoding=encoding)


def _load_manifest_data(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as exc:
        raise CorpusValidationError(f"{path}: invalid JSON manifest: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise CorpusValidationError(f"{path}: manifest must be a JSON object")
    return raw


def _validate_manifest_shape(path: Path, data: dict[str, Any]) -> None:
    _required_string(data, "cve_id", path)
    _required_string(data, "summary", path)
    _required_string(data, "project", path)
    _required_string(data, "language", path)
    replay = _required_mapping(data, "replay", path)
    replay_family = _required_string(replay, "vuln_family", path, prefix="replay.")
    _required_string(replay, "title", path, prefix="replay.")
    _required_string(replay, "repro_command", path, prefix="replay.")
    top_level_family = data.get("vuln_family")
    if top_level_family is not None:
        top_level_family = _string_value(top_level_family, "vuln_family", path)
        if top_level_family != replay_family:
            raise CorpusValidationError(
                f"{path}: vuln_family must match replay.vuln_family when both are provided"
            )
    artifacts = replay.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise CorpusValidationError(f"{path}: replay.artifacts must be a list")
    for index, artifact in enumerate(artifacts):
        _validate_artifact_payload(path, Path(path).parent, index, artifact)


def _validate_artifact_payload(
    manifest_path: Path,
    base_dir: Path,
    index: int,
    payload: object,
) -> None:
    label = f"replay.artifacts[{index}]"
    if not isinstance(payload, dict):
        raise CorpusValidationError(f"{manifest_path}: {label} must be an object")
    name = _required_string(payload, "name", manifest_path, prefix=f"{label}.")
    try:
        validate_simple_filename(name, label=f"{label}.name")
    except ValueError as exc:
        raise CorpusValidationError(
            f"{manifest_path}: {exc}"
        ) from exc
    has_content = "content" in payload
    has_file_path = "file_path" in payload and bool(str(payload["file_path"]).strip())
    if not has_content and not has_file_path:
        raise CorpusValidationError(
            f"{manifest_path}: {label} requires either content or file_path"
        )
    if has_content and not isinstance(payload["content"], str):
        raise CorpusValidationError(f"{manifest_path}: {label}.content must be a string")
    if has_file_path:
        file_path = _string_value(payload["file_path"], f"{label}.file_path", manifest_path)
        resolved = _resolve_artifact_path(base_dir, file_path)
        if not resolved.exists() or not resolved.is_file():
            raise CorpusValidationError(
                f"{manifest_path}: {label}.file_path does not resolve to a readable file"
            )


def _resolve_artifact_path(base_dir: Path, file_path: str) -> Path:
    candidate = Path(file_path)
    if candidate.is_absolute():
        raise CorpusValidationError(f"{base_dir}: artifact file_path must be relative")
    resolved = (base_dir / candidate).resolve()
    try:
        resolved.relative_to(base_dir.resolve())
    except ValueError as exc:
        raise CorpusValidationError(f"{base_dir}: artifact file_path must stay within the manifest directory") from exc
    return resolved


def _required_mapping(data: dict[str, Any], key: str, path: Path) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise CorpusValidationError(f"{path}: {key} must be an object")
    return value


def _required_string(
    data: dict[str, Any],
    key: str,
    path: Path,
    *,
    prefix: str = "",
) -> str:
    if key not in data:
        raise CorpusValidationError(f"{path}: missing required field {prefix}{key}")
    return _string_value(data[key], f"{prefix}{key}", path)


def _string_value(value: object, label: str, path: Path) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CorpusValidationError(f"{path}: {label} must be a non-empty string")
    return value.strip()
