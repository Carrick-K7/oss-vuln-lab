# Spec: Execution Safety

- Status: accepted
- Stability: stable
- Last reviewed: 2026-05-09
- Applies to: validators, pipeline, CLI, batch, schedule, future fuzzing
- Supersedes: none

## Purpose

本 Spec 定义执行 PoC、replay、validator、batch、schedule 和未来 fuzzing 时的安全边界。它是开发门禁，不是建议文档。

## Scope

覆盖这些风险面：

- imported PoC
- replay command
- target repository
- generated artifact
- corpus artifact
- host execution
- Docker execution
- file writes
- network access
- environment variables
- batch and schedule execution
- future fuzzing corpus and crash artifacts

## Non-Goals

本 Spec 不定义漏洞披露流程。披露、敏感材料和仓库内容边界由 `SECURITY.md` 定义。

## Requirements

- Imported PoCs, replay commands, target repositories, generated artifacts and fuzz corpora MUST be treated as untrusted.
- Code MUST NOT execute untrusted commands without an explicit validator path.
- Host execution MUST be opt-in through configuration or an explicit command path.
- Docker or sandboxed execution SHOULD be preferred for untrusted replay when available.
- File materialization MUST keep artifacts inside the intended run, candidate or corpus directory.
- Artifact names accepted from manifests or CLI MUST be simple filenames unless a Decision Record explicitly allows paths.
- Manifest-relative file paths MUST stay within the manifest directory.
- Network access during validation MUST be disabled or explicit by default policy.
- Secrets, API keys, tokens and sensitive target details MUST NOT be written into committed fixtures or docs.
- Batch and schedule MUST NOT weaken safety checks applied to individual scan or replay jobs.
- AI-generated commands MUST NOT be executed automatically unless they pass the same validator safety boundary as human-provided commands.

## Host Execution

Host-side validators are useful but risky. A host validator may run local target commands only when the operator has explicitly enabled it. Host execution must preserve command, environment and evidence metadata.

## Docker Execution

Docker execution is not automatically safe. Implementations must still constrain mounted paths, artifact materialization and command construction. Docker failures should be reported as validator failures or unsupported states according to `docs/specs/0003-data-semantics.md`.

## File Writes

Generated artifacts belong under configured run directories. Corpus artifact materialization must not escape the manifest directory. CLI-supplied artifact names must not allow path traversal.

## Network Access

Networked behavior must be explicit. Future integrations with OSV, NVD, advisory feeds, remote LLMs or remote workers require a Decision Record when they affect data persistence, privacy or execution semantics.

## Future Fuzzing

Fuzzing will generate high-volume inputs, crashes and minimized reproducers. Future fuzzing support must define corpus storage, crash retention, deduplication, minimization and sensitive artifact handling before implementation.

## 0.1.0 MVP Acceptance

Before tagging `0.1.0`:

- Default configuration MUST NOT enable host or direct runtime replay of untrusted commands.
- Host and direct runtime validators MUST require explicit operator configuration.
- CLI and manifest artifact names MUST be validated as simple filenames before materialization.
- Materialized artifacts MUST stay inside the intended run or corpus directory.
- Docker validation MUST use an explicit network policy; the default policy is no network.
- Batch and schedule MUST reuse individual job safety checks.
- Safety regressions MUST have deterministic negative tests.

## Scenarios

```text
Given a replay artifact name contains ../
When the system materializes the artifact
Then the operation must fail before writing outside the intended directory
```

```text
Given a schedule manifest runs a replay job
When the replay job reaches validator execution
Then the same safety checks used by direct replay must apply
```

## Compatibility

Tightening safety validation may reject manifests or CLI inputs that previously worked. If persisted compatibility is affected, write a Decision Record and update related schemas and tests.

## Security

This Spec is security-sensitive. Changes to its MUST-level requirements require a Decision Record before implementation.

## Verification

Safety changes must include negative tests for path traversal, unsafe artifact names, unsupported validator states or untrusted execution boundaries as applicable.

## Open Questions

None.
