# Spec: Engine Contracts

- Status: accepted
- Stability: evolving
- Last reviewed: 2026-05-20
- Applies to: adapters, vuln families, validators, LLM providers, impact intelligence, future engines
- Supersedes: none

## Purpose

本 Spec 定义 project adapter、vulnerability family、validator、LLM provider 以及未来 static/fuzz/binary engine 的接入契约。它防止新能力直接硬编码进 CLI 或破坏 pipeline 语义。

## Scope

覆盖这些扩展点：

- project adapters
- vulnerability family plugins
- validators
- LLM or analysis providers
- future static-analysis engines
- future fuzzing engines
- future binary-analysis engines
- impact intelligence providers and version resolvers

## Non-Goals

本 Spec 不指定某个第三方引擎的内部实现，不规定每种语言必须达到相同检测能力。

## Requirements

- New engines SHOULD plug into registry or plugin-oriented boundaries instead of adding CLI-specific branches.
- Engines MUST return structured data compatible with `docs/specs/0003-data-semantics.md`.
- Validators MUST use the shared `ValidationStatus` semantics.
- Engines MUST NOT silently execute untrusted commands outside the execution safety contract.
- Project adapters MUST describe detected language/build context without mutating the target project.
- Vulnerability family plugins MUST produce candidates as hypotheses, not confirmations.
- LLM providers MUST be optional and must not be the sole source of confirmed vulnerability claims.
- Impact intelligence providers MUST return supporting evidence only and MUST NOT produce confirmed vulnerability states.
- Version resolvers MUST be deterministic for the same manifest and repository state.
- Future fuzzing engines MUST report campaign metadata, corpus/crash artifacts, deduplication identity and validation linkage before findings become confirmed.
- Future binary engines MUST distinguish binary-risk surfacing from confirmed exploitability.

## Adapter Contract

A project adapter identifies target mode, language profile, build system, source files, entrypoints and metadata. It must be deterministic for the same local input.

## Vulnerability Family Contract

A vulnerability family plugin maps project context to candidates. It should include enough location, sink, evidence seed and severity hint for later triage and validation.

## Validator Contract

A validator evaluates a PoC, replay or finding in a controlled path. It must return validator name, status, summary, command when applicable, evidence and metadata.

## Provider Contract

An LLM or analysis provider may explain root cause, trigger condition, reachability, input shape, exploit strategy and patch direction. Provider output remains advisory until validator evidence supports it.

## Impact Intelligence Contract

An impact intelligence provider may search a configured JSON endpoint and fetch
bounded public content into the impact workspace. It returns titles, URLs,
snippets, hashes, storage paths, and fetch errors as supporting evidence only.
It must not execute fetched content or classify versions as confirmed affected.

## Future Engine Contract

Future engines must declare:

- input target type
- produced data objects
- artifact retention behavior
- safety boundary
- status mapping
- deterministic test strategy
- compatibility impact

## 0.1.0 MVP Acceptance

Before tagging `0.1.0`:

- Existing project adapters MUST remain registry-driven.
- Existing vulnerability family plugins MUST produce candidates, not confirmations.
- Existing validators MUST return shared `ValidationStatus` values.
- Existing LLM/local providers MUST not be the sole source of confirmed vulnerability claims.
- Future static, fuzzing and binary engines MAY remain design targets and MUST NOT block `0.1.0`.

## Scenarios

```text
Given a new fuzzing engine
When it discovers a crash
Then it must emit structured crash/corpus metadata and cannot mark the finding confirmed without validation semantics
```

```text
Given a new language adapter
When scan runs on a target repository
Then adapter output must fit ProjectContext without adding language-specific branches to CLI
```

## Compatibility

New engines may add fields or metadata, but they must not change existing status meanings or report semantics without a Decision Record.

## Security

All engine execution is governed by `docs/specs/0004-execution-safety.md`.

## Verification

New engines require focused tests for registry integration, deterministic output and safety behavior. Validators require at least one supported path and one unsupported or failed path test.

## Open Questions

None.
