# Spec: Data Semantics

- Status: accepted
- Stability: evolving
- Last reviewed: 2026-05-20
- Applies to: pipeline, validators, dashboard, batch, schedule, impact, schemas
- Supersedes: none

## Purpose

本 Spec 定义核心数据对象和状态值的含义。JSON Schema 只校验字段形状，本 Spec 定义字段背后的语义。

## Scope

覆盖这些概念：

- target
- project context
- candidate
- analysis result
- PoC spec
- evidence
- validation result
- finding
- run result
- corpus record
- batch result
- schedule state
- impact report

## Non-Goals

本 Spec 不列出所有 Python dataclass 字段，也不替代 `docs/schemas/` 中的机器校验文件。

## Requirements

- Data producers MUST preserve status semantics across CLI, report, dashboard, batch, and schedule.
- Persisted data MUST remain reviewable without live target access when evidence has been captured.
- Schema validation MUST NOT be treated as proof that a vulnerability exists.
- LLM-generated analysis MUST be stored as hypothesis or explanatory material unless backed by validator evidence.
- Batch summaries MUST reference underlying runs instead of replacing them as source of truth.
- Impact reports MUST keep version impact statuses separate from `FindingStatus` and `ValidationStatus`.

## Status Semantics

### ValidationStatus

- `unsupported`: validator cannot evaluate the target, language, command, environment or artifact shape.
- `failed`: validator attempted execution but did not observe evidence matching the hypothesis, or the execution failed before meaningful validation.
- `hypothesis`: validator produced useful reasoning or partial evidence, but not enough runtime confirmation.
- `confirmed`: validator observed runtime evidence consistent with the vulnerability hypothesis.

### FindingStatus

- `candidate`: a potential issue worth review.
- `poc_synthesized`: a PoC was generated or materialized, but confirmation is not guaranteed.
- `manual_review`: human review is required before stronger claims.
- `confirmed_generated_poc`: a generated PoC produced confirming validator evidence.
- `confirmed_known_poc`: a known PoC or corpus replay produced confirming validator evidence.

## Evidence Semantics

Evidence may include command output, sanitizer output, traceback, artifact path, logs or metadata. Evidence must be tied to a validation step, candidate, replay, run, batch job or schedule execution.

Evidence is not automatically sufficient. The status transition depends on whether the evidence supports the vulnerability hypothesis.

## Corpus Semantics

A corpus record describes a known vulnerability or advisory replay target. It may contain CVE ids, GHSA ids, aliases, affected versions, fixed versions, references, replay metadata and artifacts.

Corpus manifests are local research inputs. They must not contain sensitive undisclosed details unless the repository is intentionally private and governed by `SECURITY.md`.

Corpus manifest 也是当前 advisory 和 affected-version 元数据的归属位置。当前架构不包含数据库型 knowledge store。引入数据库必须先新增 Decision Record，并且不得替代 corpus manifest 或 run artifact 的 source-of-truth 地位。

## Batch Semantics

A batch result is an orchestration artifact. It summarizes job outcomes, points to underlying run ids and may compute deduplication or regression comparison metadata. It is not the canonical source for individual finding evidence.

## Schedule Semantics

Schedule state records local execution timing and last batch ids. It is not a durable distributed scheduler contract.

## Impact Semantics

An impact report is a version evidence matrix for one advisory. It may reference
underlying replay or scan run ids for per-version runtime evidence. It is not the
canonical source for individual finding evidence and it is not an authoritative
vendor version advisory.

Impact statuses are defined in `docs/specs/0006-version-impact-assessment.md`.
They are intentionally separate from `FindingStatus` and `ValidationStatus`.

## Source of Truth

- `run.json` is the canonical source for one scan or replay run.
- `report.json`, `report.md` and dashboard output are views over run data.
- `corpus/` manifest 是 curated advisory、version-range 和 replay 元数据的本地 canonical source。
- Batch results summarize job outcomes and reference run ids; they do not replace underlying runs.
- Schedule state records timing and last batch ids; it does not replace batch results.
- `impact.json` is the canonical source for one version impact assessment; it references underlying runs when runtime evidence exists.
- JSON Schema files under `docs/schemas/` are reference contracts for stable manifest shapes. Runtime validation may be implemented with hand-written validation code unless a future Decision Record makes schema validation mandatory.

## 0.1.0 MVP Acceptance

Before tagging `0.1.0`:

- Validation statuses MUST keep the meanings defined in this Spec.
- Finding statuses MUST distinguish candidate, manual review, synthesized PoC and confirmed known/generated PoC.
- `not_run` MAY appear as a derived PoC status when no validator executed.
- Batch job status MUST distinguish completed and failed jobs.
- Reports and dashboard output MUST not invent stronger status claims than the underlying run data.
- Impact reports MUST not convert `not_reproduced`, source signatures, public snippets, or advisory roles into confirmed vulnerability claims.

## Scenarios

```text
Given a validator returns sanitizer output matching the candidate trigger
When the validator status is confirmed
Then a finding may move to confirmed_generated_poc or confirmed_known_poc depending on PoC source
```

```text
Given a batch job fails before producing a run id
When the batch result is rendered
Then the job status must be failed and the batch must not invent a finding count
```

## Compatibility

Persisted data semantics may only change through a Decision Record. Additive fields are preferred over repurposing existing fields.

## Security

Evidence may contain local paths, target names, crash data or sensitive PoC material. Implementations must avoid committing generated run artifacts and sensitive corpora.

## Verification

Tests must cover status transitions and serialization/deserialization paths when semantics change. Dashboard and report tests should assert that displayed status names map to these semantics.

## Open Questions

None.
