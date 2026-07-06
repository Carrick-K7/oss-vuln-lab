# Spec: Research Workflows

- Status: accepted
- Stability: evolving
- Last reviewed: 2026-05-20
- Applies to: CLI, pipeline, dashboard, batch, schedule, impact
- Supersedes: none

## Purpose

本 Spec 定义主要研究工作流的语义。它约束 CLI、pipeline、dashboard、batch、schedule 之间如何共享同一套本地研究 kernel。

## Scope

覆盖这些工作流：

- `scan`
- `triage`
- `repro`
- `report`
- `verify-known`
- `corpus list/show`
- `replay cve`
- `replay manifest`
- `ui build/serve`
- `batch run/list/show`
- `schedule once/run/show`
- `impact plan/assess/list/show`

## Non-Goals

本 Spec 不定义 UI 视觉设计、不定义具体漏洞规则、不定义外部 advisory feed 导入协议、不定义未来远程 worker 或 SaaS 执行模型。

## Requirements

- All workflows MUST write or read local artifacts under the configured runs/corpus locations.
- CLI, dashboard, batch, and schedule MUST reuse the same pipeline semantics instead of forking research logic.
- A workflow MUST NOT silently upgrade a hypothesis to confirmed without validator evidence.
- `scan` MUST produce candidate findings from local target inspection and available analysis providers.
- `verify-known` MUST model the input as a known PoC replay, not as a new discovery claim.
- `replay cve` and `replay manifest` MUST load corpus records through the corpus validation path.
- `batch run` MUST execute scan or replay jobs and preserve per-job run references.
- `schedule once/run` MUST be local process orchestration, not a durable remote scheduler.
- `ui build/serve` MUST be an inspection layer over existing local artifacts.
- `impact` MUST produce version evidence matrices without redefining single-run finding semantics.

## Workflow Semantics

### scan

`scan` detects the target mode, builds project context, extracts candidates, generates analysis, attempts PoC synthesis when available, runs enabled validators, and writes a run result. A scan may produce zero findings.

### triage

`triage` is an operator-facing review step over an existing run and finding. It must not mutate historical evidence unless the implementation explicitly records the mutation as a new artifact or state transition.

### repro

`repro` reruns or materializes validation for a finding. It must preserve the relationship to the original run and finding.

### report

`report` renders existing run data. It must not invent new evidence or change finding semantics.

### verify-known

`verify-known` imports a known replay command and optional artifacts against a target. It records the result as known-PoC validation.

### corpus and replay

`corpus list/show` inspect local corpus manifests. `replay cve` resolves a record by CVE/GHSA id or alias. `replay manifest` executes an explicit manifest path. Both replay paths share the same validation semantics.

### ui

The local dashboard is a read-oriented workbench over run, batch, evidence and corpus artifacts. It may add navigation and summarization, but must not redefine statuses.

### batch

Batch execution groups multiple scan or replay jobs. Batch results must store per-job status, run references, finding summaries, deduplication metadata, and regression comparison when available.

### schedule

Schedule execution evaluates due local tasks and delegates due work to batch execution. Schedule state records last run timestamps and last batch ids.

### impact

`impact plan` validates an impact manifest and resolves selected Git version targets without running validators.

`impact assess` checks out selected versions, optionally captures public intelligence when network access is explicitly allowed, reuses existing replay or scan validation paths, evaluates source signatures, and writes an impact report under `<runs_dir>/impacts/`.

`impact list` and `impact show` inspect recorded impact reports. They must not mutate reports or infer new evidence.

## 0.1.0 MVP Acceptance

Before tagging `0.1.0`:

- `scan` MUST create a local run containing `run.json`, `report.json` and `report.md`.
- `verify-known` and `replay` MUST write known-PoC findings without representing them as new discoveries.
- `corpus` MUST reject malformed replay manifests before pipeline execution.
- `batch` MUST preserve per-job run references and summarize job status.
- `schedule` MUST delegate due tasks into batch execution and persist local schedule state.
- `ui build` MUST render existing local artifacts without redefining status semantics.
- `impact assess` MAY remain an evolving workflow, but any persisted impact status must follow `docs/specs/0006-version-impact-assessment.md`.
- `triage` MAY update a run only if the previous state is recorded as an explicit triage artifact or equivalent event.

## Scenarios

```text
Given a batch manifest with one scan job and one replay_cve job
When batch run executes successfully
Then the batch result references two underlying runs and summarizes findings without duplicating full run records
```

```text
Given a dashboard built from a runs directory
When the dashboard shows findings, batch results, and impact reports
Then displayed status names must match the data semantics spec
```

## Compatibility

CLI commands documented in `README.md` are treated as supported entrypoints. Behavior-changing command changes require a Decision Record when they alter persisted output, result semantics or safety boundaries.

The supported project entrypoints are `python3 -m oss_vuln_lab` and `ovl`.

## Security

Any workflow that executes target code, replay commands or PoC artifacts is governed by `docs/specs/0004-execution-safety.md`.

## Verification

Workflow changes must include deterministic unit or fixture-driven integration tests for the changed command path. Batch and schedule changes must verify local artifact creation and reload behavior.

## Open Questions

None.
