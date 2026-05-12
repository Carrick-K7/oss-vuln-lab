# Repository Guidelines

## Project Structure & Module Organization
The main package lives under `src/oss_vuln_digger/`. Keep CLI and pipeline entrypoints there, and keep plugin implementations under `src/oss_vuln_digger/plugins/`. Put automated tests in `tests/`, shell helpers in `scripts/`, high-level planning in `ROADMAP.md`, high-impact technical choices in `docs/decisions/`, current system contracts in `docs/specs/`, and stable machine-checkable manifest contracts in `docs/schemas/`.

## Local-First Workflow
This project currently runs without GitHub issues as the source of truth.

Use these layers:

- `README.md` for stable project facts
- `AGENTS.md` for AI/developer execution rules
- `ROADMAP.md` for long-term direction only
- `docs/decisions/` for numbered Decision Records
- `docs/specs/` for current system contracts
- `docs/schemas/` for stable machine-checkable manifest contracts
- `git commit` for the execution log

Do not turn `ROADMAP.md` into a task tracker. Do not create a separate backlog file as a source of truth; near-term execution belongs in the current working context and git history. Product facts, behavior, compatibility, architecture, release history, and security boundaries belong in README, specs, decisions, schemas, and git history.

## AI-Native Spec-Driven Change Gate
本项目主要由 AI 主导或辅助开发。实现前不要只依赖最近对话上下文，必须按下面顺序执行：

1. Classify the change as `S`, `M`, or `L`.
2. Read the relevant files under `docs/specs/` before changing behavior.
3. Update the relevant Spec before implementation when the change affects behavior, semantics, contracts, or safety boundaries.
4. Create a new Decision Record before implementation when the change affects long-term direction, persisted compatibility, schema strategy, validator status semantics, engine strategy, or security-sensitive boundaries.
5. Implement in small steps and run the smallest useful validation set.
6. Run the documentation impact check before finalizing.
7. In the final response, state which docs/specs were updated, or state that no docs required changes, and state which validation was run.

Update `docs/specs/` before implementation when changing:

- CLI behavior or command semantics
- scan, triage, repro, verify-known, corpus, replay, batch, or schedule workflow semantics
- finding, candidate, evidence, validation, report, run, batch, corpus, or schedule semantics
- replay, corpus, batch, or schedule manifest behavior
- validator status semantics
- PoC, fuzzing, host execution, Docker execution, file write, network, artifact retention, or other execution-safety boundaries
- adapter, vulnerability family, validator, LLM provider, static engine, fuzzing engine, or binary engine contracts

Create a Decision Record before implementation when changing:

- persisted schema or compatibility rules
- security-sensitive execution boundaries
- validator status meaning
- plugin, adapter, engine, or provider strategy
- long-term documentation governance

Do not put roadmap items into specs. Do not put active backlog into roadmap. Do not duplicate schema semantics across README and specs. README may link to contracts, but `docs/specs/` owns system semantics and `docs/schemas/` owns machine-checkable format shape.

## Documentation Impact Check
After any code or behavior change, check whether documentation must be refreshed before finalizing:

- CLI, config, install path, command output, or current capability changed: update `README.md`.
- Workflow, status, evidence, report, run, corpus, batch, schedule, or finding semantics changed: update the relevant files under `docs/specs/`.
- Manifest shape or stable machine-checkable format changed: update `docs/schemas/` and related examples.
- Security boundary changed, including PoC execution, host execution, Docker, network access, artifact materialization, or sensitive data handling: update `docs/specs/0004-execution-safety.md` and, if needed, `SECURITY.md`.
- Long-term direction changed: update `ROADMAP.md`.
- High-impact or compatibility-sensitive decision changed: add or update a Decision Record under `docs/decisions/`.

If no documentation changes are needed, explicitly say so in the final response. Do not leave docs stale just because tests pass.

## Review Agent Gate
Use a Review Agent as a development quality gate, not as a runtime vulnerability-mining component. See `docs/decisions/0005-review-agent-development-gate.md`.

Run a Review Agent pass before:

- creating or moving a release tag
- merging or committing `L` changes
- changing execution-safety boundaries
- changing validator status semantics
- changing persisted schema, report, manifest, or result semantics
- adding or changing engine, adapter, validator, provider, or corpus strategy
- introducing fuzzing, static-analysis, binary-analysis, or exploit-replay engines
- adding remote workers, queues, sync, or networked execution behavior

The Review Agent must check:

- relevant `docs/specs/` files were read and updated when behavior, contracts, or safety changed
- relevant Decision Records exist for high-impact choices
- execution-safety constraints still hold
- candidate, hypothesis, evidence, validation, and confirmed-vulnerability semantics are preserved
- safety-sensitive changes include negative tests or fixture-driven checks
- `README.md`, `ROADMAP.md`, specs, and schemas do not overclaim current capability
- architecture remains local-first and avoids premature runtime multi-agent orchestration

The Review Agent must not:

- mark findings as confirmed vulnerabilities
- execute untrusted PoCs or replay commands
- bypass validators, execution-safety checks, or human approval
- rewrite source-of-truth run artifacts into stronger claims than the evidence supports
- replace the human final decision for release or tag approval

## Change Sizing
Classify work before implementing:

- `S`: docs fixes, narrow bug fixes, small tests, local refactors with no interface change
- `M`: new validator, new vuln family, meaningful replay or corpus workflow change, new CLI subcommand
- `L`: schema/report/manifest changes, pipeline refactors, validator status changes, security-boundary changes, or work expected to take more than a day

Default behavior:

- `S`: implement, test, commit
- `M`: check relevant specs and docs, then implement, test, commit
- `L`: write a Decision Record first, update relevant specs or docs, then implement in smaller steps

## Decision Records
Use `Decision Records` instead of `ADR` as the working term. Store them in `docs/decisions/` with `0000-` style prefixes.

Create a Decision Record when you change:

- CLI behavior
- report schema or persisted result semantics
- replay manifest or corpus record shape
- validator status semantics
- language-adapter strategy
- security-sensitive workflow boundaries
- AI-native review, release-gate governance, or documentation governance

Use `docs/decisions/0000-template.md` as the template.

## Build, Test, and Development Commands
Use the current documented entrypoints and keep them stable:

- `python3 -m unittest -q` runs the test suite
- `python3 -m oss_vuln_digger scan /path/to/project` scans a target repository or ELF binary
- `python3 -m oss_vuln_digger verify-known /path/to/project ...` replays an imported known PoC
- `python3 -m oss_vuln_digger corpus list` and `python3 -m oss_vuln_digger replay cve /path/to/project CVE-...` inspect and replay local CVE manifests
- `python3 -m oss_vuln_digger ui build` and `python3 -m oss_vuln_digger ui serve` operate the local dashboard
- `python3 -m oss_vuln_digger batch run ./batch.json` and `python3 -m oss_vuln_digger schedule once ./schedule.json` drive local automation

If you add or change executable flows, document them in `README.md` and update relevant specs, schemas, or a Decision Record as needed.

## Coding Style & Naming Conventions
Use Python 3.12-compatible code, 4-space indentation, `snake_case` for modules/functions, and `PascalCase` for classes. Favor small focused modules and explicit dataclasses over ad hoc dictionaries when data crosses subsystem boundaries. Extend the plugin-oriented design instead of hardcoding language- or validator-specific branches into the CLI.

## Testing Guidelines
Add or update tests with every behavior change. Prefer deterministic unit and small fixture-driven integration tests that avoid network access. Mirror source concerns with focused files such as `tests/test_pipeline.py`, `tests/test_cli.py`, `tests/test_registry.py`, `tests/test_corpus.py`, and `tests/test_replay.py`. Use temporary directories for generated projects, runs, and payloads.

## Documentation Expectations
Keep `README.md` accurate for the shipped CLI and configuration shape. Update `ROADMAP.md` only when long-term direction changes. Keep `docs/specs/` accurate for current system contracts. Keep `docs/schemas/` accurate for stable manifest contracts. When changing config keys, command names, report schema, or corpus manifest shape, update the relevant examples and contract docs in the same change.

## Security & Configuration Tips
Never commit secrets, API keys, downloaded vulnerability feeds, generated run artifacts, or sensitive PoC corpora. Treat imported PoCs and replay commands as untrusted input. Read `SECURITY.md` before adding fixtures or writing up vulnerability details, and keep undisclosed or target-specific work outside this repository.
