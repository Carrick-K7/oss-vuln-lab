# Contributing

This project currently runs local-first. Git history is the execution log, `docs/specs/` records current system contracts, and `docs/decisions/` records larger technical choices.

## Working Style

- Small changes can go straight to implementation and commit
- Medium changes should check and update relevant specs before implementation
- Larger or riskier changes should be written down as a Decision Record before implementation, then implemented in smaller steps

Use the following rough sizing:

- `S`: docs fixes, small bugs, narrow test fixes, small refactors that do not change behavior
- `M`: new validator, new vuln family, new CLI subcommand, meaningful replay or corpus workflow change
- `L`: schema changes, report shape changes, replay manifest changes, pipeline refactors, security-boundary changes, or work expected to take more than a day

## Decision Records

Use `docs/decisions/` for high-impact choices. This project uses `Decision Records` rather than `ADR` as the working term. Filenames use a `0000-` style prefix.

Write a Decision Record when you change:

- CLI behavior or command shape
- report schema or persisted result semantics
- replay manifest or corpus record shape
- validator status semantics
- language-adapter strategy
- security-sensitive workflow boundaries

Keep records short. The default structure is:

- Context
- Decision
- Status
- Consequences
- Follow-up

## Specs

Specs are the current system contracts. Read the relevant files under `docs/specs/` before changing behavior.

Update specs before implementation when changing:

- CLI behavior or command semantics
- research workflow semantics
- finding, evidence, validation, report, batch, corpus, or schedule semantics
- replay, corpus, batch, or schedule manifest behavior
- validator status semantics
- execution safety boundaries
- adapter, vulnerability family, validator, provider, or future engine contracts

Use `docs/schemas/` for stable machine-checkable manifest formats. Do not duplicate schema field meaning in README; README should link to the relevant spec and schema.

## Documentation Check

After code or behavior changes, check whether documentation must be refreshed:

- update `README.md` for CLI, config, command output, install path, or current capability changes
- update `docs/specs/` for workflow, status, evidence, report, run, corpus, batch, schedule, or finding semantic changes
- update `docs/schemas/` and examples for manifest or stable machine-format changes
- update `docs/specs/0004-execution-safety.md` or `SECURITY.md` for security-boundary changes
- update `ROADMAP.md` only for long-term direction changes
- add a Decision Record for high-impact or compatibility-sensitive choices

If no docs require changes, say that explicitly in the change summary.

## Review Gate

Use a Review Agent as a development quality gate for high-risk work. It is a review role, not a runtime vulnerability-mining component.

Run the Review Agent gate before:

- creating or moving a release tag
- merging or committing `L` changes
- changing execution-safety boundaries
- changing validator status semantics
- changing persisted schema, report, manifest, or result semantics
- adding or changing engine, adapter, validator, provider, or corpus strategy
- introducing fuzzing, static-analysis, binary-analysis, or exploit-replay engines
- adding remote workers, queues, sync, or networked execution behavior

The review must check spec alignment, Decision Record coverage, safety boundaries, data/status semantics, negative-test coverage for safety-sensitive changes, documentation honesty, and architectural restraint.

The Review Agent must not confirm vulnerabilities, execute untrusted PoCs, bypass validators or human approval, or replace the human release decision.

## Validation

Before finalizing a change, run the smallest useful validation set. At minimum:

```bash
python3 -m unittest -q
```

If you add a new command, config key, or manifest field, update `README.md` in the same change.

## Security

This repository may involve sensitive vulnerability research. Do not commit:

- undisclosed vulnerabilities
- weaponized PoCs that are not intended for publication
- real target details
- credentials, tokens, or downloaded private datasets

Read `SECURITY.md` before adding replay samples or discussing vulnerability details in committed docs.
