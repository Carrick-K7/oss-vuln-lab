# Contributing

This project currently runs local-first. Git history is the execution log, `TASKS.md` is the active backlog, `docs/specs/` records current system contracts, and `docs/decisions/` records larger technical choices.

## Working Style

- Small changes can go straight to implementation and commit
- Medium changes should check and update relevant specs before implementation, then be reflected in `TASKS.md` when they affect active priorities
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
