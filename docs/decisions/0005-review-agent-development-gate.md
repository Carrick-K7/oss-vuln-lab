# 0005 Review Agent Development Gate

- Status: accepted
- Date: 2026-05-09

## Context

oss-vuln-digger is an AI-Native, security-sensitive project. The project needs AI-led implementation speed, but vulnerability research code has failure modes that are easy to miss in a single implementation pass:

- drifting away from the current specs
- weakening execution-safety boundaries
- changing candidate, evidence, validation, or confirmed-vulnerability semantics
- overclaiming what the tool can prove
- adding broad orchestration before the core engine contracts are stable

The project should use independent AI review where it improves engineering control. It should not adopt a runtime multi-agent vulnerability-mining architecture just because the development process uses multiple AI roles.

## Decision

Adopt a Review Agent as a development quality gate, not as a runtime vulnerability-mining component.

The Review Agent gate is required before:

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

Runtime multi-agent vulnerability-mining architecture is deferred until the core contracts for findings, evidence, validators, replay, corpus, batching, and safety boundaries are stable enough to justify orchestration.

## Consequences

- Positive: AI-led development gets an explicit quality gate for spec alignment, safety, semantics, and release readiness.
- Positive: the project gains the useful part of multi-agent work, independent review, without coupling the product architecture to agents too early.
- Positive: release tags carry a clearer governance bar.
- Tradeoff: larger changes require one more explicit review step before commit or release.
- Tradeoff: the Review Agent can block overclaiming or unsafe execution changes, but it is not itself proof that a vulnerability is real.

## Follow-up

- Add the Review Agent gate to `AGENTS.md`.
- Add the same expectation to `CONTRIBUTING.md`.
- Use this gate for the next release or tag decision after `0.1.0`.
