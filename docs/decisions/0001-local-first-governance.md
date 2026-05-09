# 0001 Local-First Project Governance

- Status: accepted
- Date: 2026-04-18

## Context

This project handles vulnerability research workflows and may involve sensitive PoCs or undisclosed issues. A GitHub-first process would improve visibility, but it would also increase the risk of publishing sensitive context too early. The project still needs lightweight planning and decision discipline so the codebase can keep evolving coherently over time.

## Decision

Use a local-first process with four persistent layers:

- `README.md` for stable project facts
- `ROADMAP.md` for long-term direction
- `TASKS.md` for the active local backlog
- `docs/decisions/` for high-impact technical decisions

Use `Decision Records` as the term instead of `ADR`. Store them as numbered Markdown files under `docs/decisions/` using a `0000-` style filename prefix.

## Consequences

- The process stays lightweight for single-maintainer work
- Sensitive vulnerability details do not need to flow into public issue trackers by default
- Important design choices remain recoverable even when the exact implementation context has faded
- Real-time collaboration features from GitHub issues and milestones are deferred until the project actually needs them

## Follow-up

- Keep `TASKS.md` short and current
- Add a new Decision Record whenever CLI, schema, validator semantics, replay manifest shape, or security boundaries change materially
- Revisit whether GitHub becomes the execution source of truth only after the local process feels stable and safe
