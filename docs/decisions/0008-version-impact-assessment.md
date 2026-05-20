# 0008 Version Impact Assessment

- Status: accepted
- Date: 2026-05-20

## Context

Operators often need to evaluate whether multiple tagged versions of an open
source project appear affected by a known advisory. Existing `scan`, `replay`,
and corpus workflows can validate one target checkout at a time, but they do not
own version target selection, public intelligence capture, or version matrix
reporting.

This decision is high impact because the feature adds a new persisted manifest
shape, a new report artifact, Git repository checkout behavior, explicit
network-enabled intelligence collection, and optional PoC execution boundaries.
It must preserve the existing rule that confirmed findings require validator
evidence and must not turn a version-range matrix into a vendor advisory.

## Decision

Add a local-first `impact` workflow for version impact assessment.

The workflow reads an impact manifest, resolves explicit Git refs and discovered
Git tags, checks out each selected version into an impact workspace, and writes a
canonical impact report under `<runs_dir>/impacts/<impact-id>/impact.json`.
Human-readable output is written to `impact.md`; public intelligence evidence is
written to `intel.json`; cloned repositories, worktrees, and fetched artifacts
remain under the impact workspace.

Impact statuses are separate from `FindingStatus` and `ValidationStatus`:

- `confirmed_affected`
- `not_reproduced`
- `likely_affected`
- `likely_fixed`
- `unknown`
- `not_buildable`
- `unsupported`
- `error`

Runtime confirmation comes only from existing validator-backed replay or scan
paths. Source signatures, advisory roles, public search snippets, generated PoC
attempts, or missing matches may support likely or unknown impact states, but
they must not create confirmed vulnerability claims.

Public web intelligence is explicit opt-in. The CLI must require
`--allow-network` for manifests that enable intelligence or use a network Git
repository. The first implementation uses a configurable JSON search endpoint
instead of scraping search engine HTML.

## Consequences

- Positive: version-range investigation gains a local, reviewable evidence
  matrix without changing per-run `scan` or `replay` semantics.
- Positive: public intelligence capture is auditable and stored as untrusted
  supporting evidence.
- Positive: corpus replay remains the source of runtime confirmation for known
  PoCs.
- Tradeoff: impact manifests and reports are new source-of-truth artifacts and
  require their own schemas, tests, dashboard rendering, and documentation.
- Tradeoff: generated or discovered PoC execution stays intentionally narrow
  until stronger safety and fixture coverage exist.
- Compatibility: existing run, report, corpus, batch, and schedule artifacts are
  unchanged. Impact reports are additive.

## Follow-up

- Add `impact plan`, `impact assess`, `impact list`, and `impact show` CLI
  commands.
- Add `docs/specs/0006-version-impact-assessment.md`.
- Add `docs/schemas/impact-manifest.schema.json`.
- Add `docs/schemas/impact-report.schema.json`.
- Update README, SECURITY, relevant specs, dashboard rendering, and tests.
- Run the Review Agent gate before committing or releasing this L-sized change.
