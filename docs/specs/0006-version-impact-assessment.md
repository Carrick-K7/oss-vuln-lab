# Spec: Version Impact Assessment

- Status: accepted
- Stability: evolving
- Last reviewed: 2026-05-20
- Applies to: CLI, impact manifests, Git version resolution, public intelligence, replay, reports, dashboard
- Supersedes: none

## Purpose

This Spec defines the `impact` workflow. The workflow evaluates evidence across
multiple Git versions for one advisory and produces a local evidence matrix. It
does not replace vendor advisories, package-manager metadata, corpus records, or
single-target run artifacts.

## Scope

Covered:

- `impact plan`
- `impact assess`
- `impact list`
- `impact show`
- impact manifest validation
- explicit refs and Git tag discovery
- public intelligence search/fetch capture
- version impact statuses
- impact report persistence and dashboard summaries

Not covered:

- package-manager version downloads
- authoritative ecosystem version-range solving
- direct search-engine HTML scraping
- remote workers, queues, or distributed assessment
- automatic exploitability or exploit-chain scoring

## Requirements

- The workflow MUST remain local-first by default.
- Network access MUST require explicit `--allow-network` when intelligence is
  enabled or the version source repository is a network URL.
- Public search results, fetched pages, target repositories, and PoC material
  MUST be treated as untrusted input.
- Version target selection MUST support explicit refs and discovered tags for
  Git repositories.
- Tag discovery MUST use `git ls-remote --tags --refs`, include/exclude glob
  filters, de-duplication by ref, a deterministic semver-like sort, and a limit.
- Runtime confirmation MUST reuse validator-backed `scan` or `replay` paths.
- Impact statuses MUST NOT alter `FindingStatus` or `ValidationStatus`.
- `confirmed_affected` MUST require confirming validator evidence for that
  version.
- `not_reproduced` means replay or execution ran without confirmation. It MUST
  NOT be interpreted as proof that a version is unaffected.
- `likely_affected` and `likely_fixed` may be based on source signatures,
  configured fixed controls, or non-confirming evidence, but MUST remain lower
  confidence than `confirmed_affected`.
- Public intelligence and fetched artifacts MUST be stored inside the impact
  workspace with bounded size and content hashes.
- Discovered PoCs MUST NOT be executed unless `--execute-discovered-poc` is set.
- Generated PoCs MUST NOT be executed unless `--execute-generated-poc` is set.
- Impact reports MUST be explicit evidence matrices, not advisory publications.

## CLI Semantics

`impact plan <manifest>` validates the manifest and prints the selected version
targets. It does not run validators and does not claim impact.

`impact assess <manifest>` resolves versions, checks out each selected ref,
runs enabled assessment steps, and writes:

- `<runs_dir>/impacts/<impact-id>/impact.json`
- `<runs_dir>/impacts/<impact-id>/impact.md`
- `<runs_dir>/impacts/<impact-id>/intel.json`
- `<runs_dir>/impacts/<impact-id>/workspace/`

`impact list` lists recorded impact reports.

`impact show <impact-id>` summarizes one recorded impact report and prints the
report artifact paths.

## Manifest Semantics

The manifest describes one advisory and one Git version source.

Required top-level fields:

- `schema_version`
- `name`
- `advisory`
- `version_source`

The advisory object identifies the issue under investigation. `advisory.id` may
be a CVE, GHSA, or other public identifier. `source_hints` identify files or
sinks useful for source analysis; they are not proof.

The version source object currently supports `type: "git"` only. Explicit
version targets provide `version`, `ref`, and optional `role`. Discovery may add
refs matching include filters and not matching exclude filters.

The replay object may reference a local corpus record with `corpus_ref`.

The intelligence object may define search queries and `max_results`. It is
ignored unless `enabled` is true and `--allow-network` is supplied.

Source signatures are deterministic file-content checks. A vulnerable signature
match may support `likely_affected`; a fixed signature match may support
`likely_fixed`.

## Assessment Order

For each selected version:

1. Check out the Git ref into the impact workspace.
2. If `replay.corpus_ref` is present, run the existing corpus replay path
   against the checkout.
3. Capture public intelligence when enabled and allowed.
4. Do not execute discovered PoC material unless `--execute-discovered-poc` is
   set.
5. Do not execute generated PoCs unless `--execute-generated-poc` is set.
6. If runtime confirmation is absent, evaluate source signatures and assign only
   `likely_affected`, `likely_fixed`, or `unknown` unless an operational error
   applies.

## Status Semantics

- `confirmed_affected`: validator-backed replay or generated PoC evidence
  confirmed the advisory hypothesis for this version.
- `not_reproduced`: runtime validation ran but did not confirm the advisory
  hypothesis. This does not prove unaffected.
- `likely_affected`: source signatures or other non-runtime evidence indicate
  the vulnerable pattern likely exists.
- `likely_fixed`: fixed/source-negative evidence or fixed-control evidence
  indicates the vulnerable pattern likely does not exist.
- `unknown`: available evidence is insufficient.
- `not_buildable`: checkout or build prerequisites prevented meaningful
  validation.
- `unsupported`: the target shape or configured validators cannot assess this
  version.
- `error`: unexpected operational failure.

## Source of Truth

- `impact.json` is the canonical source for a version impact assessment.
- `impact.md` and dashboard impact cards are views over `impact.json`.
- `intel.json` is supporting public intelligence evidence.
- `run.json` remains the canonical source for an individual scan or replay run.
- Corpus manifests remain the local canonical source for curated advisory replay
  metadata.
- `docs/schemas/impact-manifest.schema.json` defines the stable manifest shape.
- `docs/schemas/impact-report.schema.json` defines the stable impact report
  shape.

## Security

All target checkouts, fetched pages, public PoC material, generated artifacts,
and replay commands are governed by `docs/specs/0004-execution-safety.md`.
Fetched material must stay inside the impact workspace and must be size capped.
Network access and PoC execution are explicit operator choices.

## Verification

Implementations must include:

- manifest validation tests
- Git version selection tests with a local temporary repository
- CLI plan/list/show/assess tests
- safety tests for network opt-in and artifact path containment
- status mapping tests for confirmed, not reproduced, likely affected, and
  likely fixed outcomes

## Open Questions

- Whether future package-manager resolvers should produce targets alongside Git
  tags.
- Whether public advisory feeds should be imported into corpus manifests or a
  future local knowledge store.
