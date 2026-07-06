# 0010 Remove Legacy Project Aliases

- Status: accepted
- Date: 2026-05-20

## Context

The project rename to `oss-vuln-lab` happened before the first release tag.
Keeping compatibility aliases before a public release creates extra API surface,
duplicate command names, and ambiguity about the canonical project identity.

## Decision

Remove legacy project aliases before tagging `v0.1.0`.

Only these public entrypoints remain:

- Python package: `oss_vuln_lab`
- Module command: `python3 -m oss_vuln_lab`
- Console script: `ovl`
- Default runs directory: `.ovl_runs`
- Default impact intelligence API key environment variable:
  `OVL_WEB_SEARCH_API_KEY`

## Consequences

- The first release exposes one canonical package and command surface.
- No pre-release compatibility shims need to be maintained.
- Users of commits before the first tag must migrate to the canonical names.
- Tests and documentation should assert the canonical entrypoints rather than
  compatibility aliases.

## Follow-up

- Delete legacy package shims and console script aliases.
- Remove legacy environment-variable fallbacks from scripts and config.
- Run full tests and review before tagging.
