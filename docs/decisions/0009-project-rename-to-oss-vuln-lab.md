# 0009 Project Rename To oss-vuln-lab

- Status: superseded by 0010
- Date: 2026-05-20

## Context

The project has grown from candidate vulnerability discovery into a broader
local research workbench: known-CVE replay, validator-backed evidence capture,
batch and schedule orchestration, dashboard review, and version impact
assessment. The previous discovery-oriented name did not describe verification
and impact-assessment workflows well.

## Decision

Rename the project to `oss-vuln-lab`.

The primary Python package becomes `oss_vuln_lab`, the primary module entrypoint
becomes `python3 -m oss_vuln_lab`, and the primary console script becomes
`ovl`.

Initial implementation kept compatibility entrypoints for the old Python package
name and console script. Decision Record 0010 removes those before tagging the
first release.

## Consequences

- The project name better matches the broader lab/workbench scope.
- CLI documentation and examples move to `oss_vuln_lab` and `ovl`.
- Decision Record 0010 removes the compatibility window before the first tag.
- Schema identifiers and dashboard branding move to `oss-vuln-lab`.
- Default local run storage moves to `.ovl_runs`.

## Follow-up

- Update package imports, console scripts, docs, specs, schemas, and tests.
- Run the full test suite.
- Run the Review Agent gate before committing because this is an L-sized public
  interface change.
