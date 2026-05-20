# 0009 Project Rename To oss-vuln-lab

- Status: accepted
- Date: 2026-05-20

## Context

The project has grown from candidate vulnerability discovery into a broader
local research workbench: known-CVE replay, validator-backed evidence capture,
batch and schedule orchestration, dashboard review, and version impact
assessment. The previous name, `oss-vuln-digger`, overemphasized discovery and
did not describe verification and impact-assessment workflows well.

## Decision

Rename the project to `oss-vuln-lab`.

The primary Python package becomes `oss_vuln_lab`, the primary module entrypoint
becomes `python3 -m oss_vuln_lab`, and the primary console script becomes
`ovl`.

To avoid needless breakage during the pre-1.0 transition, keep compatibility
entrypoints for the old Python package name and `ovd` console script. New docs
and examples should use the new name.

## Consequences

- The project name better matches the broader lab/workbench scope.
- CLI documentation and examples move to `oss_vuln_lab` and `ovl`.
- Existing local users can continue using `python3 -m oss_vuln_digger` and
  `ovd` during the compatibility window.
- Schema identifiers and dashboard branding move to `oss-vuln-lab`.
- Default local run storage moves from `.ovd_runs` to `.ovl_runs`; scripts keep
  `OVD_RUNS_DIR` as a legacy fallback behind `OVL_RUNS_DIR`.

## Follow-up

- Update package imports, console scripts, docs, specs, schemas, and tests.
- Run the full test suite.
- Run the Review Agent gate before committing because this is an L-sized public
  interface change.
