# Roadmap

`oss-vuln-digger` is evolving toward a local-first OSS vulnerability research and verification platform. This file records the long-term direction only. Near-term execution lives in `TASKS.md`, and high-impact technical choices live in `docs/decisions/`.

The current `0.1.0` line is the local MVP baseline for engineering open source vulnerability research. The codebase already contains early UI, batch, and schedule capabilities, but the `1.x` labels below are maturity targets, not claims that the full stable platform is complete.

## `0.1.0` MVP Baseline

`0.1.0` means the project has a local minimum engineering loop for open source vulnerability research:

- scan local open source projects and produce candidate findings
- replay explicit known PoCs or local corpus records
- record run artifacts, reports, validation output, and evidence
- execute local batch and schedule jobs over scan/replay workflows
- inspect local artifacts through a read-oriented dashboard
- keep untrusted PoC, artifact, target, and replay execution safety boundaries explicit

## Final Shape

The intended end state is a multi-language vulnerability research tool with a stable local kernel, structured evidence, repeatable replay workflows, and a clear boundary between generated hypotheses and runtime-backed confirmations.

Target characteristics:

- Stable support for C/C++, Python, JavaScript, Java, and Rust
- Repeatable discovery workflows for common CVE-style bug classes
- Known-CVE and PoC replay workflows with structured evidence
- Machine-readable reports, replay manifests, and local corpus records
- Plugin-based extension points for project adapters, vulnerability families, validators, and LLM providers

## Release Trajectory

### `1.0.0` Local Research Kernel

- Ship a credible local-first research kernel with a stable CLI
- Keep the operator workflow centered on `scan`, `triage`, `repro`, `report`, `verify-known`, `corpus`, and `replay`
- Make replay and verification trustworthy:
  - multi-language adapters for C/C++, Python, JavaScript, Java, and Rust
  - structured evidence and validator semantics that mean the same thing across languages
  - replay manifests and local corpus records that are validated, portable, and safe to materialize
- Strengthen deterministic tests and fixtures so the core replay paths are reliable without network access
- Freeze the core report shape, replay manifest conventions, and `confirmed` semantics only after the local kernel behavior is credible

### `1.1.0` Local UI

- Add a local operator interface on top of the `1.0.0` kernel without changing the kernel contract
- Reuse the same run records, evidence items, and replay workflows as the CLI
- Support local inspection of findings, evidence, corpus records, and replay runs
- Keep the UI optional and local-first rather than introducing a heavy remote platform

### `1.2.0` Batch and Scheduled Mining

- Add first-class batch execution for scans and replay workloads
- Add scheduled local execution for recurring mining and replay tasks
- Store batch results in a way that supports regression comparisons, deduplication, and operator review
- Keep scheduling and automation local-first by default, with optional future queue or worker layers only after the batch model is proven

## Current Focus

- Close the largest `1.0.0` trust gaps in replay, corpus handling, and validator semantics
- Deepen deterministic replay coverage for Python, JavaScript, Java, and Rust paths
- Improve operator-facing diagnostics before freezing core contracts

## Current Non-Goals

- Heavy SaaS platform work
- Fully autonomous exploit generation
- Deep binary reverse engineering as a first-class workflow
- Large remote dataset ingestion in the default local developer flow
