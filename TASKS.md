# Tasks

This file is the local execution backlog. Keep it short. Move completed work into Git history rather than keeping a long done list here.

The current release focus is the `0.1.0` MVP baseline for engineering open source vulnerability research. Keep this file short; long-term direction belongs in `ROADMAP.md`, and contract changes belong in `docs/specs/`.

## Now

- Finish `0.1.0` release validation and tag after the safety/spec/code baseline is verified
- Keep default execution safe for untrusted open source targets and PoCs
- Keep README, Specs, and tests aligned with the `0.1.0` MVP definition

## Next

- Harden multi-language validation semantics so replay results mean the same thing across C/C++, Python, JavaScript, Java, and Rust
- Broaden validator coverage for unsupported and failure states, especially around explicit host and Docker execution paths
- Improve candidate extraction quality beyond sink matching, especially for non-C/C++ languages
- Add historical trend views on top of scheduled batch results
- Expand local corpus tooling around advisory import and fixture curation

## Later

- Add optional worker or queued execution only after the local batch model is stable
- Explore remote sync or export workflows without giving up the local-first source of truth

## Roadmap Breakdown

### `1.0.0` Local Research Kernel

- Verify that the current CLI surface is documented, tested, and intentionally supported
- Fill the largest trust and coverage gaps in multi-language scanning and replay
- Keep local workflow and sensitive-vulnerability handling explicit
- Freeze only the contracts that the kernel can already uphold reliably

### `1.1.0` Local UI

- Reuse the stable `1.0.0` kernel rather than fork logic into a separate frontend
- Surface findings, evidence, runs, and corpus records locally
- Keep the UI optional and backwards-compatible with the CLI

### `1.2.0` Batch and Scheduling

- Add batch scan and replay execution
- Add scheduled local mining and validation runs
- Add regression execution, deduplication, and cross-run evidence comparison
