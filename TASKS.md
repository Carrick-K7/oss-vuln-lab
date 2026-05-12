# Tasks

This file is the local execution backlog. Keep it short. Move completed work into Git history rather than keeping a long done list here.

`TASKS.md` is not a source of truth. Product facts belong in `README.md`; behavior and data contracts belong in `docs/specs/`; high-impact choices belong in `docs/decisions/`; execution history belongs in git commits.

Keep this file only for active local backlog items that are likely to be worked soon. Delete stale or completed items instead of archiving them here.

## Now

- Keep README, Specs, schemas, and tests aligned when behavior changes
- Improve corpus/advisory version-range manifest semantics without adding a database

## Next

- Harden multi-language validation semantics so replay results mean the same thing across C/C++, Python, JavaScript, Java, and Rust
- Broaden validator coverage for unsupported and failure states, especially around explicit host and Docker execution paths
- Improve candidate extraction quality beyond sink matching, especially for non-C/C++ languages
- Add historical trend views on top of scheduled batch results
- Expand local corpus tooling around advisory import and fixture curation

## Later

- Add optional worker or queued execution only after the local batch model is stable
- Explore remote sync or export workflows without giving up the local-first source of truth
