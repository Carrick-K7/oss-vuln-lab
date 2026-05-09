# Security Policy

`oss-vuln-digger` is a vulnerability research project. Treat vulnerability details, replay inputs, and target information with care.

## Reporting

If you discover a vulnerability in the tool itself, do not open a public issue with exploit details. Report it privately to the maintainer through an out-of-band channel first.

If this repository is later mirrored to GitHub, the same rule applies: do not use public issues for undisclosed vulnerability details.

## What Must Stay Out of the Repository

Do not commit:

- undisclosed third-party vulnerabilities
- sensitive or weaponized PoCs that are not meant to be public
- customer, target, or organization-specific attack details
- credentials, API keys, tokens, or private datasets
- large downloaded vulnerability feeds or local run artifacts

## What Can Be Committed

The repository is intended to store:

- deterministic demo fixtures
- sanitized replay examples
- de-identified manifests
- code, tests, and docs needed to evolve the engine itself

When in doubt, prefer abstraction and sanitization over realism.

## Local Research Workflow

For sensitive investigations:

- keep raw notes and sensitive PoCs outside this repository
- only upstream generalized lessons, redacted fixtures, and engine improvements
- avoid naming live targets or unpublished CVEs in committed files

## Supported Versions

There is no formal long-term support matrix yet. Treat the current default branch as the supported line for engine changes.
