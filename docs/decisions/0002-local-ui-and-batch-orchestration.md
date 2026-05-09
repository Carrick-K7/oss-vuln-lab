# 0002 Local UI and Batch Orchestration

## Status

Accepted

## Context

The roadmap now targets three adjacent releases:

- `1.0.0`: stable local research kernel
- `1.1.0`: local UI
- `1.2.0`: batch and scheduled local mining

The current repository already has a stable local artifact model built around per-run directories containing `run.json`, `report.json`, and `report.md`.

## Decision

Build the `1.1.0` and `1.2.0` layers on top of the existing local artifact model instead of introducing a separate service or database.

Concretely:

- `1.1.0` will use a static HTML dashboard plus an optional local HTTP server
- `1.2.0` will use JSON manifests for batch and schedule execution
- batch and schedule outputs will be stored under the local runs directory and will reference underlying run results instead of duplicating them

## Consequences

Positive:

- keeps the tool local-first
- avoids adding frontend build tooling or service dependencies
- makes UI and automation layers thin wrappers around the kernel
- keeps testing deterministic and file-oriented

Tradeoffs:

- the UI is intentionally simple and read-only
- scheduling is local process orchestration rather than a durable daemon
- batch metadata is file-backed instead of query-backed
