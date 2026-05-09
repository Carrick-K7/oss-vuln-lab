# OSS Vuln Digger

`oss-vuln-digger` is a local-first OSS vulnerability research tool. It scans source repositories and ELF binaries, generates candidate findings, synthesizes or replays PoCs, and records validation evidence. The current codebase already supports C/C++, Python, JavaScript, Java, Rust, and replay manifests for known CVEs.

The release trajectory is:

- `0.1.0`: local MVP baseline for engineering open source vulnerability research
- `1.0.0`: stable local research kernel
- `1.1.0`: hardened local UI built on top of the kernel
- `1.2.0`: hardened batch and scheduled local vulnerability mining

## Documentation Model

本项目采用轻量 SDD，文档按职责分层，避免 README、ROADMAP、Spec 和任务列表互相污染。

- `README.md`: 项目入口、当前能力、常用命令和文档导航
- `AGENTS.md`: AI 和开发者执行代码变更时必须遵守的门禁
- `CONTRIBUTING.md`: 人类协作流程
- `SECURITY.md`: 漏洞披露、敏感材料和仓库边界
- `ROADMAP.md`: 长期方向，不作为任务列表
- `TASKS.md`: 当前本地 backlog，保持短小
- `docs/decisions/`: 已接受的高影响决策，回答“为什么”
- `docs/specs/`: 当前系统契约，回答“必须满足什么”
- `docs/schemas/`: 稳定机器格式的 JSON Schema，回答“如何校验”
- `git commit`: 执行历史

核心原则和 AI 执行门禁见 [docs/decisions/0003-lightweight-sdd.md](./docs/decisions/0003-lightweight-sdd.md) 与 [AGENTS.md](./AGENTS.md)。开发流程见 [CONTRIBUTING.md](./CONTRIBUTING.md)。提交 replay samples 或漏洞细节前必须阅读 [SECURITY.md](./SECURITY.md)。

## Current Capabilities

- Project detection for C/C++, Python, JavaScript, Java, Rust, and ELF binaries
- Builtin vulnerability families for memory safety, boundary validation, command execution, path traversal, deserialization, SQL injection, SSRF, XXE, template injection, and binary risky-symbol surfacing
- Local heuristic analysis by default, plus OpenAI-compatible provider hooks
- Validator backends for Docker build prep, sanitizer runtime checks, host sanitizer runs, and direct runtime replay
- Local CVE corpus manifests and `replay` commands for known-PoC verification
- Static local dashboard generation and optional local HTTP serving with inline finding, evidence, corpus, and batch review
- Batch and scheduled local execution for scan and replay workloads with deduplication and regression comparison
- JSON and Markdown run reports under a per-run artifacts directory

## Repository Layout

- `src/oss_vuln_digger/`: package source
- `src/oss_vuln_digger/plugins/`: project adapters, vuln family plugins, validators, LLM providers
- `tests/`: unit and fixture-driven integration tests
- `scripts/`: helper scripts for fixture acquisition
- `docs/decisions/`: numbered Decision Records
- `docs/specs/`: current system contracts
- `docs/schemas/`: JSON Schemas for stable local manifests
- `config.example.toml`: default config example
- `config.host.example.toml`: host-side validator config example

## CLI

Primary commands:

```bash
python3 -m oss_vuln_digger scan /path/to/project
python3 -m oss_vuln_digger triage <run-id> <finding-id>
python3 -m oss_vuln_digger repro <run-id> <finding-id>
python3 -m oss_vuln_digger report <run-id>
python3 -m oss_vuln_digger verify-known /path/to/project \
  --title "Known crash replay" \
  --vuln-family memory_safety \
  --repro-command "./app @payload_path@" \
  --artifact-file ./poc.bin
```

Corpus and replay commands:

```bash
python3 -m oss_vuln_digger corpus list
python3 -m oss_vuln_digger corpus show CVE-2099-0001
python3 -m oss_vuln_digger replay cve /path/to/project CVE-2099-0001
python3 -m oss_vuln_digger replay manifest /path/to/project ./corpus/CVE-2099-0001.json
```

The installed console script is also available as:

```bash
ovd scan /path/to/project
```

Local UI commands:

```bash
python3 -m oss_vuln_digger ui build
python3 -m oss_vuln_digger ui serve --host 127.0.0.1 --port 8765
```

Batch and schedule commands:

```bash
python3 -m oss_vuln_digger batch run ./batch.json
python3 -m oss_vuln_digger batch list
python3 -m oss_vuln_digger batch show <batch-id>
python3 -m oss_vuln_digger schedule once ./schedule.json
python3 -m oss_vuln_digger schedule run ./schedule.json --iterations 1 --poll-seconds 60
python3 -m oss_vuln_digger schedule show ./schedule.json
```

## Configuration

Start from `config.example.toml`. The default provider is `local`, which uses deterministic heuristics and does not require network access.

```bash
python3 -m oss_vuln_digger scan /path/to/project \
  --config config.example.toml \
  --runs-dir .ovd_runs
```

For host-side validation without Docker:

```bash
python3 -m oss_vuln_digger repro <run-id> <finding-id> \
  --config config.host.example.toml
```

Key config fields:

- `app.runs_dir`: base directory for per-run output
- `app.corpus_dir`: directory containing local CVE replay manifests
- `app.enabled_validators`: enabled validator names
- `llm.provider`: `local`, `openai`, or `openai_compatible`

The default validator set avoids host/direct runtime replay. Enable `host_sanitizer_runtime` or `direct_runtime` only when you intentionally want local host execution of target commands or replay commands.

## Known PoC Replay

`verify-known` supports three artifact input modes:

- `--artifact-file` imports a local PoC file
- `--artifact-text` stores inline text as `payload.txt`
- `--artifact-base64` writes an exact binary artifact and requires `--artifact-name`

Supported placeholders in replay commands include:

- `@payload_path@`
- `@artifact_dir@`
- `@output_path@`
- `@build_root@`

Example:

```bash
python3 -m oss_vuln_digger verify-known /path/to/project \
  --title "Known stack overflow replay" \
  --vuln-family memory_safety \
  --repro-command "./app @payload_path@" \
  --artifact-text "AAAAAAAAAAAAAAAA"
```

## CVE Corpus Manifest Shape

`corpus` and `replay` use a local `corpus_dir` of JSON manifests. Each manifest contains CVE metadata plus a replay definition. Replay artifacts may be embedded inline or referenced by relative `file_path`.

Contract references:

- Semantics: [docs/specs/0003-data-semantics.md](./docs/specs/0003-data-semantics.md)
- Execution safety: [docs/specs/0004-execution-safety.md](./docs/specs/0004-execution-safety.md)
- Schema: [docs/schemas/cve-corpus-manifest.schema.json](./docs/schemas/cve-corpus-manifest.schema.json)

Local corpus rules:

- `replay.artifacts[*].name` must be a simple filename, not a path
- `replay.artifacts[*].file_path` must stay relative to the manifest directory
- malformed records fail fast in `corpus` and `replay` commands with a user-facing error

Example:

```json
{
  "cve_id": "CVE-2099-0001",
  "summary": "Demo replay",
  "project": "demo-app",
  "language": "python",
  "vuln_family": "command_execution",
  "references": ["https://example.invalid/CVE-2099-0001"],
  "replay": {
    "title": "Demo replay",
    "vuln_family": "command_execution",
    "repro_command": "python3 app.py @payload_path@",
    "candidate_file": "app.py",
    "function_or_sink": "__main__",
    "artifacts": [
      {
        "name": "payload.txt",
        "file_path": "payload.txt"
      }
    ]
  }
}
```

## Local Dashboard

`ui build` writes a static dashboard under `<runs_dir>/dashboard/index.html` by default. The dashboard summarizes:

- recorded runs and links to Markdown/JSON/state artifacts
- finding, validation, and evidence previews for each run
- local batch executions
- batch deduplication and regression comparison summaries
- local corpus records rendered from `corpus_dir`

`ui serve` serves the local runs directory over HTTP so the dashboard can browse the generated artifacts without introducing a separate backend.

## Batch Manifest Shape

`batch run` executes a JSON manifest of scan or replay jobs and stores a batch report under `<runs_dir>/batches/`.

Contract references:

- Workflow semantics: [docs/specs/0002-research-workflows.md](./docs/specs/0002-research-workflows.md)
- Data semantics: [docs/specs/0003-data-semantics.md](./docs/specs/0003-data-semantics.md)
- Schema: [docs/schemas/batch-manifest.schema.json](./docs/schemas/batch-manifest.schema.json)

Each batch stores:

- per-job run references
- finding summaries for operator review
- deduplication groups for repeated findings inside the batch
- regression comparison against the previous batch with the same name

Example:

```json
{
  "name": "nightly-kernel",
  "jobs": [
    {
      "name": "scan-demo",
      "mode": "scan",
      "target": "/path/to/project"
    },
    {
      "name": "replay-demo",
      "mode": "replay_cve",
      "target": "/path/to/project",
      "cve_id": "CVE-2099-0001"
    }
  ]
}
```

Supported job modes:

- `scan`
- `replay_cve`
- `replay_manifest`

## Schedule Manifest Shape

`schedule` evaluates a local polling manifest and only runs tasks that are due. State is stored under `<runs_dir>/schedules/`.

Contract references:

- Workflow semantics: [docs/specs/0002-research-workflows.md](./docs/specs/0002-research-workflows.md)
- Data semantics: [docs/specs/0003-data-semantics.md](./docs/specs/0003-data-semantics.md)
- Schema: [docs/schemas/schedule-manifest.schema.json](./docs/schemas/schedule-manifest.schema.json)

Example:

```json
{
  "name": "hourly-local",
  "tasks": [
    {
      "name": "scan-demo",
      "every_minutes": 60,
      "job": {
        "name": "scan-demo",
        "mode": "scan",
        "target": "/path/to/project"
      }
    }
  ]
}
```

Use `schedule once` for deterministic local execution or `schedule run` for the polling loop.

## Development

Run the test suite with:

```bash
python3 -m unittest -q
```

The project currently targets Python 3.12 and uses `setuptools` packaging.

## Fixtures

Fetch the official LibTIFF 4.3.0 release bundle with:

```bash
bash scripts/fetch_libtiff_fixture.sh
```

Fetch the FFmpeg 7.1.1 source bundle used for known-PoC replay with:

```bash
bash scripts/fetch_ffmpeg_fixture.sh
```
