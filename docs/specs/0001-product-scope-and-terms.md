# Spec: Product Scope and Terms

- Status: accepted
- Stability: stable
- Last reviewed: 2026-05-20
- Applies to: CLI, pipeline, validators, dashboard, batch, schedule, impact, docs
- Supersedes: none

## Purpose

本 Spec 定义 `oss-vuln-lab` 的产品边界和核心术语。它约束所有后续功能，避免 AI 或开发者把“漏洞挖掘”“CVE 验证”“PoC 复现”“新漏洞发现”等概念混用。

## Scope

本项目是本地优先的开源软件漏洞研究和验证工具。它面向授权环境中的开源软件源码仓库、构建产物和本地 replay/fuzz/scan 工作流。

项目目标是工程化支持：

- 对已知漏洞或已知 PoC 进行本地验证。
- 对一个 advisory 的多个 Git 版本生成本地影响评估证据矩阵。
- 对开源软件进行候选漏洞挖掘。
- 记录结构化证据、复现命令、artifact 和 validation 结果。
- 通过 workbench、batch、schedule 支持人工审查和批量执行。

## Non-Goals

本项目不以这些能力为目标：

- 未授权扫描真实线上目标。
- 自动化入侵、横向移动、持久化、凭据窃取或武器化利用链生成。
- 把所有 crash 自动声明为安全漏洞。
- 把未分配编号的漏洞候选称为 CVE。
- 默认采集大型远程漏洞数据集。
- 默认成为 SaaS、多租户平台或远程任务执行系统。
- 深度二进制逆向作为第一优先级工作流。

## Terms

- 开源软件漏洞挖掘: 在授权、本地、可复现环境中，通过静态分析、启发式候选提取、PoC replay、validator、batch、未来 fuzzing 等方式发现或验证潜在安全问题。
- 已知漏洞验证: 使用本地 corpus、CVE/GHSA 记录或已知 PoC，在指定目标版本上验证漏洞是否可复现。
- 新漏洞候选: 尚未公开编号、尚未完成披露流程、但具有代码位置、触发条件和证据的潜在安全问题。
- Variant: 与已知漏洞共享相似 bug class、root cause、sink、trigger shape 或 patch pattern 的新候选。Variant 不是 CVE 编号。
- Candidate: 静态或启发式分析产生的候选点。Candidate 只代表值得审查，不代表漏洞成立。
- Finding: 系统记录的研究结果，可以是 candidate、manual review、PoC synthesized 或 confirmed。
- Confirmed: 至少一个 validator 在受控环境中观察到与漏洞假设一致的运行时证据。Confirmed 不等于可利用，不等于 CVE，不等于影响所有版本。
- Evidence: 支持判断的命令输出、sanitizer 输出、traceback、artifact、日志或 metadata。
- PoC: 用于触发或验证候选的最小输入、命令或 artifact。PoC 默认视为不可信输入。
- Workbench: 本地人工审查界面或 CLI 工作流，用于查看 runs、findings、evidence、corpus、batch 和 replay 结果。
- Version impact assessment: 针对一个 advisory 和多个 Git ref/tag 的本地证据矩阵。它可以引用 replay、source signatures 和 public intelligence，但不是 vendor advisory，不改变单个 run 的 FindingStatus。

## Requirements

- The project MUST remain local-first by default.
- The project MUST separate hypotheses from runtime-backed confirmations.
- The project MUST preserve evidence needed to review a finding.
- The project MUST treat imported PoCs, replay artifacts, target repositories, and fuzz corpora as untrusted input.
- The project MUST NOT label an undisclosed candidate as a CVE.
- The project SHOULD prefer source-level workflows before binary-only workflows.
- The project SHOULD support both interactive workbench usage and batch execution through the same local research kernel.
- The project MAY integrate external data sources only when sensitive data handling and local persistence semantics are explicit.
- Version impact assessment MUST keep version-range conclusions in impact reports and MUST NOT rewrite single-target run artifacts into broader claims.

## 0.1.0 MVP Acceptance

`0.1.0` MUST represent a local engineering baseline for open source vulnerability research, not a mature autonomous vulnerability discovery platform.

Before tagging `0.1.0`:

- The project MUST scan a local open source project and produce candidate findings.
- The project MUST replay an explicit known PoC or local corpus record against a local target.
- The project MUST write reviewable run artifacts, reports and evidence.
- The project MUST support local batch execution over scan and replay jobs.
- The project MUST build a local read-oriented dashboard over recorded artifacts.
- The project MUST NOT claim automatic new CVE discovery.
- The project MUST NOT include mature fuzzing as a release requirement.

## Scenarios

```text
Given a scan finds a dangerous sink in source code
When no validator confirms runtime behavior
Then the result remains a candidate or hypothesis, not a confirmed vulnerability
```

```text
Given a known CVE manifest and local target version
When replay produces validator evidence matching the expected failure mode
Then the finding may be marked as confirmed_known_poc
```

```text
Given a crash from future fuzzing
When the crash has not been minimized, deduplicated, and mapped to a security-relevant root cause
Then the system must not call it a confirmed vulnerability
```

## Compatibility

Existing workflow commands, run artifacts, local dashboard behavior, corpus manifests, batch manifests, and schedule manifests remain valid unless a future Decision Record explicitly changes compatibility. Decision Records 0009 and 0010 make `oss_vuln_lab` and `ovl` the only supported project entrypoints before the first release tag.

## Security

All vulnerability details and PoCs are governed by `SECURITY.md` and `docs/specs/0004-execution-safety.md`.

## Verification

Implementations must preserve terminology in CLI output, report fields, dashboard labels, and documentation. Tests that assert status values or result semantics must use these definitions.

## Open Questions

None.
