# 0006 暂不引入数据库存储

- Status: accepted
- Date: 2026-05-12

## Context

项目曾考虑为漏洞、PoC 和受影响版本范围元数据引入本地 SQLite 数据库。

当前架构已经有三个清晰的本地数据来源：

- `corpus/` 存放人工整理的 CVE/advisory replay manifest 和可复用 PoC artifact。
- `.ovd_runs/<run-id>/` 存放执行证据、报告和单次运行 artifact。
- `docs/schemas/` 存放机器可校验的 manifest 形状。

在 advisory 规模、查询压力或外部 feed 同步语义尚未成型前引入数据库，会过早制造第二个元数据来源。

SQLite 本身不违反 local-first。真正的问题不是“是否本地”，而是过早引入持久化复杂度和 source-of-truth 歧义。

## Decision

当前架构不引入数据库存储。

项目继续坚持 manifest-first 和 artifact-first：

- Advisory、CVE、alias、affected version、fixed version 和 replay 元数据继续保存在本地 JSON manifest 中。
- PoC payload 和 replay artifact 继续作为文件保存在 `corpus/` 或单次运行 artifact 目录中。
- 运行证据继续保存在 `run.json` 和相关 run artifact 中。
- 对当前预期数据量，JSON 扫描和 manifest 加载已经足够。

只有至少满足以下条件之一时，才重新讨论数据库：

- 本地 advisory corpus 增长到足以让 JSON manifest 扫描成为可观测瓶颈。
- UI 需要对数千条 advisory 记录做复杂筛选、分页或聚合。
- batch 或 schedule 工作流反复需要昂贵的 advisory/version/run 关联查询。
- NVD、CNVD、OSV、GHSA 等来源需要持久化增量同步状态。
- 来源冲突处理、provenance 和版本规范化语义已经先被文档化。

如果未来引入数据库，它默认只能是本地索引或缓存层。它不得替代 `corpus/` 作为 curated replay source，也不得替代 `run.json` 作为执行证据的 source of truth。

## Consequences

- Positive: 当前 local-first 工作流保持简单、可检查。
- Positive: PoC 和 evidence 的归属保持清晰。
- Positive: 未来 advisory/version 语义可以先在 JSON 中演进，再决定是否冻结为数据库迁移模型。
- Tradeoff: 在重新讨论数据库前，大型 advisory 集合可能只能接受较慢的文件扫描。
- Tradeoff: 丰富查询能力应保守实现，或推迟到数据量足够证明其必要性之后。

## Follow-up

- 在引入数据库前，继续完善 corpus manifest 语义。
- 下一阶段 advisory/version-range 工作优先使用基于文件的查询 helper，而不是数据库。
- 添加 SQLite、PostgreSQL 或任何其他持久化数据库层之前，必须先新增 Decision Record。
