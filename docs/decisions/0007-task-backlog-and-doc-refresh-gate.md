# 0007 删除 TASKS Backlog 并保留文档刷新门禁

- Status: accepted
- Date: 2026-05-12

## Context

`TASKS.md` 原本用于记录短期本地 backlog，但活跃任务列表很容易在代码、commit 和 tag 推进后被遗忘。如果把 `TASKS.md` 当成 source of truth，它会变成过期文档并误导 AI 主导开发。

进一步审视后，`TASKS.md` 没有不可替代职责。它既不能承载稳定事实，也不适合作为长期 backlog；短期执行意图可以由当前工作上下文、计划工具和 git commit 承接。

项目需要更强的 SSOT 边界：

- 稳定事实属于 `README.md`、`docs/specs/`、`docs/decisions/`、`docs/schemas/` 和 git history。
- 短期执行意图保留在当前工作上下文中，不进入长期文档体系。
- 已完成工作属于 git history，而不是长期任务归档。

项目还需要在代码变更后执行明确的文档影响检查，因为代码可能改变 CLI 行为、安全边界、schema、示例或当前能力，但这些变化不一定会自动暴露为文档 diff。

## Decision

删除 `TASKS.md`。

规则：

- 不再维护独立 backlog 文件。
- 不要新增 `TASKS.md` 或等价 backlog 文件作为 SSOT。
- 短期执行计划可以存在于当前对话、计划工具或 commit message 中。
- 已完成工作使用 git history 追踪。
- 产品事实、行为、兼容性、架构、发布历史和安全边界仍分别属于 README、Spec、Decision Record、schema 和 git history。

任何代码或行为变更后，实现者必须在结束前执行文档影响检查：

- CLI、config、当前能力发生变化：检查 `README.md`。
- workflow、status、evidence、report、run、corpus、batch 或 schedule 语义发生变化：检查 `docs/specs/`。
- manifest 或机器可校验格式发生变化：检查 `docs/schemas/` 和相关示例。
- security、PoC execution、host execution、Docker、network、artifact 或 sensitive-data 边界发生变化：检查 `docs/specs/0004-execution-safety.md` 和 `SECURITY.md`。
- 长期方向发生变化：检查 `ROADMAP.md`。
- 高影响或兼容性敏感决策发生变化：检查 `docs/decisions/`。

最终回复必须说明更新了哪些文档；如果没有文档需要更新，也必须明确说明已执行文档影响检查且无需更新。

## Consequences

- Positive: `TASKS.md` 不会意外变成 SSOT，因为该文件已删除。
- Positive: AI 主导代码变更具备可重复的文档新鲜度检查。
- Positive: 已完成工作进入 git history，而不是堆积在过期 backlog 中。
- Tradeoff: 最终回复需要额外说明文档影响。
- Tradeoff: 本仓库不再提供独立 backlog 文档；长期方向依赖 `ROADMAP.md`，短期执行依赖当前工作上下文和 git history。

## Follow-up

- 在 `AGENTS.md` 中加入文档影响检查。
- 在 `CONTRIBUTING.md` 中同步人工贡献者的文档检查要求。
- 删除 `TASKS.md` 并清理当前文档中的引用。
