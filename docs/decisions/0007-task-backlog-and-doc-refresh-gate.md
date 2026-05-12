# 0007 TASKS Backlog and Documentation Refresh Gate

- Status: accepted
- Date: 2026-05-12

## Context

`TASKS.md` 原本用于记录短期本地 backlog，但活跃任务列表很容易在代码、commit 和 tag 推进后被遗忘。如果把 `TASKS.md` 当成 source of truth，它会变成过期文档并误导 AI 主导开发。

项目需要更强的 SSOT 边界：

- 稳定事实属于 `README.md`、`docs/specs/`、`docs/decisions/`、`docs/schemas/` 和 git history。
- 短期执行意图可以放在 `TASKS.md`。
- 已完成工作属于 git history，而不是长期任务归档。

项目还需要在代码变更后执行明确的文档影响检查，因为代码可能改变 CLI 行为、安全边界、schema、示例或当前能力，但这些变化不一定会自动暴露为文档 diff。

## Decision

`TASKS.md` 不是 source of truth。它只是可选的、短生命周期的本地活跃工作队列。

规则：

- 不要用 `TASKS.md` 定义产品事实、行为、兼容性、架构、发布历史或安全边界。
- 不要在 `TASKS.md` 保留已完成工作；执行历史使用 git history。
- 不要把过期的 `TASKS.md` 条目视为高于代码、Spec、Decision Record、README 或 schema 的权威。
- 只有活跃本地 backlog 变化时才更新 `TASKS.md`。
- 如果没有需要跟踪的活跃本地 backlog，`TASKS.md` 可以保持极简。

任何代码或行为变更后，实现者必须在结束前执行文档影响检查：

- CLI、config、当前能力发生变化：检查 `README.md`。
- workflow、status、evidence、report、run、corpus、batch 或 schedule 语义发生变化：检查 `docs/specs/`。
- manifest 或机器可校验格式发生变化：检查 `docs/schemas/` 和相关示例。
- security、PoC execution、host execution、Docker、network、artifact 或 sensitive-data 边界发生变化：检查 `docs/specs/0004-execution-safety.md` 和 `SECURITY.md`。
- 长期方向发生变化：检查 `ROADMAP.md`。
- 活跃本地 backlog 发生变化：检查 `TASKS.md`。
- 高影响或兼容性敏感决策发生变化：检查 `docs/decisions/`。

最终回复必须说明更新了哪些文档；如果没有文档需要更新，也必须明确说明已执行文档影响检查且无需更新。

## Consequences

- Positive: `TASKS.md` 不会意外变成 SSOT。
- Positive: AI 主导代码变更具备可重复的文档新鲜度检查。
- Positive: 已完成工作进入 git history，而不是堆积在过期 backlog 中。
- Tradeoff: 最终回复需要额外说明文档影响。
- Tradeoff: backlog 跟踪会刻意保持轻量，对长期项目管理的承载能力较弱。

## Follow-up

- 在 `AGENTS.md` 中加入文档影响检查。
- 在 `CONTRIBUTING.md` 中同步人工贡献者的文档检查要求。
- 简化 `TASKS.md`，使其只反映当前工作，而不是历史发布任务。
