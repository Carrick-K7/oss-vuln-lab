# 0003 Lightweight SDD Governance

- Status: accepted
- Date: 2026-05-09
- Amended by: `docs/decisions/0007-task-backlog-and-doc-refresh-gate.md`

## Context

`oss-vuln-lab` 是一个 AI-Native 的本地优先漏洞研究项目。主要开发工作会由 AI 执行或辅助执行，但项目本身涉及 PoC、验证命令、批量执行、运行证据和潜在未公开漏洞信息。仅靠 README、ROADMAP 或临时任务描述不足以约束 AI 在长期开发中的行为。

项目需要一套稳定、低认知负担、可演进的文档治理方式：

- 人类读者需要快速理解项目入口、能力和边界。
- AI 开发者需要明确知道实现前应该读取哪些契约。
- 安全敏感变更需要先写下原因、边界和后果。
- manifest、report、batch、schedule 等机器格式需要在稳定后可校验。
- 文档结构本身不应随着每个新功能反复改变。

## Decision

采用轻量级 Spec-Driven Development，简称轻量 SDD。不引入完整 OpenSpec、Spec Kit 或额外顶层规范目录。

固定文档职责如下：

- `README.md`: 项目入口、当前能力、常用命令和文档导航。
- `AGENTS.md`: AI 和开发者执行代码变更时必须遵守的门禁。
- `CONTRIBUTING.md`: 人类协作流程。
- `SECURITY.md`: 漏洞披露、敏感材料和仓库边界。
- `ROADMAP.md`: 长期方向，不作为任务列表。
- `docs/decisions/`: 已接受的高影响决策，回答“为什么”。
- `docs/specs/`: 当前系统契约，回答“必须满足什么”。
- `docs/schemas/`: 稳定机器格式的 JSON Schema，回答“如何校验”。

`TASKS.md` was later removed by `docs/decisions/0007-task-backlog-and-doc-refresh-gate.md`. 短期执行意图不再进入长期文档体系；当前规则以 `AGENTS.md` 为准。

核心 Spec 固定为：

- `docs/specs/0001-product-scope-and-terms.md`
- `docs/specs/0002-research-workflows.md`
- `docs/specs/0003-data-semantics.md`
- `docs/specs/0004-execution-safety.md`
- `docs/specs/0005-engine-contracts.md`

AI 执行开发时必须先分类变更规模：

- `S`: 文档修正、窄 bugfix、小测试、无接口变化的小重构。
- `M`: 新 validator、新漏洞族、重要 replay/corpus 工作流变化、新 CLI 子命令。
- `L`: schema/report/manifest 变化、pipeline 重构、validator status 语义变化、安全边界变化、预计超过一天的工作。

执行门禁：

- `S`: 可以直接实现，但最终回答必须说明验证方式。
- `M`: 先检查相关 Spec，必要时更新相关 Spec，再实现。
- `L`: 先写 Decision Record，再更新相关 Spec，然后拆分实现。

下列变化必须先更新 `docs/specs/`，再实现：

- CLI 行为或命令语义。
- scan、triage、repro、verify-known、corpus、replay、batch、schedule 工作流语义。
- finding、candidate、evidence、validation、report、run、batch、corpus 的含义。
- replay、corpus、batch、schedule manifest 行为。
- validator status 语义。
- PoC、fuzzing、host execution、Docker execution、文件写入、网络访问、artifact retention 等执行安全边界。
- adapter、vulnerability family、validator、LLM provider、future static/fuzz/binary engine 的契约。

下列变化必须先写新的 Decision Record：

- 持久化 schema 或兼容性规则变化。
- 安全敏感执行边界变化。
- validator status 含义变化。
- 插件、engine 或 adapter 策略变化。
- 文档治理方式变化。

## Consequences

正向结果：

- AI 不再只根据最近上下文实现功能，而是先读取稳定契约。
- 文档结构固定，功能演进只改变 Spec 内容、schema 或新的 Decision Record。
- README 保持入口职责，不承载完整系统契约。
- ROADMAP 保持长期方向，不退化为任务系统。
- Spec 和 schema 分工明确，避免 Markdown 和 JSON Schema 各自定义一套语义。

权衡：

- 中大型变更前会多一步文档更新。
- Spec 需要维护，否则会变成过期契约。
- 早期不要过度冻结 schema，只有已经用于互操作或持久化的格式才进入 `docs/schemas/`。

## Follow-up

- 新增核心 Spec。
- 新增当前稳定 manifest 的 JSON Schema。
- 更新 `README.md` 的文档模型说明。
- 更新 `AGENTS.md` 的 AI 执行门禁。
- 更新 `CONTRIBUTING.md`，让人类协作者与 AI 使用同一套门禁。
