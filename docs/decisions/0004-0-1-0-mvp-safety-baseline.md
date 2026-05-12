# 0004 0.1.0 MVP Safety Baseline

- Status: accepted
- Date: 2026-05-09

## Context

`0.1.0` 需要代表“开源软件漏洞挖掘的本地最小工程闭环”，而不是单纯的文档治理基线。这个版本至少要能扫描开源项目、验证已知 PoC、记录证据、批量执行、本地审查，并且在处理不可信目标、PoC、artifact 和 replay command 时有明确安全边界。

当前代码已经具备 scan、replay、corpus、batch、schedule、dashboard 和报告骨架，但发布前必须避免一个关键误导：默认执行路径不能让不可信 replay command 在 host 上无提示执行。

## Decision

将 `0.1.0` 定义为：

`开源软件漏洞挖掘的本地最小工程闭环`

`0.1.0` 必须满足：

- 可以扫描本地开源项目并生成 candidate findings。
- 可以使用本地 corpus 或显式 PoC replay 验证已知漏洞。
- 可以沉淀 run、report、evidence、artifact 和 batch 结果。
- 可以通过本地 dashboard 审查 runs、findings、evidence、corpus 和 batch。
- batch 和 schedule 必须复用同一套 pipeline 安全边界。
- 默认配置不得启用 host/direct runtime replay。
- CLI 和 manifest 输入的 artifact 名称必须限制为 simple filename。
- Docker validator 默认使用无网络运行策略，除非未来 Decision Record 明确改变。

## Consequences

正向结果：

- `0.1.0` 的 tag 语义从“文档已整理”升级为“本地漏洞研究 MVP 已具备最低可信闭环”。
- AI 后续开发有明确 tag gate，不会把长期目标误当成当前已满足能力。
- 不可信 PoC 和 replay command 的默认执行风险下降。

权衡：

- 默认配置下，部分 replay 只能得到 hypothesis、unsupported 或 failed，不能自动 host-confirm。
- 需要用户显式启用 host/direct validator 才能获得更强运行时确认。
- Docker 无网络策略可能让依赖联网构建的项目无法默认验证，需要未来单独设计 opt-in 网络策略。

## Follow-up

- 更新核心 Spec 的 `0.1.0 MVP Acceptance`。
- 更新默认 validator 配置。
- 增加 artifact name 安全校验。
- 为 triage mutation 写入显式记录。
- 更新 README 和测试。
