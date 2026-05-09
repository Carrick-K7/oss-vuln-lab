# Spec: Title

- Status: draft | accepted | superseded
- Stability: experimental | evolving | stable
- Last reviewed: YYYY-MM-DD
- Applies to: CLI | pipeline | validators | dashboard | batch | schedule | docs
- Supersedes: none | path/to/spec.md

## Purpose

说明这份 Spec 约束什么，为什么需要独立存在。

## Scope

本 Spec 覆盖的行为、数据、边界或接口。

## Non-Goals

本 Spec 明确不覆盖的内容，避免被误读为隐含承诺。

## Terms

定义会影响实现和判断的术语。术语必须足够精确，不能只写产品宣传语。

## Requirements

使用 `MUST`、`SHOULD`、`MAY` 表达约束强度：

- `MUST`: 实现必须满足，违反即为 bug 或设计违约。
- `SHOULD`: 默认应满足，偏离时需要在 Decision Record 或实现说明中解释。
- `MAY`: 允许但不要求。

## Scenarios

用 Given/When/Then 描述需要可验证的关键场景。

```text
Given ...
When ...
Then ...
```

## Compatibility

说明如何处理已有 CLI、manifest、report、run artifact、batch artifact 或用户数据。

## Security

说明本 Spec 涉及的安全边界和敏感材料处理规则。若无安全影响，写明“无额外安全影响”。

## Verification

说明实现者如何证明代码满足本 Spec。可以是测试、CLI smoke、fixture、schema validation 或人工检查。

## Open Questions

列出尚未决定的问题。`accepted` 状态的 Spec 不应长期保留会阻塞实现的问题。
