# go-siem-detection-engine-go

纯本地的日志检测与告警关联引擎：读取本地规则文件与日志文件即可完成
完整验证，不依赖任何外部服务。

## 快速复现

```bash
# 端到端跑一遍示例规则 + 示例日志
go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl \
    -lateness 10m -dedup 10m

# 跑全部测试（含竞态检测）
go test -race ./...

# 关键路径测试会打印输入事件、命中规则与判定依据
go test -v ./internal/engine/ ./internal/alert/ ./internal/rules/
```

## 规则格式

规则文件为 JSON，顶层 `rules` 数组，每条规则：

```json
{
  "id": "R-BRUTE-FORCE",
  "version": 1,
  "description": "same source reports 3+ login failures within 5m",
  "severity": "high",
  "window": "5m",
  "threshold": 3,
  "group_by": "source",
  "conditions": [
    {"field": "action", "op": "eq", "value": "login_failed"},
    {"field": "amount", "op": "gt", "value": "10000"}
  ]
}
```

- `window`：Go duration 字符串（`30s`、`5m`、`1h`）。
- `threshold`：窗口内去重事件数达到该值即命中。
- `group_by`：分组计数的字段，缺省按 `source` 分组。
- `conditions[].op`：`eq` / `neq` / `contains` / `gt` / `lt`；
  `gt`、`lt` 的 `value` 必须是数字。
- 条件字段可引用内建字段 `id` / `source` / `timestamp`，或事件
  `fields` 表中的任意键。

### 规则校验与拒绝原因

不合法的规则不会被悄悄跳过，`rules.LoadFile` 返回的
`LoadResult.Rejections` 会逐条列出，原因互相可区分：

| RejectReason | 含义 |
|---|---|
| `version_too_new` | 规则版本高于引擎支持的版本（当前支持 `1`） |
| `invalid_condition` | 未知操作符、数值条件值不是数字、窗口时长无法解析 |
| `missing_field` | 必填字段缺失：`id` 为空/重复、`window` 为空、`threshold <= 0`、`conditions` 为空 |

**重新加载的隔离性**：`engine.NewCorrelator` 在构造时拷贝规则切片，
之后修改/重新加载规则文件不会改变已有关联器对事件的判定；要使用新
规则需显式创建新的 Correlator（有测试
`TestReloadDoesNotAffectExistingCorrelator` 保证）。

## 日志格式

JSON Lines，每行一条事件：

```json
{"id":"e1","timestamp":"2026-10-01T10:00:00Z","source":"web-1","fields":{"action":"login_failed","user":"alice"}}
```

## 时间窗口与关联语义

引擎采用水位线（watermark）语义，结论与事件到达顺序无关：

- **去重**：事件按 `id` 全局去重，同一事件重复到达只计一次
  （计入 `Stats.Duplicates`）。
- **水位线**：`watermark = 已见最大事件时间 - lateness`（CLI `-lateness`）。
- **迟到事件**：事件时间 `<= watermark` 的事件被丢弃并计入
  `Stats.LateDropped`，不参与任何判定。
- **窗口**：以事件时间 `t` 为右端，统计 `(t-window, t]` 内的去重事件数。
- **闭合才产出**：只有当 `t <= watermark`（窗口闭合，不可能再有属于
  该窗口的事件到达）时才产出 Match，因此乱序与按序输入得到相同的
  命中集合（测试 `TestOutOfOrderEqualsInOrder` 用 20 种随机乱序验证）。
- **Flush**：输入结束时调用 `Flush()`（CLI 自动调用），把所有未闭合
  窗口视为闭合并完成评估。

## 告警去重与生命周期

- **去重键**：`(rule_id, group_key)`。
- **滑动窗口合并**：同一去重键在 `-dedup` 窗口内（自上次命中起算）
  再次命中时不新建告警，而是合并进已有告警：`Hits+1`、
  `Suppressed+1`，并在 `Reason` 中说明被抑制的原因。
- **生命周期**：`firing` → 超过窗口未再命中时 `Expire()` 将其转为
  `resolved` 并记录原因。
- **并发安全**：`Manager` 与 `Correlator` 全部方法加锁，多来源并发
  写入不计丢、不竞态（`TestConcurrentRecordNoRaceNoLoss` 在
  `-race` 下验证 8×500 次并发命中合并为一条 hits=4000 的告警）。

## 目录结构

```
cmd/siem/          本地验证入口（规则文件 + 日志文件 -> 命中与告警）
internal/rules/    规则加载、校验、归一化
internal/engine/   水位线窗口关联、去重、迟到处理
internal/alert/    告警去重与生命周期
rules/rules.json   示例规则（含 3 条会被拒绝的畸形规则）
data/events.jsonl  示例日志（含重复与迟到事件）
```
