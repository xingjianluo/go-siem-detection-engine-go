# 本地日志检测与告警关联引擎

一个零外部依赖、完全在本地运行的 SIEM 风格检测引擎：从本地 JSON 规则文件加载检测规则，
读取本地 JSON Lines 日志事件，做**按时间窗口的有状态关联检测**，并对命中做
**滑动窗口告警去重与生命周期管理**。适合离线复盘、CI 中验证检测规则以及作为教学实现。

## 快速开始

```bash
# 用内置示例一键验证（批量模式：先按事件时间排序，乱序与按序结论一致）
go run ./cmd/siem -rules examples/rules.json -events examples/events.jsonl

# 流式模式：严格按文件到达顺序处理，靠 watermark 决定窗口关闭与迟到丢弃
go run ./cmd/siem -stream -rules examples/rules.json -events examples/events.jsonl \
  -allowed-lateness 10s -dedup-window 5m

# 全部单元测试，带竞态检测
go test -race -count=1 ./...
```

示例 `examples/rules.json` 里故意混入了 3 条坏规则（版本过新、正则非法、字段缺失），
`examples/events.jsonl` 里故意混入了重复事件与迟到事件，启动后可直接看到
互相区分的拒绝原因、`DUPLICATE(ignored)` 与 `LATE(dropped)` 判定。

## 规则文件格式

一个 JSON 文档，顶层是 `rules` 数组，每条规则独立校验：合法的被归一进快照，
非法的被记录为一条**带拒绝原因的拒绝记录**，不会被悄悄跳过：

```json
{
  "rules": [
    {
      "version": 2,
      "id": "failed-ssh",
      "name": "Failed SSH logins burst",
      "description": "可选描述",
      "severity": "high",
      "match": {"field": "message", "op": "contains", "value": "Failed password"},
      "window": "1m",
      "threshold": 3,
      "dedup_window": "5m"
    }
  ]
}
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `version` | 是 | 规则定义格式版本。当前支持 `1`、`2`；其它值拒绝。 |
| `id` | 是 | 规则唯一标识；同一文档内重复 ID 拒绝。 |
| `name` | 是 | 告警标题。 |
| `description` | 否 | 描述。 |
| `severity` | 否 | `info`/`low`/`medium`/`high`/`critical`，默认 `medium`；非法值拒绝。 |
| `match` | 是 | 匹配条件对象。 |
| `window` | 否 | 滚动关联窗口，Go duration 字符串（`"30s"`、`"5m"`），默认 `0s`。 |
| `threshold` | 否 | 窗口内命中事件数阈值，默认 1；`threshold>1` 时 `window` 必须非 0。 |
| `dedup_window` | 否 | 告警滑动去重窗口，默认取引擎级 `-dedup-window`（5m）。 |

`match` 字段：

- `field`：事件字段名。内置名 `id`/`source`/`message`/`ts` 取事件顶层字段，
  其它名字取 `events.fields[name]`。
- `op` 与 `value`：

| op | 语义 | value 要求 |
|---|---|---|
| `eq` / `ne` | 相等/不等（JSON 数字按数值比较） | 任意非 null |
| `contains` / `prefix` / `suffix` | 字符串包含/前缀/后缀 | 字符串 |
| `regex` | RE2 正则匹配 | 字符串，且必须能编译 |
| `gt` / `gte` / `lt` / `lte` | 数值大小比较（数字字符串也可比较） | 数字 |
| `exists` | 字段存在即为真 | 无 |

### 拒绝原因（互相可区分）

加载结果 `Snapshot.Rejections()` 中每条记录带有 `Reason`：

- `version_unsupported`：版本号超出支持范围（如 99）
- `malformed_entry`：单条 JSON 结构错误（字段类型错、severity 非法等）
- `missing_field`：缺少必填字段（version/id/name/match、field、op）
- `invalid_condition`：未知操作符、操作符与值类型不匹配、正则编译失败
- `invalid_window`：window/dedup_window 非法或为负、threshold<1、阈值>1 但 window=0
- `duplicate_rule_id`：同一文档内规则 ID 重复

注意区分：**顶层文档本身无法解析**（截断、没有 `rules` 数组）属于加载错误；
文档结构正常但**单条**规则非法，属于拒绝记录，其余规则照常加载。

## 事件文件格式

JSON Lines，每行一个事件：

```json
{"id":"e1","source":"auth","ts":"2026-10-01T10:00:00Z",
 "message":"Failed password for root","fields":{"src_ip":"10.0.0.1","bytes_out":120}}
```

`id` 是事件全局身份，用于去重；`ts` 为 RFC3339 事件时间。

## 时间窗口、迟到与去重语义

### 1. 事件时间 vs 处理时间

窗口归属只看**事件自带时间戳（event time）**；API 的 `now` 参数是
**处理时间（processing time）**，只影响告警去重与生命周期，不影响窗口判定。
因此输入怎么乱序、何时到达，结论只由事件时间决定。

### 2. 滚动窗口（tumbling window）

规则窗口 `W` 下，事件时间 `t` 归入半开区间
`[floor(t/W)*W, floor(t/W)*W + W)`，按 epoch 对齐，与到达顺序无关。
窗口内累计命中事件数，达到 `threshold` 时，**每个窗口恰好产出一条 Finding**，
携带窗口边界、命中次数与全部事件 ID（有序去重）。`window=0` 为即时规则，
命中当下立即产出 Finding。

### 3. Watermark 与迟到事件（流式模式）

`watermark = 已观察到的最大事件时间 − AllowedLateness`。

- watermark 越过某窗口结束点时，该窗口**终结且只终结一次**（达标则产出 Finding）。
- 时间戳早于 watermark 的事件判定为**迟到**：标记 `Late=true / LateDropped=true`
  并丢弃，绝不回改已终结窗口。这是任意到达顺序下唯一稳定的选择。
- 迟到事件的 ID 仍登记去重；它再次到达时是 `DUPLICATE`，不会被当成迟到重新接收。
- `-allowed-lateness`（默认 10s）越大，越能容忍乱序与延迟；`0s` 表示严格按序。

### 4. 乱序/按序结论一致（批量模式）

`IngestBatch` / CLI 默认模式先把事件按 `(时间戳, 事件ID)` **稳定排序**再处理，
末尾 flush 全部窗口。因此同批事件无论按时间正序、倒序还是洗牌喂入，
最终 Findings 与 Alerts 完全一致（见 `TestOrderIndependence`）。
流式模式下，只要事件乱序幅度不超过 allowed-lateness，结论同样一致；
超出容忍范围的迟到事件按上节明确丢弃。

### 5. 事件去重

以 `Event.ID` 为身份全局去重：同一 ID 无论重复多少次、出现在什么位置，
只在首次被接受时计入窗口，后续一律 `Duplicate=true` 且计数为零。

### 6. 告警去重（滑动窗口）与生命周期

每条规则维护至多一条活动告警（Key 为 `rule:<id>`）：

- 首次命中：创建告警，`count` = 窗口内命中数。
- 在 `lastSeen + dedup_window` 内再次命中：**不新增告警**，而是合并进同一条：
  `count` 累加、`lastSeen` 前移、去重截止时间随之**滑动**，告警上记录
  `suppressed=dedup_window`，`AlertManager.History()` 中留下可审计的抑制原因。
- 静默时间超过 dedup 窗口后 `Sweep(now)` 将其置为 `RESOLVED`；
  再次命中会开启一条全新告警，而不是复活旧告警。
- 所有事件 ID 合并去重，告警列表按 `(FirstSeen, RuleID)` 稳定排序。

### 7. 规则热重载不改变历史

`Engine.ReplaceRules(snapshot)` 原子替换不可变规则快照：快照有单调递增版本号，
已产出的 Finding / Alert 永不重新评估、永不改变。新规则只对替换之后到达的事件生效；
若被替换掉的规则仍有未关闭窗口，该窗口直接丢弃，不产生新结论。

## 代码结构

```
cmd/siem/main.go      CLI：加载规则/事件、跑引擎、打印判定与告警
pkg/model/            统一领域模型：事件、规则、拒绝原因、Finding、Alert
pkg/rules/            规则加载、校验、归一、拒绝原因分类、不可变快照
pkg/matcher/          条件求值（eq/ne/contains/prefix/suffix/regex/gt/gte/lt/lte/exists）
pkg/engine/           去重、watermark、滚动窗口关联、批量排序、热重载
pkg/alert/            滑动窗口告警去重、抑制审计、resolved 生命周期
examples/             含坏规则、重复/迟到事件的本地复现样例
```

## 作为库使用

```go
snap, _ := rules.NewLoader().LoadFile("rules.json")
eng := engine.New(snap, engine.DefaultConfig()) // AllowedLateness=10s, Dedup=5m

// 批量：乱序安全
outs := eng.IngestBatch(events, time.Now())

// 或流式逐条
out  := eng.Ingest(event, time.Now())
eng.Flush(time.Now())
eng.AlertManager().Sweep(time.Now())

for _, r := range snap.Rejections() { /* r.Reason 区分拒绝原因 */ }
for _, f := range eng.Findings()     { /* 确定性顺序的最终判定 */ }
```
