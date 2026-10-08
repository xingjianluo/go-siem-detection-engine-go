# go-siem-detection-engine-go

纯本地的日志检测与告警关联引擎：读取本地规则文件与日志文件即可完成
完整验证，不依赖任何外部服务。

## 快速复现

```bash
# 端到端跑一遍示例规则 + 示例日志（无状态一口气跑完）
go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl \
    -lateness 10m -dedup 10m

# 跑全部测试（含竞态检测）
go test -race ./...

# 关键路径测试会打印输入事件、命中规则与判定依据
go test -v ./internal/engine/ ./internal/alert/ ./internal/rules/ ./internal/state/
```

## 三种运行方式

### 1. 一口气跑完（无状态，原始语义）

不传 `-state-dir` 即与旧版本完全一致：不落盘、进程结束状态即消失。

```bash
go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl
```

### 2. 停一下再接着跑（断点续跑）

加上 `-state-dir` 与 `-resume` 后，引擎会周期性把**处理进度与判定状态**
原子落盘；进程重启后从上次的字节偏移继续，只处理新追加的日志。

```bash
go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl \
    -state-dir ./.siem-state -resume
```

续跑沿用既有判定语义，不改变已经定下的结论：

- **进度层**：游标记录“日志路径 + 已确认字节偏移”，重启后已处理区间
  不再读入；日志被轮转/截断（比保存的偏移还短）会报
  `ErrProgressTruncated`，不会悄悄从头重算。
- **判定层**：关联器的事件去重表、水位线、分组缓冲、已产出命中标记，
  以及告警的 `Hits` / `Suppressed` / 状态 / 抑制原因都随快照恢复。
  即使重启后又喂入已处理事件，它们全部判为重复（计入
  `Stats.Duplicates`），不会产生新命中，也不会改乱已有告警的计数。
- **迟到事件**：水位线从快照恢复，容忍范围内的迟到事件重启后依旧
  正确并入，超出容忍的照旧丢弃（`Stats.LateDropped`）。
- **写半行保护**：文件末尾没有换行符的半行不会被当成坏事件，等追加
  完整后同一行照常读到。
- **规则换了**：`-resume` 时发现当前规则与落盘规则不一致会直接报
  `ErrRulesChanged`，不会静默用新规则改写历史判定。要按新规则看
  历史，请用下面的历史回放；要丢弃旧现场从头开始，显式加 `-fresh`。

相关参数：`-checkpoint-every N`（每 N 行落一次盘，默认 100，
进程在批中间崩溃最多重跑最后 N 行，重复由去重表兜底）。

### 3. 历史回放对账

`-replay <名称>` 用当前规则把整份历史日志从头重跑一遍。回放现场与
实时链路使用**不同的状态键、不同的状态文件**，物理隔离：

```bash
go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl \
    -state-dir ./.siem-state -replay audit-1008
```

- 回放可以放心使用与实时链路不同的规则（规则评估换版时用它对账）。
- 回放结论与“把同一批事件直接按文件顺序交给平时那条链路”的结论
  一致；乱序、重复、迟到走的还是关联器同一套顺序无关语义
  （`TestReplayOutOfOrderParity` 用 10 种随机乱序验证）。
- 回放状态键形如 `replay-audit-1008-<UTC时间戳>`，多次回放互不覆盖，
  也绝不写实时键 `realtime`。

## 状态文件、容量与兼容

### 状态放在哪

`-state-dir` 目录下（默认不启用，即无状态模式）：

```
.siem-state/
  realtime.state.json                              # 实时链路检查点
  .realtime.lock                                   # 同键跨进程互斥锁
  replay-<名称>-<UTC时间戳>.state.json             # 每次历史回放一份
  .replay-<名称>-<UTC时间戳>.lock
```

每个状态文件 = 外层信封（魔数 `go-siem-state-v1`、格式版本、保存时间、
payload 的 SHA-256 校验和）+ payload（关联器判定状态、告警状态、日志
游标）。写入走“临时文件 + fsync + rename”，读者要么看到完整旧文件、
要么看到完整新文件；同键写入进程内互斥、跨进程加文件锁，多来源同时
写不会竞态或写丢。

### 容量与保留（状态不能只涨不消）

| 机制 | 行为 |
|---|---|
| 关联器状态自然上界 | 水位线语义只保留 `(lateness + 最大规则窗口)` 事件跨度内的去重表、缓冲与命中标记，旧状态在摄入时持续清理 |
| `resolved` 告警保留期 | `-state-max-age`（默认 **72h**）之前最后出现的 `resolved` 告警在下次落盘时删除；`firing` 告警**永不**被保留策略静默删除 |
| 状态文件大小上限 | `-state-max-bytes`（默认 **16 MiB**）。超限先清全部 `resolved` 告警；若关联器最小必要状态仍超限，返回 `ErrCapacityExceeded`，不靠删判定状态硬塞 |
| 旧回放文件清理 | `Store.Sweep()` 按同一 MaxAge 删除过期的回放状态文件（实时键不受影响） |
| 检查点整体过期 | checkpoint 的保存时间超出 MaxAge 时，`Load` 返回 `ErrExpired`，而不是当空状态从头开始 |

### 不兼容 / 损坏 / 过期：三类结果互相可区分

读取检查点时不会“一声不吭当没有状态”：

| 错误 | 触发情形 | 处置建议 |
|---|---|---|
| `ErrVersionIncompatible` | 魔数不是本引擎格式，或状态版本号高于当前程序支持版本（当前格式版本 `1`） | 换用对应版本的程序；或移走旧文件，用 `-replay` 重建对账结论、`-fresh` 重启实时 |
| `ErrCorrupt` | 信封 JSON 截断、校验和不符（磁盘损坏/手工篡改）、payload 无法解码或内部数据不一致 | 移走损坏文件后 `-replay` + `-fresh` |
| `ErrExpired` | checkpoint 保存时间早于 `-state-max-age` | 历史结论走 `-replay`；实时链路 `-fresh` 重启 |
| `ErrRulesChanged` | 续跑时规则与落盘规则不一致 | 旧规则 `-resume` 保留旧现场，或新规则 `-replay` 另开现场 |
| `ErrProgressTruncated` | 日志文件被轮转/截断到已保存偏移之前 | 确认新文件后 `-fresh` |
| `ErrLockBusy` | 另一进程正持有同一状态键 | 停掉对方或换状态目录 |

CLI 遇到这些错误会分别打印类别、细节与恢复提示。

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
cmd/siem/          本地验证入口（无状态 / -resume 续跑 / -replay 回放）
internal/rules/    规则加载、校验、归一化
internal/engine/   水位线窗口关联、去重、迟到处理；判定状态快照/恢复/保留裁剪
internal/alert/    告警去重与生命周期；告警状态快照/恢复/resolved 清理
internal/state/    断点续跑、历史回放、原子落盘、文件锁、容量与保留策略
rules/rules.json   示例规则（含 3 条会被拒绝的畸形规则）
data/events.jsonl  示例日志（含重复与迟到事件）
```

## 本地一步步复现验证

```bash
go build -o /tmp/siem ./cmd/siem
D=$(mktemp -d)

# 1) 先处理日志前半段并落盘
head -5 data/events.jsonl > $D/log.jsonl
/tmp/siem -rules rules/rules.json -logs $D/log.jsonl \
  -state-dir $D/state -resume -state-max-age 0

# 2) 进程“重启”且没有新日志：偏移之后 0 新行，结论不重算
/tmp/siem -rules rules/rules.json -logs $D/log.jsonl \
  -state-dir $D/state -resume -state-max-age 0

# 3) 追加剩余日志后续跑：只处理新增部分，最终告警与一口气跑完一致
cat data/events.jsonl >> $D/log.jsonl
/tmp/siem -rules rules/rules.json -logs $D/log.jsonl \
  -state-dir $D/state -resume -state-max-age 0

# 4) 历史回放对账：独立状态键，不动 realtime 文件
/tmp/siem -rules rules/rules.json -logs data/events.jsonl \
  -state-dir $D/state -replay audit-1008 -state-max-age 0
ls $D/state   # realtime.state.json 与 replay-audit-1008-*.state.json 并存

# 5) 自动化测试：重启续跑 / 回放对账 / 容量 / 不兼容处理，含竞态检测
go test -race -v ./internal/state/ ./internal/engine/ ./internal/alert/
```

测试运行时会打印 `[resume-scenario]`、`[replay-scenario]`、
`[compat-scenario]`、`[expiry-scenario]`、`[retention-scenario]`、
`[capacity-scenario]`、`[concurrent-scenario]`、`[lock-scenario]`
等中文业务场景日志，说明每条用例在验证什么。

### 已知边界与限制

- 进度游标语义是“同一路径的追加文件”。日志按天切分到**新文件名**时，
  应对新文件新起一条链路或在编排层轮询多个游标；同名文件被截断会明确
  报 `ErrProgressTruncated` 而不是静默重放。
- 容量上限的可收缩对象是已 `resolved` 的告警与水位线之外的判定状态；
  当规则窗口 + 迟到容忍本身需要的最小状态就超过 `-state-max-bytes` 时，
  引擎选择报错（`ErrCapacityExceeded`）而不是改变窗口/迟到判定结论。
- 跨进程锁在 Unix 上为 O_EXCL 锁文件（持有者进程退出即视为陈旧锁可
  接管），Windows 上为 `LockFileEx`（句柄关闭自动释放）。
- 状态格式当前为版本 `1`，由更高版本程序写入的状态会被拒绝加载并给出
  明确提示，而不是被错误解读。
