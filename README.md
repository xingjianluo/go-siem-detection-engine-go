# go-siem-detection-engine-go

纯本地的日志检测与告警关联引擎：读取本地规则文件与日志文件即可完成
完整验证，不依赖任何外部服务。支持**暂停续跑**（进度与判定状态落盘，
进程重启后接着跑）与**历史回放对账**（独立现场重跑历史日志，不干扰
实时链路）。

## 快速复现

```bash
# 端到端跑一遍示例规则 + 示例日志（纯内存，不落盘）
go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl \
    -lateness 10m -dedup 10m

# 跑全部测试（含竞态检测）
go test -race ./...

# 关键路径测试会打印每条用例验证的业务场景
go test -v ./internal/...
```

### 一步步复现“暂停续跑”

```bash
# 1. 第一次运行：处理完日志后把进度与判定状态落盘到 var/state
go run ./cmd/siem -logs data/events.jsonl -state var/state

# 2. 模拟进程重启，再执行同一命令：
#    输出 "resumed from checkpoint (processed=9 events)"，
#    已处理的事件被跳过，告警 hits/suppressed 与停机前完全一致
go run ./cmd/siem -logs data/events.jsonl -state var/state

# 3. 向 data/events.jsonl 追加新一批日志后再跑一次，
#    只会处理追加的部分，结论与“一口气跑完”相同

# 4. 状态不可用时（损坏/版本不兼容/过期/规则或参数变更），
#    进程以退出码 2 拒绝启动并说明原因，绝不静默从头开始；
#    确认要放弃旧现场时显式加 -fresh
go run ./cmd/siem -logs data/events.jsonl -state var/state -fresh
```

### 一步步复现“历史回放对账”

```bash
# 实时链路先跑起来（状态落在 var/state）
go run ./cmd/siem -logs data/events.jsonl -state var/state

# 拿同一份历史日志按当前规则独立重跑：
# 不读写 var/state，结论与实时链路逐条一致
go run ./cmd/siem -logs data/events.jsonl -replay
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

## 暂停续跑（状态落盘）

加 `-state <目录>` 后，每处理完一批事件（含 `Flush`）就把完整判定
现场落盘：

- **落盘内容**：已消费事件条数（续跑偏移）、关联器状态（水位线、
  去重表、分组缓冲、已产出命中标记、统计）、告警状态（含
  hits/suppressed/生命周期）、规则指纹与 `-lateness`/`-dedup` 参数。
- **重启续跑**：再次启动时从检查点恢复，CLI 跳过已落盘进度之前的
  事件；崩溃导致上游重推的事件由引擎按 ID 去重（或按水位线迟到
  丢弃），不会重算，已有告警的命中/抑制结论不变
  （`TestResumeThenRefedBatchDoesNotDoubleCount`）。
- **迟到语义不变**：恢复后水位线、宽限与保留边界与中断前完全一致，
  容忍范围内的迟到事件照旧并入（`TestRestoreKeepsLatenessSemantics`）。
- **结论等价**：分批 + 中间重启的最终结论与单进程一次跑完逐条一致
  （`TestResumeAfterRestartEqualsSingleRun`、
  `TestSnapshotRestoreEqualsUninterrupted`）。

### 状态留在哪、占多少地方

状态目录（`-state` 指定）下的文件：

```
checkpoint.json    当前检查点（tmp 写入 + rename 原子替换，崩溃不留半个文件）
checkpoint.1.json  上一份历史检查点（轮换保留）
checkpoint.2.json  更早的历史检查点
checkpoint.lock    多来源写入的互斥锁文件（flock）
```

- **容量上限**：快照文件总数不超过 `-state-keep`（默认 3，含当前
  这份），超出自动轮换删除，磁盘占用有硬上限。
- **保留期**：检查点年龄超过 `-state-max-age`（默认 24h）即视为
  过期，加载时拒绝（`ErrExpired`），不会拿着太旧的进度硬跑。
- **内存侧**：引擎按 `水位线 - 最大规则窗口` 的保留边界持续清理
  去重表/缓冲/命中标记，状态不随运行时长无限增长。

### 状态异常的可区分处理

打开链路时，状态问题不会“一声不吭当作没有状态从头开始”，
CLI 以退出码 2 拒绝启动并打印原因类别，API 侧用
`pipeline.ResumeStatus` / `errors.Is` 区分：

| 情况 | ResumeStatus / error |
|---|---|
| 首次运行，无状态文件 | `no_state` / `state.ErrNoState`（正常，直接开跑） |
| 状态文件版本不兼容 | `incompatible_version` / `state.ErrIncompatibleVersion` |
| 文件损坏（解析失败或 CRC 校验和不匹配） | `corrupted` / `state.ErrCorrupted` |
| 超出保留期 | `expired` / `state.ErrExpired` |
| 规则指纹或 lateness/dedup 参数与落盘时不一致 | `config_changed` |

确认要放弃旧现场时显式加 `-fresh`（API 侧 `pipeline.OpenFresh`），
旧状态会在首次落盘时被覆盖。

**多来源并发写**：同一状态目录的并发写入通过 `checkpoint.lock`
文件锁串行化，配合 tmp+rename 原子提交，不会竞态、写丢或留下
撕裂文件（`TestConcurrentSaveNoRaceNoTornWrite` 在 `-race` 下验证）。

## 历史回放对账

`-replay`（API 侧 `pipeline.Replay`）用当前规则对历史日志独立
重跑一遍：

- **隔离性**：全程只用内存现场，不读写任何状态目录，不干扰正在
  运行的实时链路（`TestReplayMatchesLiveAndDoesNotTouchState`
  断言回放前后落盘内容不变）。
- **一致性**：回放结论与把同一批事件按时间交给实时链路（含
  Flush）逐条一致；乱序、重复、迟到事件的处理沿用同一套水位线
  语义，天然站得住。
- **对账口径**：比较时忽略每次运行都会变化的告警 ID，只比对
  业务结论（规则、分组、hits、suppressed、状态、时间线）。

## 目录结构

```
cmd/siem/            本地验证入口（一次性 / 续跑 / 回放三种用法）
internal/rules/      规则加载、校验、归一化、规则指纹
internal/engine/     水位线窗口关联、去重、迟到处理、判定状态快照
internal/alert/      告警去重与生命周期、告警状态快照
internal/state/      状态文件仓库：版本化、校验和、原子写、轮换与保留
internal/pipeline/   实时链路组装（续跑）与历史回放
rules/rules.json     示例规则（含 3 条会被拒绝的畸形规则）
data/events.jsonl    示例日志（含重复与迟到事件）
```
