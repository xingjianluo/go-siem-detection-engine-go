// Package engine 实现基于时间窗口的有状态关联检测。
//
// 语义约定（稳定且与到达顺序无关）：
//   - 事件按 ID 全局去重，重复事件只算一次；
//   - 水位线 watermark = 已见最大事件时间 - allowedLateness；
//   - 事件时间 <= watermark 的迟到事件被丢弃并计入 Stats.LateDropped；
//   - 每条规则按 GroupBy 字段分组，组内维护按时间排序的去重事件集合；
//   - 窗口以事件时间 t 为右端，统计 (t-window, t] 内的事件数；
//   - 只有当 t <= watermark（窗口闭合，不可能再有属于该窗口的事件到达）
//     时才产出 Match，因此命中集合只取决于被接受事件的集合，
//     与到达顺序无关；
//   - 同一 (rule, group, windowEnd) 的命中只产出一次。
package engine

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
)

// Event 是一条归一化后的日志事件。
type Event struct {
	ID        string
	Timestamp time.Time
	Source    string
	Fields    map[string]string
}

// Match 表示一次规则命中。
type Match struct {
	RuleID    string
	GroupKey  string
	Count     int       // 窗口闭合时窗口内的去重事件数
	WindowEnd time.Time // 窗口右端（触发事件的原始时间戳）
	EventIDs  []string  // 窗口内参与计数的事件 ID（按时间排序，便于判定依据展示）
}

// Stats 记录关联器运行统计。
type Stats struct {
	Ingested    int // 成功摄入（未去重、未迟到）的事件数
	Duplicates  int // 因 ID 重复被忽略的事件数
	LateDropped int // 因迟到被丢弃的事件数
}

// Correlator 是有状态的窗口关联器，并发安全。
// 规则在构造时拷贝，之后重新加载规则文件不影响本实例的判定。
type Correlator struct {
	mu       sync.Mutex
	rules    []rules.Rule
	lateness time.Duration

	maxSeen time.Time
	hasMax  bool
	seenIDs map[string]time.Time       // 事件 ID -> 事件时间，用于去重与过期清理
	buffers map[bufKey][]bufferedEvent // (rule, group) -> 按时间排序的事件
	emitted map[emitKey]struct{}       // 已产出过的命中，防止重复
	stats   Stats
}

type bufKey struct {
	ruleID   string
	groupKey string
}

type emitKey struct {
	ruleID    string
	groupKey  string
	windowEnd time.Time
}

type bufferedEvent struct {
	id string
	ts time.Time
}

// NewCorrelator 创建关联器。allowedLateness 决定水位线落后最大事件时间多少。
func NewCorrelator(rs []rules.Rule, allowedLateness time.Duration) *Correlator {
	cp := make([]rules.Rule, len(rs))
	copy(cp, rs)
	return &Correlator{
		rules:    cp,
		lateness: allowedLateness,
		seenIDs:  map[string]time.Time{},
		buffers:  map[bufKey][]bufferedEvent{},
		emitted:  map[emitKey]struct{}{},
	}
}

// Ingest 摄入一条事件，返回因本次摄入而闭合的窗口所触发的规则命中。
// 重复或迟到事件不会产生命中。
func (c *Correlator) Ingest(e Event) []Match {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. 去重：同一 ID 的事件只算一次。
	if _, dup := c.seenIDs[e.ID]; dup {
		c.stats.Duplicates++
		return nil
	}

	// 2. 迟到判定：事件时间 <= watermark 直接丢弃。
	if c.hasMax && !e.Timestamp.After(c.watermark()) {
		c.stats.LateDropped++
		return nil
	}

	c.seenIDs[e.ID] = e.Timestamp
	c.stats.Ingested++
	if !c.hasMax || e.Timestamp.After(c.maxSeen) {
		c.maxSeen = e.Timestamp
		c.hasMax = true
	}

	// 3. 条件匹配，写入各规则对应的分组缓冲。
	matched := map[string]bool{}
	for _, r := range c.rules {
		if !matchAll(r.Conditions, e) {
			continue
		}
		key := bufKey{ruleID: r.ID, groupKey: groupKeyOf(r, e)}
		c.buffers[key] = insertSorted(c.buffers[key], bufferedEvent{id: e.ID, ts: e.Timestamp})
		matched[r.ID] = true
	}

	// 4. 评估所有已闭合窗口（窗口右端 <= watermark）。
	matches := c.evaluateClosedLocked(c.watermark())

	c.pruneLocked()
	return matches
}

// Flush 在输入结束时调用：把所有未闭合窗口视为闭合并评估，
// 返回此前尚未产出的命中。语义等价于把水位线推进到无穷大。
func (c *Correlator) Flush() []Match {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hasMax {
		return nil
	}
	// 用足够大的水位线评估全部窗口；不改动 maxSeen，
	// 之后若仍有事件到达，正常的水位线语义不受影响。
	return c.evaluateClosedLocked(c.maxSeen.Add(c.lateness).Add(1))
}

// Stats 返回运行统计的副本。
func (c *Correlator) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// watermark 返回当前水位线。
func (c *Correlator) watermark() time.Time {
	return c.maxSeen.Add(-c.lateness)
}

// evaluateClosedLocked 扫描所有分组缓冲，对右端 <= wm 且尚未产出过
// 命中的窗口做计数，达到阈值则产出 Match。
func (c *Correlator) evaluateClosedLocked(wm time.Time) []Match {
	if !c.hasMax {
		return nil
	}
	ruleByID := map[string]rules.Rule{}
	for _, r := range c.rules {
		ruleByID[r.ID] = r
	}

	var matches []Match
	// 遍历 map 顺序不稳定，先收集再排序，保证输出确定。
	for key, buf := range c.buffers {
		r := ruleByID[key.ruleID]
		for _, be := range buf {
			if be.ts.After(wm) {
				continue // 窗口未闭合
			}
			ek := emitKey{ruleID: key.ruleID, groupKey: key.groupKey, windowEnd: be.ts}
			if _, done := c.emitted[ek]; done {
				continue
			}
			lo := be.ts.Add(-r.Window)
			var ids []string
			for _, w := range buf {
				if w.ts.After(lo) && !w.ts.After(be.ts) {
					ids = append(ids, w.id)
				}
			}
			if len(ids) < r.Threshold {
				continue
			}
			c.emitted[ek] = struct{}{}
			matches = append(matches, Match{
				RuleID:    key.ruleID,
				GroupKey:  key.groupKey,
				Count:     len(ids),
				WindowEnd: be.ts,
				EventIDs:  ids,
			})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if !matches[i].WindowEnd.Equal(matches[j].WindowEnd) {
			return matches[i].WindowEnd.Before(matches[j].WindowEnd)
		}
		if matches[i].RuleID != matches[j].RuleID {
			return matches[i].RuleID < matches[j].RuleID
		}
		return matches[i].GroupKey < matches[j].GroupKey
	})
	return matches
}

// pruneLocked 清理早于（水位线 - 最大窗口）的缓冲事件、去重记录与命中标记。
// 该 horizon 之外的状态不可能再影响任何未来判定：
// 属于那些窗口的事件必然 <= watermark，只会被迟到丢弃。
func (c *Correlator) pruneLocked() {
	if !c.hasMax {
		return
	}
	var maxWindow time.Duration
	for _, r := range c.rules {
		if r.Window > maxWindow {
			maxWindow = r.Window
		}
	}
	horizon := c.watermark().Add(-maxWindow)
	for k, buf := range c.buffers {
		i := sort.Search(len(buf), func(i int) bool { return buf[i].ts.After(horizon) })
		if i == len(buf) {
			delete(c.buffers, k)
		} else if i > 0 {
			c.buffers[k] = append([]bufferedEvent(nil), buf[i:]...)
		}
	}
	for id, ts := range c.seenIDs {
		if !ts.After(horizon) {
			delete(c.seenIDs, id)
		}
	}
	for ek := range c.emitted {
		if !ek.windowEnd.After(horizon) {
			delete(c.emitted, ek)
		}
	}
}

// matchAll 检查事件是否满足规则的全部条件。
func matchAll(conds []rules.Condition, e Event) bool {
	for _, cond := range conds {
		if !matchCond(cond, e) {
			return false
		}
	}
	return true
}

func matchCond(cond rules.Condition, e Event) bool {
	v, ok := fieldValue(e, cond.Field)
	if !ok {
		return false
	}
	switch cond.Op {
	case rules.OpEq:
		return v == cond.Value
	case rules.OpNeq:
		return v != cond.Value
	case rules.OpContains:
		return strings.Contains(v, cond.Value)
	case rules.OpGt, rules.OpLt:
		n, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return false
		}
		if cond.Op == rules.OpGt {
			return n > cond.Number
		}
		return n < cond.Number
	}
	return false
}

// fieldValue 取事件字段：内建字段（id/source/timestamp）优先，其次 Fields 表。
func fieldValue(e Event, name string) (string, bool) {
	switch name {
	case "id":
		return e.ID, true
	case "source":
		return e.Source, true
	case "timestamp":
		return e.Timestamp.Format(time.RFC3339Nano), true
	}
	v, ok := e.Fields[name]
	return v, ok
}

func groupKeyOf(r rules.Rule, e Event) string {
	field := r.GroupBy
	if field == "" {
		field = "source"
	}
	v, _ := fieldValue(e, field)
	return v
}

// insertSorted 按 (ts, id) 顺序插入，保证缓冲内容与到达顺序无关。
func insertSorted(buf []bufferedEvent, ev bufferedEvent) []bufferedEvent {
	i := sort.Search(len(buf), func(i int) bool {
		if buf[i].ts.Equal(ev.ts) {
			return buf[i].id >= ev.id
		}
		return buf[i].ts.After(ev.ts)
	})
	buf = append(buf, bufferedEvent{})
	copy(buf[i+1:], buf[i:])
	buf[i] = ev
	return buf
}
