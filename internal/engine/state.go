// 状态快照：供 state 包把关联器的判定状态落盘 / 恢复使用。
//
// 快照内容与 Correlator 的内部判定状态一一对应，恢复后对后续事件的
// 判定结论与未重启时完全一致（含去重表、水位线、分组缓冲、已产出标记）。
// 运行统计 Stats 属于进程期观测口径，不入快照。
// Correlator 构造时持有的规则副本也一并入快照。
package engine

import (
	"fmt"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
)

// State 是 Correlator 判定状态的可序列化快照。
type State struct {
	Rules       []rules.Rule     `json:"rules"`
	LatenessNS  int64            `json:"lateness_ns"`
	MaxSeen     time.Time        `json:"max_seen"`
	HasMax      bool             `json:"has_max"`
	SeenIDs     map[string]int64 `json:"seen_ids"` // 事件 ID -> 事件时间（UnixNano）
	Buffers     []BufS           `json:"buffers"`
	EmittedKeys []EmittedKeyS    `json:"emitted_keys"`
	// Stats 不随快照恢复：它是本次进程运行期的观测计数，重启后从 0
	// 重新累计。序列化时写零值，避免旧计数与重启后的真实计数混淆。
	Stats Stats `json:"stats"`
}

// BufS 是一个 (rule, group) 分组的缓冲事件快照。
type BufS struct {
	RuleID   string      `json:"rule_id"`
	GroupKey string      `json:"group_key"`
	Events   []BufEventS `json:"events"`
}

// BufEventS 是缓冲中的一条事件（仅判定所需字段）。
type BufEventS struct {
	ID string    `json:"id"`
	TS time.Time `json:"ts"`
}

// EmittedKeyS 是一条已产出命中的标记。
type EmittedKeyS struct {
	RuleID    string    `json:"rule_id"`
	GroupKey  string    `json:"group_key"`
	WindowEnd time.Time `json:"window_end"`
}

// SnapshotState 返回当前判定状态的深拷贝快照。
func (c *Correlator) SnapshotState() State {
	c.mu.Lock()
	defer c.mu.Unlock()

	st := State{
		Rules:       make([]rules.Rule, len(c.rules)),
		LatenessNS:  int64(c.lateness),
		MaxSeen:     c.maxSeen,
		HasMax:      c.hasMax,
		SeenIDs:     make(map[string]int64, len(c.seenIDs)),
		Buffers:     make([]BufS, 0, len(c.buffers)),
		EmittedKeys: make([]EmittedKeyS, 0, len(c.emitted)),
		// Stats 刻意留零：它是进程期计数，不跨重启携带。
	}
	copy(st.Rules, c.rules)
	for id, ts := range c.seenIDs {
		st.SeenIDs[id] = ts.UnixNano()
	}
	for k, buf := range c.buffers {
		b := BufS{RuleID: k.ruleID, GroupKey: k.groupKey,
			Events: make([]BufEventS, len(buf))}
		for i, be := range buf {
			b.Events[i] = BufEventS{ID: be.id, TS: be.ts}
		}
		st.Buffers = append(st.Buffers, b)
	}
	for ek := range c.emitted {
		st.EmittedKeys = append(st.EmittedKeys, EmittedKeyS{
			RuleID: ek.ruleID, GroupKey: ek.groupKey, WindowEnd: ek.windowEnd,
		})
	}
	return st
}

// RestoreState 用快照恢复关联器。目标实例必须是新建的（不能把两个
// 现场合并到一起，否则去重与水位线语义会被破坏），否则返回错误。
func (c *Correlator) RestoreState(s State) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hasMax || len(c.seenIDs) > 0 || len(c.buffers) > 0 || len(c.emitted) > 0 {
		return fmt.Errorf("RestoreState: target correlator is not empty")
	}
	if s.LatenessNS < 0 {
		return fmt.Errorf("RestoreState: bad lateness %d", s.LatenessNS)
	}

	c.rules = make([]rules.Rule, len(s.Rules))
	copy(c.rules, s.Rules)
	c.lateness = time.Duration(s.LatenessNS)
	c.maxSeen, c.hasMax = s.MaxSeen, s.HasMax
	// stats 保持零值：重启后的观测计数从本次进程重新累计。

	c.seenIDs = make(map[string]time.Time, len(s.SeenIDs))
	for id, ns := range s.SeenIDs {
		if id == "" {
			return fmt.Errorf("RestoreState: empty event id in seen_ids")
		}
		c.seenIDs[id] = time.Unix(0, ns).UTC()
	}
	c.buffers = make(map[bufKey][]bufferedEvent, len(s.Buffers))
	for _, b := range s.Buffers {
		k := bufKey{ruleID: b.RuleID, groupKey: b.GroupKey}
		if _, dup := c.buffers[k]; dup {
			return fmt.Errorf("RestoreState: duplicate buffer for rule=%q group=%q", b.RuleID, b.GroupKey)
		}
		buf := make([]bufferedEvent, 0, len(b.Events))
		for _, be := range b.Events {
			if be.ID == "" {
				return fmt.Errorf("RestoreState: empty buffered event id in rule=%q group=%q", b.RuleID, b.GroupKey)
			}
			buf = append(buf, bufferedEvent{id: be.ID, ts: be.TS})
		}
		c.buffers[k] = buf
	}
	c.emitted = make(map[emitKey]struct{}, len(s.EmittedKeys))
	for _, ek := range s.EmittedKeys {
		key := emitKey{ruleID: ek.RuleID, groupKey: ek.GroupKey, windowEnd: ek.WindowEnd}
		if _, dup := c.emitted[key]; dup {
			return fmt.Errorf("RestoreState: duplicate emitted key rule=%q group=%q end=%s",
				ek.RuleID, ek.GroupKey, ek.WindowEnd.Format(time.RFC3339Nano))
		}
		c.emitted[key] = struct{}{}
	}
	return nil
}

// RetainHorizon 按给定的状态保留边界裁剪内部状态：
// 事件时间 <= horizon 的去重记录、缓冲事件与命中标记一律删除。
// 这与 pruneLocked 的清理口径一致：horizon 之外的状态不可能再影响
// 任何未来判定（属于那些窗口的事件只会落在水位线之前被迟到丢弃）。
// 返回裁剪后保留的去重 ID 数。
func (c *Correlator) RetainHorizon(horizon time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, buf := range c.buffers {
		i := 0
		for i < len(buf) && !buf[i].ts.After(horizon) {
			i++
		}
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
	return len(c.seenIDs)
}
