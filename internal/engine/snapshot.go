package engine

import (
	"errors"
	"fmt"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
)

// ErrLatenessMismatch 表示恢复快照时水位线参数与落盘时不一致。
var ErrLatenessMismatch = errors.New("lateness mismatch with snapshot")

// Snapshot 是 Correlator 判定状态的可序列化快照。
// 快照内容等价于内存状态的全量拷贝：用 Snapshot + RestoreSnapshot
// 恢复的关联器继续摄入事件，结论与从未中断的单次运行一致。
type Snapshot struct {
	LatenessNs int64
	MaxSeen    int64 // UnixNano；HasMax=false 时无意义
	HasMax     bool
	SeenIDs    map[string]int64 // 事件 ID -> 事件时间 UnixNano
	Buffers    []BufferEntry
	Emitted    []EmitEntry
	Stats      Stats
}

// BufferEntry 是一个 (rule, group) 分组缓冲的快照条目。
type BufferEntry struct {
	RuleID   string
	GroupKey string
	Events   []BufferedEvent
}

// BufferedEvent 是缓冲中的单条事件。
type BufferedEvent struct {
	ID string
	TS int64 // UnixNano
}

// EmitEntry 记录一个已产出过的命中，防止恢复后重复产出。
type EmitEntry struct {
	RuleID    string
	GroupKey  string
	WindowEnd int64 // UnixNano
}

// Snapshot 导出当前判定状态。返回值为深拷贝，之后修改关联器不影响快照。
func (c *Correlator) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	snap := Snapshot{
		LatenessNs: int64(c.lateness),
		HasMax:     c.hasMax,
		Stats:      c.stats,
		SeenIDs:    make(map[string]int64, len(c.seenIDs)),
	}
	if c.hasMax {
		snap.MaxSeen = c.maxSeen.UnixNano()
	}
	for id, ts := range c.seenIDs {
		snap.SeenIDs[id] = ts.UnixNano()
	}
	for key, buf := range c.buffers {
		entry := BufferEntry{RuleID: key.ruleID, GroupKey: key.groupKey}
		for _, be := range buf {
			entry.Events = append(entry.Events, BufferedEvent{ID: be.id, TS: be.ts.UnixNano()})
		}
		snap.Buffers = append(snap.Buffers, entry)
	}
	for ek := range c.emitted {
		snap.Emitted = append(snap.Emitted, EmitEntry{
			RuleID:    ek.ruleID,
			GroupKey:  ek.groupKey,
			WindowEnd: ek.windowEnd.UnixNano(),
		})
	}
	return snap
}

// RestoreSnapshot 从快照恢复关联器。规则取调用方当前传入的规则
// （判定语义与快照无关，规则一致性由上层校验），水位线宽限必须与
// 快照一致，否则返回 ErrLatenessMismatch，由调用方区分处理。
func RestoreSnapshot(snap Snapshot, rs []rules.Rule, lateness time.Duration) (*Correlator, error) {
	if time.Duration(snap.LatenessNs) != lateness {
		return nil, fmt.Errorf("%w: snapshot=%s current=%s",
			ErrLatenessMismatch, time.Duration(snap.LatenessNs), lateness)
	}
	c := NewCorrelator(rs, lateness)
	c.hasMax = snap.HasMax
	if snap.HasMax {
		c.maxSeen = time.Unix(0, snap.MaxSeen).UTC()
	}
	c.stats = snap.Stats
	for id, ts := range snap.SeenIDs {
		c.seenIDs[id] = time.Unix(0, ts).UTC()
	}
	for _, entry := range snap.Buffers {
		key := bufKey{ruleID: entry.RuleID, groupKey: entry.GroupKey}
		buf := make([]bufferedEvent, 0, len(entry.Events))
		for _, be := range entry.Events {
			buf = append(buf, bufferedEvent{id: be.ID, ts: time.Unix(0, be.TS).UTC()})
		}
		c.buffers[key] = buf
	}
	for _, ee := range snap.Emitted {
		c.emitted[emitKey{
			ruleID:    ee.RuleID,
			groupKey:  ee.GroupKey,
			windowEnd: time.Unix(0, ee.WindowEnd).UTC(),
		}] = struct{}{}
	}
	return c, nil
}
