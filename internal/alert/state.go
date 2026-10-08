// 告警管理器状态快照：供 state 包落盘 / 恢复使用。
//
// 恢复后已有告警的 Hits / Suppressed / 状态与抑制结论保持不变。
// 重启后若重复喂入已处理事件，这些命中在关联器层即被去重表挡住，
// 不会再次进入 Manager，因此计数与抑制结论不会被改乱。
package alert

import (
	"encoding/json"
	"fmt"
	"time"
)

// State 是 Manager 告警状态的可序列化快照。
type State struct {
	DedupWindowNS int64         `json:"dedup_window_ns"`
	Seq           int           `json:"seq"` // 新建告警序号，恢复后继续递增
	Alerts        []AlertStateS `json:"alerts"`
}

// AlertStateS 是单条告警的序列化形式（与 Alert 一一对应）。
type AlertStateS struct {
	ID         string `json:"id"`
	RuleID     string `json:"rule_id"`
	GroupKey   string `json:"group_key"`
	Hits       int    `json:"hits"`
	Suppressed int    `json:"suppressed"`
	FirstSeen  int64  `json:"first_seen_unix_nano"`
	LastSeen   int64  `json:"last_seen_unix_nano"`
	Status     Status `json:"status"`
	Reason     string `json:"reason"`
}

// SnapshotState 返回告警状态的深拷贝快照。
func (m *Manager) SnapshotState() State {
	m.mu.Lock()
	defer m.mu.Unlock()

	st := State{
		DedupWindowNS: int64(m.window),
		Seq:           m.seq,
		Alerts:        make([]AlertStateS, 0, len(m.alerts)),
	}
	for _, a := range m.alerts {
		st.Alerts = append(st.Alerts, AlertStateS{
			ID:         a.ID,
			RuleID:     a.RuleID,
			GroupKey:   a.GroupKey,
			Hits:       a.Hits,
			Suppressed: a.Suppressed,
			FirstSeen:  a.FirstSeen.UnixNano(),
			LastSeen:   a.LastSeen.UnixNano(),
			Status:     a.Status,
			Reason:     a.Reason,
		})
	}
	return st
}

// RestoreState 用快照恢复管理器。目标实例必须为空（不能合并两个现场）。
func (m *Manager) RestoreState(s State) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.alerts) > 0 {
		return fmt.Errorf("RestoreState: target manager is not empty")
	}
	if s.DedupWindowNS < 0 {
		return fmt.Errorf("RestoreState: bad dedup window %d", s.DedupWindowNS)
	}
	if s.Seq < 0 {
		return fmt.Errorf("RestoreState: bad seq %d", s.Seq)
	}
	m.window = time.Duration(s.DedupWindowNS)
	m.seq = s.Seq
	m.alerts = make(map[string]*Alert, len(s.Alerts))
	for _, as := range s.Alerts {
		if as.ID == "" || as.RuleID == "" {
			return fmt.Errorf("RestoreState: alert missing id/rule: %+v", as)
		}
		if as.Status != StatusFiring && as.Status != StatusResolved {
			return fmt.Errorf("RestoreState: alert %s has unknown status %q", as.ID, as.Status)
		}
		if as.Hits < 1 || as.Suppressed < 0 || as.Suppressed >= as.Hits {
			return fmt.Errorf("RestoreState: alert %s has bad hits=%d suppressed=%d",
				as.ID, as.Hits, as.Suppressed)
		}
		key := as.RuleID + "|" + as.GroupKey
		if _, dup := m.alerts[key]; dup {
			return fmt.Errorf("RestoreState: duplicate alert for rule=%q group=%q",
				as.RuleID, as.GroupKey)
		}
		m.alerts[key] = &Alert{
			ID:         as.ID,
			RuleID:     as.RuleID,
			GroupKey:   as.GroupKey,
			Hits:       as.Hits,
			Suppressed: as.Suppressed,
			FirstSeen:  time.Unix(0, as.FirstSeen).UTC(),
			LastSeen:   time.Unix(0, as.LastSeen).UTC(),
			Status:     as.Status,
			Reason:     as.Reason,
		}
	}
	return nil
}

// PruneResolvedBefore 删除 LastSeen 早于 cutoff 的 resolved 告警，
// 返回删除条数。只清理已关闭的结论，firing 告警不由此删除，
// 避免保留策略悄悄丢掉仍在生效的告警。
func (m *Manager) PruneResolvedBefore(cutoff time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for key, a := range m.alerts {
		if a.Status == StatusResolved && a.LastSeen.Before(cutoff) {
			delete(m.alerts, key)
			removed++
		}
	}
	return removed
}

// StateBytes 返回当前告警状态 JSON 序列化后的字节数（容量估算用）。
func (m *Manager) StateBytes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := json.Marshal(alertStateForSize{Window: m.window, Alerts: m.alerts})
	if err != nil {
		// 本结构全部为可 JSON 序列化字段，理论上不会失败；失败按 0 处理。
		return 0
	}
	return len(b)
}

type alertStateForSize struct {
	Window time.Duration
	Alerts map[string]*Alert
}
