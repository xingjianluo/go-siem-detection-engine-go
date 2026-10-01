// Package alert 实现告警去重与生命周期管理。
//
// 语义约定：
//   - 去重键为 (RuleID, GroupKey)；
//   - 同一去重键在滑动窗口（自上次命中起算）内再次命中时，不新建告警，
//     而是合并进已有告警：Hits+1、Suppressed+1，并在 Reason 中说明
//     本次命中被抑制（未产生新告警）的原因；
//   - 超过窗口未再命中的告警可通过 Expire 转为 resolved；
//   - 所有方法并发安全，多来源并发写入不会竞态或丢失计数。
package alert

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
)

// Status 是告警生命周期状态。
type Status string

const (
	StatusFiring   Status = "firing"
	StatusResolved Status = "resolved"
)

// Alert 是一条告警。
type Alert struct {
	ID         string
	RuleID     string
	GroupKey   string
	Hits       int // 窗口内累计命中次数（含首次）
	Suppressed int // 被去重抑制、未单独成告警的命中次数
	FirstSeen  time.Time
	LastSeen   time.Time
	Status     Status
	Reason     string // 最近一次抑制/状态变化的原因说明
}

// Manager 管理告警的去重与生命周期，并发安全。
type Manager struct {
	mu     sync.Mutex
	window time.Duration
	alerts map[string]*Alert // 去重键 -> 告警
}

// NewManager 创建告警管理器，window 为去重滑动窗口。
func NewManager(window time.Duration) *Manager {
	return &Manager{window: window, alerts: map[string]*Alert{}}
}

func dedupKey(m engine.Match) string { return m.RuleID + "|" + m.GroupKey }

// Record 记录一次规则命中，返回更新后的告警快照与是否为新告警。
// 窗口内的重复命中会合并到已有告警并注明抑制原因。
func (m *Manager) Record(match engine.Match, now time.Time) (Alert, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := dedupKey(match)
	if a, ok := m.alerts[key]; ok && a.Status == StatusFiring && now.Sub(a.LastSeen) <= m.window {
		a.Hits++
		a.Suppressed++
		a.LastSeen = now
		a.Reason = fmt.Sprintf("hit suppressed: same rule+group fired %s ago (<= dedup window %s), merged into alert %s",
			now.Sub(a.FirstSeen).Round(time.Millisecond), m.window, a.ID)
		return *a, false
	}

	a := &Alert{
		ID:        fmt.Sprintf("%s-%d", key, now.UnixNano()),
		RuleID:    match.RuleID,
		GroupKey:  match.GroupKey,
		Hits:      1,
		FirstSeen: now,
		LastSeen:  now,
		Status:    StatusFiring,
		Reason:    "new alert: first hit in dedup window",
	}
	m.alerts[key] = a
	return *a, true
}

// Expire 把超过去重窗口未再命中的 firing 告警标记为 resolved，
// 返回本次被关闭的告警快照。
func (m *Manager) Expire(now time.Time) []Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	var closed []Alert
	for _, a := range m.alerts {
		if a.Status == StatusFiring && now.Sub(a.LastSeen) > m.window {
			a.Status = StatusResolved
			a.Reason = fmt.Sprintf("resolved: no hit for %s (> dedup window %s)",
				now.Sub(a.LastSeen).Round(time.Millisecond), m.window)
			closed = append(closed, *a)
		}
	}
	return closed
}

// Snapshot 返回当前所有告警的副本（按 ID 排序，保证输出稳定）。
func (m *Manager) Snapshot() []Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Alert, 0, len(m.alerts))
	for _, a := range m.alerts {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
