// Package alert implements alert deduplication with a sliding window and
// alert lifecycle management. All operations are safe for concurrent use.
//
// Semantics (the "now" parameter is the processing time, not event time):
//
//   - A fire for rule R creates an alert if no active alert for R exists.
//   - While now < activeAlert.lastSeen + dedupWindow, a later fire is
//     *suppressed* (reason dedup_window) and merged: hit count and lastSeen
//     advance and the dedup deadline slides forward. No new alert is created.
//   - Once the dedup window elapses without another fire, Sweep resolves the
//     alert. A fire after resolution opens a brand-new alert.
package alert

import (
	"sort"
	"sync"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/model"
)

// HistoryEntry records a fire and whether it created or was suppressed
// into an alert, giving suppressed alerts an explainable audit trail.
type HistoryEntry struct {
	RuleID     string
	At         time.Time
	Suppressed bool
	Reason     model.SuppressReason
	AlertKey   string
	Count      int
}

// Manager holds active and resolved alerts and applies dedup semantics.
type Manager struct {
	mu           sync.Mutex
	dedupDefault time.Duration
	active       map[string]*model.Alert
	resolved     map[string]*model.Alert
	dedupWindow  map[string]time.Duration // per-alert effective dedup window
	history      []HistoryEntry
}

// NewManager creates an alert Manager with the given default dedup window.
func NewManager(defaultDedup time.Duration) *Manager {
	if defaultDedup <= 0 {
		defaultDedup = 5 * time.Minute
	}
	return &Manager{
		dedupDefault: defaultDedup,
		active:       map[string]*model.Alert{},
		resolved:     map[string]*model.Alert{},
		dedupWindow:  map[string]time.Duration{},
	}
}

// AlertKey is the dedup identity of an alert. All rules are single-group;
// identity is therefore the rule ID.
func AlertKey(ruleID string) string { return "rule:" + ruleID }

// SubmitResult describes what happened when a finding was submitted.
type SubmitResult struct {
	Alert      *model.Alert
	Suppressed bool
	Reason     model.SuppressReason
}

// Submit applies a fired finding: either creating a new alert, merging it
// into an existing one (dedup), or leaving a resolved alert untouched.
// now is processing time.
func (m *Manager) Submit(f *model.Finding, r *model.Rule, now time.Time) SubmitResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := AlertKey(r.ID)
	dedup := r.DedupWindow
	if dedup <= 0 {
		dedup = m.dedupDefault
	}

	a, ok := m.active[key]
	if !ok {
		a = &model.Alert{
			Key:         key,
			RuleID:      r.ID,
			Severity:    r.Severity,
			Title:       r.Name,
			Count:       f.Count,
			FirstSeen:   now,
			LastSeen:    now,
			WindowStart: f.WindowStart,
			WindowEnd:   f.WindowEnd,
			EventIDs:    append([]string(nil), f.EventIDs...),
			UpdatedAt:   now,
		}
		m.active[key] = a
		m.dedupWindow[key] = dedup
		m.history = append(m.history, HistoryEntry{
			RuleID: r.ID, At: now, AlertKey: key, Count: f.Count,
		})
		return SubmitResult{Alert: a}
	}

	// Active alert inside its dedup window: merge and suppress.
	a.Count += f.Count
	a.LastSeen = now
	a.WindowEnd = f.WindowEnd
	a.EventIDs = mergeIDs(a.EventIDs, f.EventIDs)
	a.Suppressed = model.SuppressDedupWindow
	a.UpdatedAt = now
	m.history = append(m.history, HistoryEntry{
		RuleID: r.ID, At: now, Suppressed: true,
		Reason: model.SuppressDedupWindow, AlertKey: key, Count: f.Count,
	})
	return SubmitResult{Alert: a, Suppressed: true, Reason: model.SuppressDedupWindow}
}

// Sweep resolves every active alert whose sliding dedup window has elapsed
// at processing time now. Returns the resolved alerts.
func (m *Manager) Sweep(now time.Time) []*model.Alert {
	m.mu.Lock()
	defer m.mu.Unlock()

	var resolved []*model.Alert
	for key, a := range m.active {
		if now.Sub(a.LastSeen) >= m.dedupWindow[key] {
			a.Resolved = true
			a.Suppressed = model.SuppressNone
			a.UpdatedAt = now
			m.resolved[key] = a
			delete(m.active, key)
			delete(m.dedupWindow, key)
			resolved = append(resolved, a)
		}
	}
	sortAlerts(resolved)
	return resolved
}

// Alerts returns a snapshot of all alerts (active and resolved) ordered by
// first-seen time, then rule ID, for deterministic output.
func (m *Manager) Alerts() []*model.Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*model.Alert, 0, len(m.active)+len(m.resolved))
	for _, a := range m.active {
		out = append(out, cloneAlert(a))
	}
	for _, a := range m.resolved {
		out = append(out, cloneAlert(a))
	}
	sortAlerts(out)
	return out
}

// ActiveAlerts returns only unresolved alerts.
func (m *Manager) ActiveAlerts() []*model.Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*model.Alert, 0, len(m.active))
	for _, a := range m.active {
		out = append(out, cloneAlert(a))
	}
	sortAlerts(out)
	return out
}

// History returns a copy of the fire/merge audit trail in arrival order.
func (m *Manager) History() []HistoryEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HistoryEntry, len(m.history))
	copy(out, m.history)
	return out
}

func mergeIDs(existing, extra []string) []string {
	seen := make(map[string]struct{}, len(existing))
	for _, id := range existing {
		seen[id] = struct{}{}
	}
	merged := append([]string(nil), existing...)
	for _, id := range extra {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		merged = append(merged, id)
	}
	sort.Strings(merged)
	return merged
}

func sortAlerts(as []*model.Alert) {
	sort.Slice(as, func(i, j int) bool {
		if !as[i].FirstSeen.Equal(as[j].FirstSeen) {
			return as[i].FirstSeen.Before(as[j].FirstSeen)
		}
		return as[i].RuleID < as[j].RuleID
	})
}

func cloneAlert(a *model.Alert) *model.Alert {
	c := *a
	c.EventIDs = append([]string(nil), a.EventIDs...)
	return &c
}
