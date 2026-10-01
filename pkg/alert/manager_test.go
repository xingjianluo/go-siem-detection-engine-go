package alert

import (
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/model"
)

var base = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

func testRule(dedup time.Duration) *model.Rule {
	return &model.Rule{
		ID: "failed-ssh", Name: "Failed SSH", Severity: model.SeverityHigh,
		DedupWindow: dedup,
	}
}

func finding(ids []string, start time.Time) *model.Finding {
	return &model.Finding{
		RuleID:      "failed-ssh",
		WindowStart: start, WindowEnd: start.Add(time.Minute),
		EventIDs: ids, Count: len(ids), CreatedAt: base,
	}
}

func TestDedupMergesRepeatedFiresWithReason(t *testing.T) {
	m := NewManager(time.Minute)
	r := testRule(time.Minute)

	r1 := m.Submit(finding([]string{"a", "b", "c"}, base), r, base)
	if r1.Suppressed {
		t.Fatal("first fire must create a new alert")
	}
	r2 := m.Submit(finding([]string{"d", "e"}, base.Add(time.Minute)), r, base.Add(30*time.Second))
	if !r2.Suppressed || r2.Reason != model.SuppressDedupWindow {
		t.Fatalf("second fire must be suppressed with reason, got %+v", r2)
	}
	r3 := m.Submit(finding([]string{"a", "f"}, base.Add(2*time.Minute)), r, base.Add(50*time.Second))
	if !r3.Suppressed {
		t.Fatal("repeated fire within sliding window stays merged")
	}

	alerts := m.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("repeated hits must merge into ONE alert, got %d", len(alerts))
	}
	a := alerts[0]
	// 3 + 2 + 2, with duplicate "a" counted only once in the event list,
	// but Count sums raw window hits (a was in different windows).
	if a.Count != 7 {
		t.Errorf("hit count = %d, want 7", a.Count)
	}
	if len(a.EventIDs) != 6 {
		t.Errorf("unique event ids = %v (%d), want 6", a.EventIDs, len(a.EventIDs))
	}
	if a.Suppressed != model.SuppressDedupWindow {
		t.Errorf("alert should record suppression reason, got %q", a.Suppressed)
	}
	if !a.LastSeen.Equal(base.Add(50 * time.Second)) {
		t.Errorf("sliding lastSeen wrong: %v", a.LastSeen)
	}

	// Audit trail explains every suppressed fire.
	h := m.History()
	if len(h) != 3 || !h[1].Suppressed || h[1].Reason != model.SuppressDedupWindow {
		t.Fatalf("history must explain suppression: %+v", h)
	}
}

func TestResolveAfterSilenceAndReopen(t *testing.T) {
	m := NewManager(time.Minute)
	r := testRule(time.Minute)

	m.Submit(finding([]string{"a"}, base), r, base)
	resolved := m.Sweep(base.Add(60 * time.Second))
	if len(resolved) != 1 || !resolved[0].Resolved {
		t.Fatalf("expected one resolved alert, got %+v", resolved)
	}
	if len(m.ActiveAlerts()) != 0 {
		t.Fatal("no active alerts after sweep")
	}
	// A later fire opens a brand-new alert rather than resurrecting.
	r2 := m.Submit(finding([]string{"b"}, base.Add(2*time.Minute)), r, base.Add(2*time.Minute))
	if r2.Suppressed {
		t.Fatal("fire after resolution must create a new alert")
	}
	all := m.Alerts()
	if len(all) != 2 {
		t.Fatalf("expected resolved + new alert, got %d", len(all))
	}
}

func TestSweepUsesRuleDedupWindow(t *testing.T) {
	m := NewManager(time.Minute)
	r := testRule(5 * time.Minute)
	m.Submit(finding([]string{"a"}, base), r, base)
	if got := m.Sweep(base.Add(2 * time.Minute)); len(got) != 0 {
		t.Fatalf("rule-specific 5m window not elapsed, got %d resolved", len(got))
	}
	if got := m.Sweep(base.Add(5 * time.Minute)); len(got) != 1 {
		t.Fatalf("expected resolve at 5m, got %d", len(got))
	}
}
