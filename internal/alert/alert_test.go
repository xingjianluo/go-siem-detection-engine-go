package alert

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
)

var base = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

func match(rule, group string, min int) engine.Match {
	return engine.Match{
		RuleID:    rule,
		GroupKey:  group,
		Count:     3,
		WindowEnd: base.Add(time.Duration(min) * time.Minute),
		EventIDs:  []string{"e1", "e2", "e3"},
	}
}

// 滑动窗口内反复命中要合并成一条带命中次数的告警，且注明抑制原因。
func TestDedupMergesHitsWithinWindow(t *testing.T) {
	m := NewManager(10 * time.Minute)

	a1, isNew := m.Record(match("R1", "web-1", 0), base)
	t.Logf("hit 1 -> alert=%s new=%v hits=%d reason=%q", a1.ID, isNew, a1.Hits, a1.Reason)
	if !isNew || a1.Hits != 1 {
		t.Fatalf("first hit must create alert with hits=1, got %+v", a1)
	}

	a2, isNew := m.Record(match("R1", "web-1", 3), base.Add(3*time.Minute))
	t.Logf("hit 2 -> alert=%s new=%v hits=%d suppressed=%d reason=%q",
		a2.ID, isNew, a2.Hits, a2.Suppressed, a2.Reason)
	if isNew {
		t.Fatal("hit within dedup window must not create a new alert")
	}
	if a2.ID != a1.ID || a2.Hits != 2 || a2.Suppressed != 1 {
		t.Fatalf("hit not merged: %+v", a2)
	}
	if a2.Reason == "" {
		t.Error("suppressed hit must carry a reason")
	}

	// 超出窗口后再命中，应产生新告警。
	a3, isNew := m.Record(match("R1", "web-1", 20), base.Add(20*time.Minute))
	t.Logf("hit 3 (after window) -> alert=%s new=%v hits=%d", a3.ID, isNew, a3.Hits)
	if !isNew || a3.ID == a1.ID {
		t.Fatalf("hit after dedup window must create a new alert, got %+v", a3)
	}
}

// 超期未命中的告警转为 resolved 并说明原因。
func TestExpireResolvesStaleAlerts(t *testing.T) {
	m := NewManager(10 * time.Minute)
	m.Record(match("R1", "web-1", 0), base)

	closed := m.Expire(base.Add(30 * time.Minute))
	if len(closed) != 1 {
		t.Fatalf("want 1 resolved alert, got %d", len(closed))
	}
	t.Logf("resolved: %s reason=%q", closed[0].ID, closed[0].Reason)
	if closed[0].Status != StatusResolved || closed[0].Reason == "" {
		t.Errorf("bad resolved alert: %+v", closed[0])
	}
}

// 多来源并发写入：计数不能丢失，不能有数据竞态（配合 -race）。
func TestConcurrentRecordNoRaceNoLoss(t *testing.T) {
	m := NewManager(time.Hour)
	const sources = 8
	const hitsPerSource = 500

	var wg sync.WaitGroup
	var newCount int64
	var mu sync.Mutex
	for s := 0; s < sources; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			for i := 0; i < hitsPerSource; i++ {
				// 所有 goroutine 命中同一 (rule, group)，应全部合并进一条告警。
				_, isNew := m.Record(match("R1", "web-1", 0), base)
				if isNew {
					mu.Lock()
					newCount++
					mu.Unlock()
				}
			}
		}(s)
	}
	wg.Wait()

	snap := m.Snapshot()
	t.Logf("after %d sources x %d hits: alerts=%d", sources, hitsPerSource, len(snap))
	for _, a := range snap {
		t.Logf("  alert=%s hits=%d suppressed=%d", a.ID, a.Hits, a.Suppressed)
	}
	if len(snap) != 1 {
		t.Fatalf("want exactly 1 alert, got %d", len(snap))
	}
	want := sources * hitsPerSource
	if snap[0].Hits != want {
		t.Fatalf("lost hits: want %d, got %d", want, snap[0].Hits)
	}
	if newCount != 1 {
		t.Fatalf("want exactly 1 new alert across goroutines, got %d", newCount)
	}
}

// 不同 group 的命中互不合并。
func TestDifferentGroupsAreSeparate(t *testing.T) {
	m := NewManager(10 * time.Minute)
	for i := 0; i < 3; i++ {
		g := fmt.Sprintf("web-%d", i)
		a, isNew := m.Record(match("R1", g, 0), base)
		t.Logf("group=%s -> alert=%s new=%v", g, a.ID, isNew)
		if !isNew {
			t.Fatalf("different groups must not merge: %v", a)
		}
	}
	if got := len(m.Snapshot()); got != 3 {
		t.Fatalf("want 3 alerts, got %d", got)
	}
}
