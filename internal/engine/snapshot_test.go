package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
)

// 场景：进程跑到一半重启，从快照恢复后继续喂后续事件，
// 最终命中与统计必须和“一口气跑完”完全一致。
func TestSnapshotRestoreEqualsUninterrupted(t *testing.T) {
	rule := bruteForceRule()
	events := []Event{
		loginEvent("e1", 0, "web-1"),
		loginEvent("e2", 1, "web-1"),
		loginEvent("e3", 2, "web-1"),
		loginEvent("e4", 3, "web-1"),
		loginEvent("e5", 20, "web-1"), // 推进水位线，闭合前面的窗口
		loginEvent("e6", 21, "web-2"),
		loginEvent("e7", 22, "web-2"),
		loginEvent("e8", 23, "web-2"),
	}

	run := func(split int) ([]Match, Stats) {
		c := NewCorrelator([]rules.Rule{rule}, 10*time.Minute)
		var all []Match
		for _, e := range events[:split] {
			all = append(all, c.Ingest(e)...)
		}
		if split < len(events) {
			// 模拟重启：导出快照，恢复成全新实例继续跑。
			snap := c.Snapshot()
			var err error
			c, err = RestoreSnapshot(snap, []rules.Rule{rule}, 10*time.Minute)
			if err != nil {
				t.Fatalf("restore: %v", err)
			}
		}
		for _, e := range events[split:] {
			all = append(all, c.Ingest(e)...)
		}
		all = append(all, c.Flush()...)
		return all, c.Stats()
	}

	want, wantStats := run(len(events)) // 不重启的基准
	logMatches(t, "uninterrupted", want)
	for _, split := range []int{1, 3, 5, 7} {
		got, gotStats := run(split)
		if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
			t.Fatalf("split=%d: restored run differs\nwant: %v\ngot:  %v", split, want, got)
		}
		if gotStats != wantStats {
			t.Fatalf("split=%d: stats = %+v, want %+v", split, gotStats, wantStats)
		}
		t.Logf("重启续跑场景：在第 %d 条事件后快照重启，命中与统计和不间断运行一致", split)
	}
}

// 场景：重启后上游把已经处理过的事件又推了一遍，
// 必须按 ID 去重，不能重复计数、不能重复产出命中。
func TestRestoreThenRefedProcessedEvents(t *testing.T) {
	rule := bruteForceRule()
	c := NewCorrelator([]rules.Rule{rule}, 10*time.Minute)
	batch := []Event{
		loginEvent("e1", 0, "web-1"),
		loginEvent("e2", 1, "web-1"),
		loginEvent("e3", 2, "web-1"),
	}
	for _, e := range batch {
		c.Ingest(e)
	}
	snap := c.Snapshot()
	statsBefore := c.Stats()

	c2, err := RestoreSnapshot(snap, []rules.Rule{rule}, 10*time.Minute)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, e := range batch { // 重推同一批
		if ms := c2.Ingest(e); len(ms) != 0 {
			t.Fatalf("re-fed event %s produced matches: %v", e.ID, ms)
		}
	}
	st := c2.Stats()
	if st.Ingested != statsBefore.Ingested {
		t.Fatalf("re-fed events were re-ingested: %+v vs %+v", st, statsBefore)
	}
	if st.Duplicates != len(batch) {
		t.Fatalf("duplicates = %d, want %d", st.Duplicates, len(batch))
	}
	t.Logf("重复推送场景：重启后重推 %d 条已处理事件，全部按 ID 去重，未重复计数", len(batch))
}

// 场景：重启后迟到的旧事件（超出水位线宽限）照旧被丢弃，
// 容忍范围内的乱序事件照旧并入。
func TestRestoreKeepsLatenessSemantics(t *testing.T) {
	rule := bruteForceRule()
	c := NewCorrelator([]rules.Rule{rule}, 10*time.Minute)
	c.Ingest(loginEvent("e1", 0, "web-1"))
	c.Ingest(loginEvent("e2", 30, "web-1")) // 水位线推进到 20m
	snap := c.Snapshot()

	c2, err := RestoreSnapshot(snap, []rules.Rule{rule}, 10*time.Minute)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	// 超出宽限（5m <= 水位线 20m）：丢弃。
	c2.Ingest(loginEvent("e3", 5, "web-1"))
	// 宽限内（25m > 水位线 20m）：并入。
	c2.Ingest(loginEvent("e4", 25, "web-1"))
	st := c2.Stats()
	if st.LateDropped != 1 {
		t.Fatalf("late dropped = %d, want 1", st.LateDropped)
	}
	if st.Ingested != 3 {
		t.Fatalf("ingested = %d, want 3", st.Ingested)
	}
	t.Log("迟到语义场景：恢复后超宽限事件被丢弃、宽限内事件正常并入，水位线语义不变")
}

// 场景：水位线宽限参数与落盘时不一致，必须显式报错而不是
// 拿着旧状态按新参数硬跑。
func TestRestoreRejectsLatenessMismatch(t *testing.T) {
	c := NewCorrelator([]rules.Rule{bruteForceRule()}, 10*time.Minute)
	c.Ingest(loginEvent("e1", 0, "web-1"))
	snap := c.Snapshot()
	if _, err := RestoreSnapshot(snap, []rules.Rule{bruteForceRule()}, 5*time.Minute); err == nil {
		t.Fatal("want error for lateness mismatch, got nil")
	}
	t.Log("参数变更场景：lateness 10m->5m 恢复快照被显式拒绝")
}
