package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
)

// 业务场景：跑到一半做快照，用快照重建关联器，后续结论必须与不中断一致；
// 重启后重复喂旧事件只能增加 duplicates 计数，不能改乱命中。
func TestSnapshotRestoreContinuesIndistinguishably(t *testing.T) {
	run := func(splitAfter int) ([]Match, Stats, Stats) {
		c := NewCorrelator([]rules.Rule{bruteForceRule()}, 10*time.Minute)
		events := []Event{
			loginEvent("e1", 0, "web-1"),
			loginEvent("e2", 1, "web-1"),
			loginEvent("e3", 2, "web-1"), // 窗口在更晚事件到达后闭合
			loginEvent("e4", 12, "web-1"),
			loginEvent("e5", 13, "web-1"),
		}
		var all []Match
		for i, e := range events {
			all = append(all, c.Ingest(e)...)
			if i == splitAfter {
				t.Logf("[restore-scenario] checkpoint after event %s at %s, seen=%d buffers=%d emitted=%d",
					e.ID, e.Timestamp.Format(time.RFC3339),
					len(c.seenIDs), len(c.buffers), len(c.emitted))
				st := c.SnapshotState()
				c2 := NewCorrelator(nil, 0)
				if err := c2.RestoreState(st); err != nil {
					t.Fatalf("restore: %v", err)
				}
				c = c2 // 模拟“进程重启”，后续事件喂给恢复出来的实例
			}
		}
		all = append(all, c.Flush()...)
		return all, c.Stats(), Stats{}
	}

	var ref []Match
	{
		c := NewCorrelator([]rules.Rule{bruteForceRule()}, 10*time.Minute)
		events := []Event{
			loginEvent("e1", 0, "web-1"),
			loginEvent("e2", 1, "web-1"),
			loginEvent("e3", 2, "web-1"),
			loginEvent("e4", 12, "web-1"),
			loginEvent("e5", 13, "web-1"),
		}
		for _, e := range events {
			ref = append(ref, c.Ingest(e)...)
		}
		ref = append(ref, c.Flush()...)
	}

	for _, split := range []int{0, 1, 2, 3, 4} {
		got, stats, _ := run(split)
		t.Logf("[restore-scenario] split after event #%d: ref matches=%d restored matches=%d stats=%+v",
			split, len(ref), len(got), stats)
		if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", ref) {
			t.Fatalf("split=%d mismatch:\nref %v\ngot %v", split, ref, got)
		}
	}
}

// 业务场景：重启后重复喂入已处理事件，它们必须全部被判为 duplicate，
// 且不产生任何新命中（命中次数/抑制结论由上层保持不变）。
func TestRestoredCorrelatorRejectsRefedOldEvents(t *testing.T) {
	c := NewCorrelator([]rules.Rule{bruteForceRule()}, 10*time.Minute)
	first := []Event{
		loginEvent("e1", 0, "web-1"),
		loginEvent("e2", 1, "web-1"),
		loginEvent("e3", 2, "web-1"),
		loginEvent("e4", 12, "web-1"),
	}
	var before []Match
	for _, e := range first {
		before = append(before, c.Ingest(e)...)
	}

	c2 := NewCorrelator(nil, 0)
	if err := c2.RestoreState(c.SnapshotState()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	t.Logf("[restart-dedup-scenario] restored, re-feeding %d already-processed events", len(first))
	for _, e := range first {
		if ms := c2.Ingest(e); len(ms) != 0 {
			t.Fatalf("old event %s produced matches after restart: %v", e.ID, ms)
		}
	}
	st := c2.Stats()
	if st.Duplicates != 4 || st.Ingested != 0 {
		t.Fatalf("re-fed old events must all be duplicates, got %+v", st)
	}
	t.Logf("[restart-dedup-scenario] duplicates=%d ingested=%d: no conclusion changed", st.Duplicates, st.Ingested)

	// 容忍范围内的迟到事件（事件时间 > watermark）重启后依旧能正确并入。
	lateOK := loginEvent("e6", 5, "web-1") // watermark = 12-10 = 02:00；05:00 仍可接受
	t.Logf("[restart-late-scenario] feeding within-tolerance late event %s ts=%s",
		lateOK.ID, lateOK.Timestamp.Format(time.RFC3339))
	c2.Ingest(lateOK)
	if got := c2.Stats(); got.LateDropped != 0 || got.Ingested != 1 {
		t.Fatalf("within-tolerance late event must be accepted, got %+v", got)
	}
	// 超出容忍的迟到事件仍然丢弃。
	lateBad := loginEvent("e7", 1, "web-2")
	c2.Ingest(lateBad)
	if got := c2.Stats(); got.LateDropped != 1 {
		t.Fatalf("out-of-tolerance late event must be dropped, got %+v", got)
	}
	t.Logf("[restart-late-scenario] accepted within-lateness, dropped beyond-lateness: stats=%+v", c2.Stats())
}

// 业务场景：保留边界之外的判定状态被裁掉，但边界内的窗口结论不受影响。
func TestRetainHorizonPrunesOnlyOldState(t *testing.T) {
	c := NewCorrelator([]rules.Rule{bruteForceRule()}, 10*time.Minute)
	for i := 0; i < 14; i++ {
		c.Ingest(loginEvent(fmt.Sprintf("e%02d", i), i, "web-1"))
	}
	t.Logf("[retain-scenario] before retain: seen=%d buffers=%d emitted=%d",
		len(c.seenIDs), totalBufLen(c), len(c.emitted))

	// 只保留 10:08 之后的状态。
	kept := c.RetainHorizon(base.Add(8 * time.Minute))
	t.Logf("[retain-scenario] after retain horizon=10:08: seen=%d buffers=%d emitted=%d",
		kept, totalBufLen(c), len(c.emitted))
	for id, ts := range c.seenIDs {
		if !ts.After(base.Add(8 * time.Minute)) {
			t.Fatalf("old id %s ts=%s survived retain", id, ts.Format(time.RFC3339))
		}
	}

	// 裁剪后新事件照常工作，迟到判定仍成立。
	if ms := c.Ingest(loginEvent("e-old", 7, "web-1")); len(ms) != 0 {
		t.Fatalf("event at pruned side must not re-trigger matches: %v", ms)
	}
	c.Ingest(loginEvent("e-new", 15, "web-1"))
}

func totalBufLen(c *Correlator) int {
	n := 0
	for _, b := range c.buffers {
		n += len(b)
	}
	return n
}

// 业务场景：往非空实例恢复 / 恢复坏快照必须被拒绝，不能静默混用两个现场。
func TestRestoreRejectsDirtyOrInvalid(t *testing.T) {
	c := NewCorrelator([]rules.Rule{bruteForceRule()}, time.Minute)
	c.Ingest(loginEvent("e1", 0, "web-1"))
	if err := c.RestoreState(SnapshotOfFresh()); err == nil {
		t.Fatal("restore into non-empty correlator must fail")
	}
	t.Logf("[restore-guard-scenario] restore into dirty instance rejected")

	bad := SnapshotOfFresh()
	bad.SeenIDs[""] = 1
	if err := NewCorrelator(nil, 0).RestoreState(bad); err == nil {
		t.Fatal("empty event id in snapshot must be rejected")
	}
	t.Logf("[restore-guard-scenario] corrupt snapshot (empty id) rejected")
}

func SnapshotOfFresh() State {
	return NewCorrelator([]rules.Rule{bruteForceRule()}, time.Minute).SnapshotState()
}
