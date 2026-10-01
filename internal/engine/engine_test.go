package engine

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
)

var base = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

func bruteForceRule() rules.Rule {
	return rules.Rule{
		ID:        "R-BRUTE-FORCE",
		Version:   1,
		Window:    5 * time.Minute,
		Threshold: 3,
		GroupBy:   "source",
		Conditions: []rules.Condition{
			{Field: "action", Op: rules.OpEq, Value: "login_failed"},
		},
	}
}

func loginEvent(id string, min int, source string) Event {
	return Event{
		ID:        id,
		Timestamp: base.Add(time.Duration(min) * time.Minute),
		Source:    source,
		Fields:    map[string]string{"action": "login_failed"},
	}
}

func logMatches(t *testing.T, label string, ms []Match) {
	t.Helper()
	for _, m := range ms {
		t.Logf("[%s] match rule=%s group=%s count=%d window_end=%s events=%v",
			label, m.RuleID, m.GroupKey, m.Count,
			m.WindowEnd.Format(time.RFC3339), m.EventIDs)
	}
}

// 乱序与按序输入必须得到相同的命中序列。
func TestOutOfOrderEqualsInOrder(t *testing.T) {
	events := []Event{
		loginEvent("e1", 0, "web-1"),
		loginEvent("e2", 1, "web-1"),
		loginEvent("e3", 2, "web-1"),
		loginEvent("e4", 3, "web-1"),
		loginEvent("e5", 1, "web-2"),
		loginEvent("e6", 2, "web-2"),
	}

	run := func(evs []Event) []Match {
		c := NewCorrelator([]rules.Rule{bruteForceRule()}, 10*time.Minute)
		var all []Match
		for _, e := range evs {
			all = append(all, c.Ingest(e)...)
		}
		all = append(all, c.Flush()...) // 输入结束，闭合剩余窗口
		return all
	}

	inOrder := run(events)
	logMatches(t, "in-order", inOrder)

	// 多种随机乱序，结论都必须一致。
	for seed := int64(0); seed < 20; seed++ {
		shuffled := append([]Event(nil), events...)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		got := run(shuffled)
		if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", inOrder) {
			t.Fatalf("seed %d: out-of-order result differs\nin-order:  %v\nshuffled: %v", seed, inOrder, got)
		}
	}
	t.Logf("out-of-order (20 shuffles) matches in-order: %d matches", len(inOrder))
}

// 重复事件（同 ID）不能被计两次。
func TestDuplicateEventCountedOnce(t *testing.T) {
	c := NewCorrelator([]rules.Rule{bruteForceRule()}, 10*time.Minute)
	input := []Event{
		loginEvent("e1", 0, "web-1"),
		loginEvent("e1", 0, "web-1"), // 重复
		loginEvent("e2", 1, "web-1"),
		loginEvent("e2", 1, "web-1"), // 重复
		loginEvent("e3", 2, "web-1"),
	}
	var matches []Match
	for _, e := range input {
		t.Logf("ingest id=%s ts=%s source=%s", e.ID, e.Timestamp.Format(time.RFC3339), e.Source)
		matches = append(matches, c.Ingest(e)...)
	}
	matches = append(matches, c.Flush()...)
	logMatches(t, "dedup", matches)

	if len(matches) != 1 {
		t.Fatalf("want exactly 1 match (threshold 3 with 3 unique events), got %d", len(matches))
	}
	if matches[0].Count != 3 {
		t.Errorf("duplicate counted twice: match count=%d, want 3", matches[0].Count)
	}
	stats := c.Stats()
	t.Logf("stats: %+v", stats)
	if stats.Duplicates != 2 || stats.Ingested != 3 {
		t.Errorf("stats: want ingested=3 duplicates=2, got %+v", stats)
	}
}

// 迟到事件（早于水位线）必须被丢弃且计数。
func TestLateEventDropped(t *testing.T) {
	c := NewCorrelator([]rules.Rule{bruteForceRule()}, 5*time.Minute)
	// 先把水位线推进到 10:10 - 5m = 10:05。
	c.Ingest(loginEvent("e-max", 10, "web-1"))

	late := loginEvent("e-late", 3, "web-1") // 10:03 <= watermark 10:05
	t.Logf("ingest late event id=%s ts=%s (watermark=10:05)", late.ID, late.Timestamp.Format(time.RFC3339))
	if ms := c.Ingest(late); len(ms) != 0 {
		t.Fatalf("late event produced matches: %v", ms)
	}
	stats := c.Stats()
	t.Logf("stats after late event: %+v", stats)
	if stats.LateDropped != 1 {
		t.Errorf("want late_dropped=1, got %+v", stats)
	}
}

// 构造后修改规则切片不影响已创建的关联器（重新加载不改变已有判定）。
func TestReloadDoesNotAffectExistingCorrelator(t *testing.T) {
	ruleList := []rules.Rule{bruteForceRule()}
	c := NewCorrelator(ruleList, 10*time.Minute)

	// 模拟“重新加载”：把阈值改到 100，原关联器不应感知。
	ruleList[0].Threshold = 100

	var matches []Match
	for i := 0; i < 3; i++ {
		matches = append(matches, c.Ingest(loginEvent(fmt.Sprintf("e%d", i), i, "web-1"))...)
	}
	matches = append(matches, c.Flush()...)
	logMatches(t, "after-reload", matches)
	if len(matches) != 1 || matches[0].Count != 3 {
		t.Fatalf("existing correlator must still use threshold=3, got %v", matches)
	}
	t.Logf("decision basis: correlator holds its own copy of rules taken at construction")
}
