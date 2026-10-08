package state

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
)

// 直接把事件按给定顺序喂给一条链路（模拟平时那条按文件顺序处理的链路），
// 返回命中摘要与告警摘要。
func runEventsThroughPipeline(evs []engine.Event) (string, string, engine.Stats) {
	p := newTestPipeline()
	var ms []engine.Match
	for _, e := range evs {
		ms = append(ms, p.IngestEvent(e).Matches...)
	}
	ms = append(ms, p.Flush().Matches...)
	return matchDigest(ms), alertDigest(p), p.Stats()
}

// 业务场景：历史回放走独立状态键，回放结论与“把事件直接按文件顺序交给
// 平时那条链路”的结论一致；并且回放完全不碰实时链路的现场。
func TestReplayParityAndIsolation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "history.jsonl")
	stateDir := filepath.Join(dir, "state")
	store, err := NewStore(stateDir, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	// checkpoint 的墙钟固定在事件当天，避免 72h 保留期把回放现场判过期。
	store.withClock(func() time.Time { return tBase.Add(time.Hour) })

	events := []engine.Event{
		evt("e1", 0, "web-1"),
		evt("e2", 1, "web-1"),
		evt("e3", 2, "web-1"), // 10:02 窗口 3 连击
		evt("e4", 1, "web-2"),
		evt("e5", 2, "web-2"),
		evt("e3", 2, "web-1"), // 重复
		evt("e6", 12, "web-1"),
		evt("e7", 1, "web-3"), // 迟到：watermark=02:00，01:00 被丢
		evt("e8", 3, "web-1"), // 迟到但在容忍内，应并入
	}
	lines := make([]string, len(events))
	for i, e := range events {
		lines[i] = evtLine(e)
	}
	writeLog(t, logPath, lines...)

	// 先给实时链路喂一点状态，待会验证回放不影响它。
	rt := newTestPipeline()
	rt.BindStore(store, RealtimeKey)
	rt.BindCursor(logPath)
	rtI := rt.IngestEvent(evt("rt-1", 0, "rt-host"))
	rtCp, err := rt.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	rtSnapshot := alertDigest(rt)
	t.Logf("[replay-scenario] realtime baseline: alerts={%s} bytes=%d ingest_new=%d",
		rtSnapshot, rtCp.Bytes, rtI.Stats.Ingested)

	// —— 历史回放：独立 key ——
	key := ReplayKey("incident-1008")
	rp := NewPipeline(Config{
		Rules:       []rules.Rule{testRule()},
		Lateness:    10 * time.Minute,
		DedupWindow: 10 * time.Minute,
	})
	rp.BindStore(store, key)
	rp.BindCursor(logPath)
	rr, err := Runner{}.RunFile(rp)
	if err != nil {
		t.Fatal(err)
	}
	fr := rp.Flush()
	if _, err := rp.Checkpoint(); err != nil { // 与 CLI 一致：回放结束落盘
		t.Fatal(err)
	}
	gotMatch := matchDigest(append(append([]engine.Match{}, rr.Matches...), fr.Matches...))
	gotAlert := alertDigest(rp)
	t.Logf("[replay-scenario] replay key=%s lines=%d dup=%d late=%d matches=%d alerts={%s}",
		key, rr.LinesRead, rr.Duplicates, rr.LateDropped,
		len(rr.Matches)+len(fr.Matches), gotAlert)

	// 期望：同样事件顺序直接喂给普通链路。
	wantMatch, wantAlert, wantStats := runEventsThroughPipeline(events)
	if gotMatch != wantMatch {
		t.Fatalf("replay matches != direct pipeline:\nreplay:   %s\ndirect:   %s", gotMatch, wantMatch)
	}
	if gotAlert != wantAlert {
		t.Fatalf("replay alerts != direct pipeline:\nreplay:   %s\ndirect:   %s", gotAlert, wantAlert)
	}
	if rr.Duplicates != wantStats.Duplicates || rr.LateDropped != wantStats.LateDropped {
		t.Fatalf("replay stats mismatch: replay=%+v direct=%+v", rr, wantStats)
	}
	t.Logf("[replay-scenario] parity OK: dup=%d late_dropped=%d identical matches & alerts",
		wantStats.Duplicates, wantStats.LateDropped)

	// 实时链路现场必须原封不动：文件存在、告警快照不变。
	rt2st, err := store.Load(RealtimeKey)
	if err != nil {
		t.Fatalf("realtime state disappeared after replay: %v", err)
	}
	rt2, err := RestorePipeline(rt2st, []rules.Rule{testRule()}, store, RealtimeKey)
	if err != nil {
		t.Fatal(err)
	}
	if alertDigest(rt2) != rtSnapshot {
		t.Fatalf("replay mutated realtime state:\nbefore: %s\nafter:  %s", rtSnapshot, alertDigest(rt2))
	}
	t.Logf("[replay-scenario] realtime state untouched after replay: alerts={%s}", rtSnapshot)

	// 两个状态文件物理上并存。
	if !store.Exists(RealtimeKey) || !store.Exists(key) {
		t.Fatal("both realtime and replay state files must coexist")
	}
	t.Logf("[replay-scenario] state files coexist: %s and %s", RealtimeKey, key)
}

// 业务场景：回放输入做多种随机乱序（同时保留重复/迟到事件）。
// 两件事都要成立：
//  1. 对每一种顺序，“走文件+游标+独立落盘的回放路径”的结论与
//     “把同一顺序的事件直接喂给内存链路”的结论完全一致；
//  2. 不同乱序之间命中与告警集合一致（沿用引擎既有的顺序无关语义，
//     回放层不改变它）。
func TestReplayOutOfOrderParity(t *testing.T) {
	dir := t.TempDir()
	// 与引擎既有 TestOutOfOrderEqualsInOrder 同款数据：事件时间跨度
	// 都在 lateness(10m) 之内，任意排列下“被接受事件集合”相同，
	// 因而结论顺序无关。重复事件也保留在内。
	events := []engine.Event{
		evt("e1", 0, "web-1"), evt("e2", 1, "web-1"),
		evt("e3", 2, "web-1"), evt("e4", 3, "web-1"),
		evt("e5", 1, "web-2"), evt("e6", 2, "web-2"),
		evt("e3", 2, "web-1"), // 重复
	}
	store, err := NewStore(filepath.Join(dir, "state"), DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	store.withClock(func() time.Time { return tBase.Add(time.Hour) })

	var canonical string
	for seed := int64(0); seed < 10; seed++ {
		shuffled := append([]engine.Event(nil), events...)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})

		// 直接喂内存链路（同顺序）作为该顺序的期望。
		wantMatch, wantAlert, _ := runEventsThroughPipeline(shuffled)

		logPath := filepath.Join(dir, fmt.Sprintf("shuf-%d.jsonl", seed))
		lines := make([]string, len(shuffled))
		for i, e := range shuffled {
			lines[i] = evtLine(e)
		}
		writeLog(t, logPath, lines...)

		key := ReplayKey(fmt.Sprintf("shuf-%d", seed))
		p := newTestPipeline()
		p.BindStore(store, key)
		p.BindCursor(logPath)
		rr, rerr := Runner{}.RunFile(p)
		if rerr != nil {
			t.Fatal(rerr)
		}
		fr := p.Flush()
		gotMatch := matchDigest(append(append([]engine.Match{}, rr.Matches...), fr.Matches...))
		gotAlert := alertDigest(p)
		if gotMatch != wantMatch || gotAlert != wantAlert {
			t.Fatalf("seed %d: replay path differs from direct pipeline (same order):\nmatch replay=%s\nmatch direct=%s\nalert replay=%s\nalert direct=%s",
				seed, gotMatch, wantMatch, gotAlert, wantAlert)
		}
		if canonical == "" {
			canonical = gotMatch + "||" + gotAlert
		} else if gotMatch+"||"+gotAlert != canonical {
			t.Fatalf("seed %d: shuffled replay conclusion differs from earlier shuffle (order-dependence introduced)", seed)
		}
	}
	t.Logf("[replay-shuffle-scenario] 10 shuffled replays match direct pipeline and each other: %s", canonical)
}

// 业务场景：用新规则回放必须显式走独立 key；恢复实时链路时规则变了，
// 要返回 ErrRulesChanged，不能悄悄用新规则改写既有判定。
func TestResumeRejectsChangedRules(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	store, err := NewStore(stateDir, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPipeline()
	p.BindStore(store, RealtimeKey)
	p.BindCursor(filepath.Join(dir, "x.jsonl"))
	p.IngestEvent(evt("e1", 0, "web-1"))
	if _, err := p.Checkpoint(); err != nil {
		t.Fatal(err)
	}

	changed := []rules.Rule{testRule()}
	changed[0].Threshold = 2 // 规则语义已变
	st, err := store.Load(RealtimeKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RestorePipeline(st, changed, store, RealtimeKey); err == nil {
		t.Fatal("resuming with changed rules must fail")
	} else if !errorIs(err, ErrRulesChanged) {
		t.Fatalf("want ErrRulesChanged, got %v", err)
	}
	t.Logf("[rules-changed-scenario] resume with changed rules rejected: %v", err)
}

func errorIs(err, target error) bool {
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

var _ = time.Second
