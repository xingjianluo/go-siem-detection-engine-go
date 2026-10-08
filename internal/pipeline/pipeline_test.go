package pipeline

import (
	"fmt"
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/alert"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/state"
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

func loginEvent(id string, min int, source string) engine.Event {
	return engine.Event{
		ID:        id,
		Timestamp: base.Add(time.Duration(min) * time.Minute),
		Source:    source,
		Fields:    map[string]string{"action": "login_failed"},
	}
}

// alertDigest 提取告警的对账摘要：忽略每次运行都会变化的告警 ID，
// 只比较业务结论（规则、分组、命中数、抑制数、状态、时间线）。
func alertDigest(as []alert.Alert) string {
	out := ""
	for _, a := range as {
		out += fmt.Sprintf("%s|%s|hits=%d|sup=%d|%s|first=%d|last=%d\n",
			a.RuleID, a.GroupKey, a.Hits, a.Suppressed, a.Status,
			a.FirstSeen.Unix(), a.LastSeen.Unix())
	}
	return out
}

func logAlerts(t *testing.T, label string, as []alert.Alert) {
	t.Helper()
	for _, a := range as {
		t.Logf("[%s] alert rule=%s group=%s hits=%d suppressed=%d status=%s",
			label, a.RuleID, a.GroupKey, a.Hits, a.Suppressed, a.Status)
	}
}

// 场景：本地运维跑了一批日志后进程重启，换批继续喂；
// 最终告警结论必须和“一口气跑完”完全一致。
func TestResumeAfterRestartEqualsSingleRun(t *testing.T) {
	rs := []rules.Rule{bruteForceRule()}
	batch1 := []engine.Event{
		loginEvent("e1", 0, "web-1"),
		loginEvent("e2", 1, "web-1"),
		loginEvent("e3", 2, "web-1"),
	}
	batch2 := []engine.Event{
		loginEvent("e4", 3, "web-1"),
		loginEvent("e5", 20, "web-1"), // 推进水位线，闭合前面窗口
	}

	// 基准：单进程一次跑完。
	dirRef := t.TempDir()
	ref, st, err := OpenLive(state.NewStore(dirRef, 3, time.Hour), rs, 10*time.Minute, 10*time.Minute)
	if err != nil || st != StatusNoState {
		t.Fatalf("open ref: status=%s err=%v", st, err)
	}
	if _, err := ref.IngestBatch(append(append([]engine.Event{}, batch1...), batch2...)); err != nil {
		t.Fatal(err)
	}
	if _, err := ref.Flush(); err != nil {
		t.Fatal(err)
	}
	want := alertDigest(ref.Alerts())
	logAlerts(t, "single-run", ref.Alerts())

	// 现场：跑完 batch1 落盘后“重启”，再喂 batch2。
	dir := t.TempDir()
	store := state.NewStore(dir, 3, time.Hour)
	p1, st1, err := OpenLive(store, rs, 10*time.Minute, 10*time.Minute)
	if err != nil || st1 != StatusNoState {
		t.Fatalf("first open: status=%s err=%v", st1, err)
	}
	if _, err := p1.IngestBatch(batch1); err != nil {
		t.Fatal(err)
	}
	t.Logf("第一批处理完：processed=%d，进程模拟重启", p1.Processed())

	p2, st2, err := OpenLive(store, rs, 10*time.Minute, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if st2 != StatusResumed {
		t.Fatalf("second open status = %s, want %s", st2, StatusResumed)
	}
	if p2.Processed() != int64(len(batch1)) {
		t.Fatalf("resumed processed = %d, want %d", p2.Processed(), len(batch1))
	}
	if _, err := p2.IngestBatch(batch2); err != nil {
		t.Fatal(err)
	}
	if _, err := p2.Flush(); err != nil {
		t.Fatal(err)
	}
	got := alertDigest(p2.Alerts())
	logAlerts(t, "resumed", p2.Alerts())
	if got != want {
		t.Fatalf("resumed run differs from single run\nwant:\n%s\ngot:\n%s", want, got)
	}
	t.Logf("重启续跑场景：分两批+中间重启的结论与单次运行一致（processed=%d）", p2.Processed())
}

// 场景：重启后上游把上一批已处理的事件重推了一遍，
// 不能重复计数，已有告警的命中/抑制结论不能被改乱。
func TestResumeThenRefedBatchDoesNotDoubleCount(t *testing.T) {
	rs := []rules.Rule{bruteForceRule()}
	store := state.NewStore(t.TempDir(), 3, time.Hour)
	batch := []engine.Event{
		loginEvent("e1", 0, "web-1"),
		loginEvent("e2", 1, "web-1"),
		loginEvent("e3", 2, "web-1"),
		loginEvent("e4", 20, "web-1"),
	}

	p1, _, _ := OpenLive(store, rs, 10*time.Minute, 10*time.Minute)
	if _, err := p1.IngestBatch(batch); err != nil {
		t.Fatal(err)
	}
	if _, err := p1.Flush(); err != nil {
		t.Fatal(err)
	}
	want := alertDigest(p1.Alerts())

	// 重启后整批重推。
	p2, st, _ := OpenLive(store, rs, 10*time.Minute, 10*time.Minute)
	if st != StatusResumed {
		t.Fatalf("status = %s, want resumed", st)
	}
	ms, err := p2.IngestBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 0 {
		t.Fatalf("re-fed batch produced %d matches, want 0", len(ms))
	}
	got := alertDigest(p2.Alerts())
	if got != want {
		t.Fatalf("alerts changed after re-feed\nbefore:\n%s\nafter:\n%s", want, got)
	}
	stats := p2.Stats()
	// 重推的事件要么命中去重表（duplicates），要么因早于水位线被
	// 迟到丢弃（late_dropped，去重表已按保留边界清理），
	// 两者都是“没被重新算一遍”，合计必须等于整批条数。
	if stats.Duplicates+stats.LateDropped != len(batch) {
		t.Fatalf("duplicates+late_dropped = %d, want %d",
			stats.Duplicates+stats.LateDropped, len(batch))
	}
	if stats.Ingested != len(batch) {
		t.Fatalf("ingested = %d, want %d (重推事件不应再被计入)", stats.Ingested, len(batch))
	}
	t.Logf("重推去重场景：重启后重推 %d 条已处理事件，告警结论不变；duplicates=%d late_dropped=%d，无一被重算",
		len(batch), stats.Duplicates, stats.LateDropped)
}

// 场景：回放对账——拿历史日志按当前规则独立重跑，
// 结论必须与实时链路一致；且回放不能动实时链路的落盘状态。
func TestReplayMatchesLiveAndDoesNotTouchState(t *testing.T) {
	rs := []rules.Rule{bruteForceRule()}
	// 含乱序、重复、迟到的历史日志。
	events := []engine.Event{
		loginEvent("e1", 0, "web-1"),
		loginEvent("e3", 2, "web-1"), // 乱序：e3 先于 e2 到达
		loginEvent("e2", 1, "web-1"),
		loginEvent("e2", 1, "web-1"), // 重复
		loginEvent("e4", 30, "web-1"),
		loginEvent("e5", 3, "web-1"), // 迟到（水位线已到 20m），被丢弃
	}

	store := state.NewStore(t.TempDir(), 3, time.Hour)
	live, _, err := OpenLive(store, rs, 10*time.Minute, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.IngestBatch(events); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Flush(); err != nil {
		t.Fatal(err)
	}
	want := alertDigest(live.Alerts())
	logAlerts(t, "live", live.Alerts())

	// 记录实时链路落盘现场，回放后必须原封不动。
	before, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}

	got := alertDigest(Replay(events, rs, 10*time.Minute, 10*time.Minute))
	if got != want {
		t.Fatalf("replay differs from live\nlive:\n%s\nreplay:\n%s", want, got)
	}

	after, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Processed != before.Processed {
		t.Fatalf("replay touched live state: processed %d -> %d", before.Processed, after.Processed)
	}
	t.Logf("回放对账场景：含乱序/重复/迟到的历史日志，回放结论与实时链路一致；落盘状态 processed=%d 未被干扰",
		after.Processed)
}

// 场景：规则换了之后重启，必须明确报告“配置变更”，
// 不能拿着旧规则攒下的状态按新规则硬跑，也不能静默从头开始。
func TestOpenLiveDetectsConfigChange(t *testing.T) {
	rs := []rules.Rule{bruteForceRule()}
	store := state.NewStore(t.TempDir(), 3, time.Hour)
	p1, _, _ := OpenLive(store, rs, 10*time.Minute, 10*time.Minute)
	if _, err := p1.IngestBatch([]engine.Event{loginEvent("e1", 0, "web-1")}); err != nil {
		t.Fatal(err)
	}

	// 规则变更：阈值 3 -> 5。
	changed := bruteForceRule()
	changed.Threshold = 5
	p2, st, err := OpenLive(store, []rules.Rule{changed}, 10*time.Minute, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if st != StatusConfigChanged || p2 != nil {
		t.Fatalf("status = %s pipeline=%v, want config_changed/nil", st, p2)
	}
	t.Log("规则变更场景：threshold 3->5 后打开链路，显式返回 config_changed，未静默沿用旧状态")

	// 参数变更：lateness 10m -> 5m。
	_, st2, err := OpenLive(store, rs, 5*time.Minute, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if st2 != StatusConfigChanged {
		t.Fatalf("lateness change: status = %s, want config_changed", st2)
	}
	t.Log("参数变更场景：lateness 10m->5m 后打开链路，同样显式返回 config_changed")
}

// 场景：状态文件损坏时打开链路，必须得到可区分的损坏状态，
// 而不是被当成首次运行。
func TestOpenLiveReportsCorruptedState(t *testing.T) {
	rs := []rules.Rule{bruteForceRule()}
	dir := t.TempDir()
	store := state.NewStore(dir, 3, time.Hour)
	p1, _, _ := OpenLive(store, rs, 10*time.Minute, 10*time.Minute)
	if _, err := p1.IngestBatch([]engine.Event{loginEvent("e1", 0, "web-1")}); err != nil {
		t.Fatal(err)
	}
	// 写坏状态文件。
	if err := corruptCheckpoint(dir); err != nil {
		t.Fatal(err)
	}
	p2, st, err := OpenLive(store, rs, 10*time.Minute, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if st != StatusCorrupted || p2 != nil {
		t.Fatalf("status = %s pipeline=%v, want corrupted/nil", st, p2)
	}
	t.Log("状态损坏场景：打开链路显式返回 corrupted，未被误判为首次运行")
}
