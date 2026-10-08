package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
)

var tBase = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

func testRule() rules.Rule {
	return rules.Rule{
		ID:        "R-BRUTE",
		Version:   1,
		Window:    5 * time.Minute,
		Threshold: 3,
		GroupBy:   "source",
		Conditions: []rules.Condition{
			{Field: "action", Op: rules.OpEq, Value: "login_failed"},
		},
	}
}

func evt(id string, min int, source string) engine.Event {
	return engine.Event{
		ID:        id,
		Timestamp: tBase.Add(time.Duration(min) * time.Minute),
		Source:    source,
		Fields:    map[string]string{"action": "login_failed"},
	}
}

func evtLine(e engine.Event) string {
	return fmt.Sprintf(`{"id":%q,"timestamp":%q,"source":%q,"fields":{"action":"login_failed"}}`,
		e.ID, e.Timestamp.Format(time.RFC3339Nano), e.Source)
}

func writeLog(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestPipeline() *Pipeline {
	return NewPipeline(Config{
		Rules:       []rules.Rule{testRule()},
		Lateness:    10 * time.Minute,
		DedupWindow: 10 * time.Minute,
	})
}

// alertDigest 产出只取决于事件集合的对账摘要（不含墙钟/ID 形式差异）。
func alertDigest(p *Pipeline) string {
	var b strings.Builder
	for _, a := range p.Alerts() {
		fmt.Fprintf(&b, "%s|%s|hits=%d|sup=%d|first=%s|last=%s|status=%s;",
			a.RuleID, a.GroupKey, a.Hits, a.Suppressed,
			a.FirstSeen.Format(time.RFC3339), a.LastSeen.Format(time.RFC3339), a.Status)
	}
	return b.String()
}

func matchDigest(ms []engine.Match) string {
	var b strings.Builder
	for _, m := range ms {
		fmt.Fprintf(&b, "%s|%s|%d|%s|%v;", m.RuleID, m.GroupKey, m.Count,
			m.WindowEnd.Format(time.RFC3339), m.EventIDs)
	}
	return b.String()
}

// 业务场景：处理到中途落盘 -> 模拟进程重启 -> 从偏移继续追加处理，
// 最终命中、告警 hits/suppressed、统计与一口气跑完全程一致；
// 重启后游标不会重读旧行，重复喂旧行也全部被去重挡住。
func TestRestartResumeContinuesFromCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	stateDir := filepath.Join(dir, "state")
	store, err := NewStore(stateDir, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}

	batch1 := []engine.Event{
		evt("e1", 0, "web-1"), evt("e2", 1, "web-1"),
		evt("e3", 2, "web-1"), evt("e4", 12, "web-1"),
	}
	writeLog(t, logPath) // 先建空文件
	if err := os.WriteFile(logPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	// —— 第一段进程 ——
	p := newTestPipeline()
	p.BindStore(store, RealtimeKey)
	p.BindCursor(logPath)
	writeLog(t, logPath, evtLine(batch1[0]), evtLine(batch1[1]), evtLine(batch1[2]), evtLine(batch1[3]))
	r1 := Runner{}.RunFile
	_ = r1
	rr, err := Runner{}.RunFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := p.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[resume-scenario] process1: lines=%d new=%d merged=%d checkpoint_bytes=%d offset=%d",
		rr.LinesRead, rr.NewAlerts, rr.MergedHits, cp.Bytes, p.Cursor().Offset())
	if rr.LinesRead != 4 {
		t.Fatalf("want 4 lines read, got %d", rr.LinesRead)
	}

	// 模拟“重启后又喂了一遍已处理事件 + 文件在原位没增长”：
	// 不允许整段重算——这里直接恢复并再跑一次 RunFile，应当 0 新行。
	st, err := store.Load(RealtimeKey)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := RestorePipeline(st, []rules.Rule{testRule()}, store, RealtimeKey)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := Runner{}.RunFile(p2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[resume-scenario] process2 with no growth: lines=%d ingested=%d dup=%d",
		empty.LinesRead, empty.Ingested, empty.Duplicates)
	if empty.LinesRead != 0 || empty.Ingested != 0 {
		t.Fatalf("no new bytes => no new processing, got %+v", empty)
	}

	// 文件追加了新一批（含一个重复 ID、一个容忍范围内迟到事件）。
	batch2 := []engine.Event{
		evt("e2", 1, "web-1"),  // 重复
		evt("e5", 13, "web-1"), // 推进水位线到 03:00
		evt("e6", 4, "web-1"),  // 迟到但 > watermark 03:00，应并入
		evt("e7", 14, "web-1"), // 正常新事件
	}
	var allLines []string
	for _, e := range append(append([]engine.Event{}, batch1...), batch2...) {
		allLines = append(allLines, evtLine(e))
	}
	writeLog(t, logPath, allLines...)
	rr2, err := Runner{}.RunFile(p2)
	if err != nil {
		t.Fatal(err)
	}
	fr, _, err := Runner{}.FinishAndCheckpoint(p2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[resume-scenario] process2 after append: lines=%d dup=%d ingested=%d late_dropped=%d flush_matches=%d alerts=%s",
		rr2.LinesRead, rr2.Duplicates, rr2.Ingested, rr2.LateDropped, len(fr.Matches), alertDigest(p2))
	if rr2.LinesRead != 4 {
		t.Fatalf("only the 4 appended lines should be read, got %d", rr2.LinesRead)
	}
	if rr2.Duplicates != 1 {
		t.Fatalf("repeated e2 must be counted duplicate, got %+v", rr2)
	}

	// 对照组：把全部 8 行从头交给一条全新链路（顺序相同），收集全程命中。
	ref := newTestPipeline()
	ref.BindCursor(logPath)
	refRes, err := Runner{}.RunFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	refFlush := ref.Flush()
	refAll := append(append([]engine.Match{}, refRes.Matches...), refFlush.Matches...)
	t.Logf("[resume-scenario] reference one-shot: lines=%d dup=%d ingested=%d matches=%d alerts=%s",
		refRes.LinesRead, refRes.Duplicates, refRes.Ingested, len(refAll), alertDigest(ref))

	if alertDigest(p2) != alertDigest(ref) {
		t.Fatalf("alert conclusions differ across restart:\nresumed: %s\nreference: %s",
			alertDigest(p2), alertDigest(ref))
	}

	// 命中对账：第一段进程已经产出并落盘为 emitted 标记的命中不能重复产出；
	// 第二段新产出的命中必须恰好等于“全程命中减去第一段已产出命中”。
	phase1 := rr.Matches // 进程1 已产出（Checkpoint 前 Ingest 返回）的命中
	wantPhase2 := subtractMatches(refAll, phase1)
	gotPhase2 := append(append([]engine.Match{}, rr2.Matches...), fr.Matches...)
	if matchDigest(gotPhase2) != matchDigest(wantPhase2) {
		t.Fatalf("phase-2 matches differ:\nresumed: %s\nreference\\phase1: %s",
			matchDigest(gotPhase2), matchDigest(wantPhase2))
	}
	t.Logf("[resume-scenario] match reconciliation ok: phase1=%d phase2=%d (no double emission, no loss)",
		len(phase1), len(gotPhase2))
}

// matchKey 唯一标识一次命中（同一 rule/group/窗口右端只产出一次）。
func matchKey(m engine.Match) string {
	return fmt.Sprintf("%s|%s|%s", m.RuleID, m.GroupKey, m.WindowEnd.Format(time.RFC3339Nano))
}

// subtractMatches 返回 all 中去掉 phase1 已包含的命中（按命中键去重）。
func subtractMatches(all, phase1 []engine.Match) []engine.Match {
	seen := map[string]bool{}
	for _, m := range phase1 {
		seen[matchKey(m)] = true
	}
	var out []engine.Match
	for _, m := range all {
		if !seen[matchKey(m)] {
			out = append(out, m)
		}
	}
	return out
}

// 业务场景：日志文件在重启后被截断/轮转（比保存的偏移短），必须明确报错，
// 不能悄悄从头开始把旧事件重算一遍。
func TestCursorDetectsTruncatedLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	writeLog(t, logPath, evtLine(evt("e1", 0, "web-1")), evtLine(evt("e2", 1, "web-1")))

	c := NewCursor(logPath)
	if err := c.ReadLines(func(offset int64, line []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	saved := c.State()
	t.Logf("[truncate-scenario] saved offset=%d size=%d", saved.Offset, saved.Size)

	// 文件被轮转成更短的新文件。
	writeLog(t, logPath, evtLine(evt("n1", 0, "web-1")))
	c2 := NewCursor(logPath)
	err := c2.Restore(saved)
	if !errors.Is(err, ErrProgressTruncated) {
		t.Fatalf("want ErrProgressTruncated, got %v", err)
	}
	t.Logf("[truncate-scenario] truncation detected and rejected: %v", err)
}

// 业务场景：写了一半的最后一行（无换行）不能被当成坏事件处理，
// 等文件追加完成后同一行应能完整读到。
func TestCursorWaitsForPartialLastLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	full := evtLine(evt("e1", 0, "web-1"))
	if err := os.WriteFile(logPath, []byte(full[:len(full)-5]), 0o600); err != nil {
		t.Fatal(err) // 半行且无换行
	}
	c := NewCursor(logPath)
	var saw int
	if err := c.ReadLines(func(offset int64, line []byte) error { saw++; return nil }); err != nil {
		t.Fatal(err)
	}
	if saw != 0 || c.Offset() != 0 {
		t.Fatalf("partial line must not be consumed, saw=%d offset=%d", saw, c.Offset())
	}
	t.Logf("[partial-line-scenario] incomplete tail held back: offset stays 0")

	// 补齐这行并再加一行。
	if err := os.WriteFile(logPath, []byte(full+"\n"+evtLine(evt("e2", 1, "web-1"))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.ReadLines(func(offset int64, line []byte) error { saw++; return nil }); err != nil {
		t.Fatal(err)
	}
	if saw != 2 {
		t.Fatalf("want 2 complete lines after tail completed, got %d", saw)
	}
	t.Logf("[partial-line-scenario] completed tail + new line both read: count=%d offset=%d", saw, c.Offset())
}
