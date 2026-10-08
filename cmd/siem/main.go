// siem 是本地验证入口：读取规则文件与日志文件（JSON Lines），
// 输出被拒绝的规则、规则命中与最终告警。
//
// 一次性跑完（纯内存，不落盘）：
//
//	go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl
//
// 可暂停续跑（进度与判定状态落盘，重启后接着跑）：
//
//	go run ./cmd/siem -logs data/events.jsonl -state var/state
//	# 进程停掉后再执行同一命令，会从落盘位置继续；
//	# 已处理过的事件会被跳过/去重，不会重算。
//
// 历史回放对账（独立现场，不触碰实时链路的落盘状态）：
//
//	go run ./cmd/siem -logs data/events.jsonl -replay
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/alert"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/pipeline"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/state"
)

type rawEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Fields    map[string]string `json:"fields"`
}

func main() {
	rulesPath := flag.String("rules", "rules/rules.json", "path to rules JSON file")
	logsPath := flag.String("logs", "data/events.jsonl", "path to events JSONL file")
	lateness := flag.Duration("lateness", 10*time.Minute, "allowed event lateness (watermark slack)")
	dedup := flag.Duration("dedup", 10*time.Minute, "alert dedup sliding window")
	stateDir := flag.String("state", "", "state directory for checkpointing (empty = in-memory only)")
	fresh := flag.Bool("fresh", false, "discard existing state and start over")
	replay := flag.Bool("replay", false, "replay historical logs with current rules, isolated from live state")
	maxSnapshots := flag.Int("state-keep", 3, "max checkpoint files kept in the state directory")
	stateMaxAge := flag.Duration("state-max-age", 24*time.Hour, "checkpoint retention; older state is rejected as expired")
	flag.Parse()

	res, err := rules.LoadFile(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load rules: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("== rules: %d loaded, %d rejected ==\n", len(res.Rules), len(res.Rejections))
	for _, rj := range res.Rejections {
		fmt.Printf("  REJECTED %s\n", rj)
	}
	for _, r := range res.Rules {
		fmt.Printf("  LOADED   %s (window=%s threshold=%d group_by=%q)\n", r.ID, r.Window, r.Threshold, r.GroupBy)
	}

	events, err := loadEvents(*logsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load events: %v\n", err)
		os.Exit(1)
	}

	// 历史回放：独立内存现场，不读写任何落盘状态。
	if *replay {
		fmt.Printf("\n== replaying %d historical events (isolated from live state) ==\n", len(events))
		alerts := pipeline.Replay(events, res.Rules, *lateness, *dedup)
		printAlerts(alerts)
		return
	}

	var store *state.Store
	if *stateDir != "" {
		store = state.NewStore(*stateDir, *maxSnapshots, *stateMaxAge)
	}

	var p *pipeline.Pipeline
	if *fresh {
		p = pipeline.OpenFresh(store, res.Rules, *lateness, *dedup)
		fmt.Println("== state: discarded by -fresh, starting over ==")
	} else {
		var status pipeline.ResumeStatus
		p, status, err = pipeline.OpenLive(store, res.Rules, *lateness, *dedup)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open pipeline: %v\n", err)
			os.Exit(1)
		}
		switch status {
		case pipeline.StatusResumed:
			fmt.Printf("== state: resumed from checkpoint (processed=%d events) ==\n", p.Processed())
		case pipeline.StatusNoState:
			fmt.Println("== state: no checkpoint found, starting from scratch ==")
		default:
			// 版本不兼容/损坏/过期/配置变更：明确报告，绝不静默从头开始。
			fmt.Fprintf(os.Stderr, "cannot resume: %s\n", status)
			fmt.Fprintln(os.Stderr, "state is NOT silently discarded; investigate the state directory,")
			fmt.Fprintln(os.Stderr, "or pass -fresh to explicitly abandon it and start over.")
			os.Exit(2)
		}
	}

	// 续跑：跳过落盘进度之前的事件；崩溃重推的重复事件由引擎按 ID 去重。
	todo := events
	if skipped := p.Processed(); skipped > 0 {
		if skipped > int64(len(events)) {
			skipped = int64(len(events))
		}
		todo = events[skipped:]
		fmt.Printf("== skipping %d already-checkpointed events ==\n", skipped)
	}

	fmt.Printf("\n== ingesting %d events ==\n", len(todo))
	matches, err := p.IngestBatch(todo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ingest: %v\n", err)
		os.Exit(1)
	}
	printMatches(matches)

	flushed, err := p.Flush()
	if err != nil {
		fmt.Fprintf(os.Stderr, "flush: %v\n", err)
		os.Exit(1)
	}
	printMatches(flushed)

	stats := p.Stats()
	fmt.Printf("\n== stats: ingested=%d duplicates=%d late_dropped=%d processed=%d ==\n",
		stats.Ingested, stats.Duplicates, stats.LateDropped, p.Processed())
	printAlerts(p.Alerts())
}

func printMatches(ms []engine.Match) {
	for _, m := range ms {
		fmt.Printf("  HIT rule=%s group=%s count=%d window_end=%s events=%v\n",
			m.RuleID, m.GroupKey, m.Count,
			m.WindowEnd.Format(time.RFC3339), m.EventIDs)
	}
}

func printAlerts(as []alert.Alert) {
	fmt.Println("\n== alerts ==")
	for _, a := range as {
		fmt.Printf("  [%s] rule=%s group=%s hits=%d suppressed=%d last=%s\n      reason: %s\n",
			a.Status, a.RuleID, a.GroupKey, a.Hits, a.Suppressed,
			a.LastSeen.Format(time.RFC3339), a.Reason)
	}
}

func loadEvents(path string) ([]engine.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []engine.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		var re rawEvent
		if err := json.Unmarshal(sc.Bytes(), &re); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, engine.Event{ID: re.ID, Timestamp: re.Timestamp, Source: re.Source, Fields: re.Fields})
	}
	return out, sc.Err()
}
