// siem 是本地验证入口：读取规则文件与日志文件（JSON Lines），
// 输出被拒绝的规则、规则命中与最终告警。
//
// 用法：
//
//	go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl \
//	    -lateness 10m -dedup 10m
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
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
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

	corr := engine.NewCorrelator(res.Rules, *lateness)
	mgr := alert.NewManager(*dedup)

	fmt.Printf("\n== ingesting %d events ==\n", len(events))
	for _, e := range events {
		for _, m := range corr.Ingest(e) {
			a, isNew := mgr.Record(m, m.WindowEnd)
			verb := "MERGED "
			if isNew {
				verb = "NEW     "
			}
			fmt.Printf("  %s rule=%s group=%s count=%d window_end=%s -> alert hits=%d (%s)\n",
				verb, m.RuleID, m.GroupKey, m.Count,
				m.WindowEnd.Format(time.RFC3339), a.Hits, a.Reason)
		}
	}

	for _, m := range corr.Flush() {
		a, isNew := mgr.Record(m, m.WindowEnd)
		verb := "MERGED "
		if isNew {
			verb = "NEW     "
		}
		fmt.Printf("  %s rule=%s group=%s count=%d window_end=%s -> alert hits=%d (%s)\n",
			verb, m.RuleID, m.GroupKey, m.Count,
			m.WindowEnd.Format(time.RFC3339), a.Hits, a.Reason)
	}

	stats := corr.Stats()
	fmt.Printf("\n== stats: ingested=%d duplicates=%d late_dropped=%d ==\n",
		stats.Ingested, stats.Duplicates, stats.LateDropped)

	fmt.Println("\n== alerts ==")
	for _, a := range mgr.Snapshot() {
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
