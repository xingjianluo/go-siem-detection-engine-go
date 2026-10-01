// Command siem runs the local log detection and alert correlation engine
// against a rules file and a JSON-lines log file. No external services:
//
//	siem -rules examples/rules.json -events examples/events.jsonl \
//	     -allowed-lateness 10s -dedup-window 5m
//
// Log lines are JSON objects:
//
//	{"id":"e1","source":"auth","ts":"2026-10-01T10:00:00Z",
//	 "message":"Failed password for root","fields":{"src_ip":"10.0.0.1"}}
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/engine"
	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/model"
	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/rules"
)

func main() {
	rulesPath := flag.String("rules", "examples/rules.json", "path to the rule definition file")
	eventsPath := flag.String("events", "examples/events.jsonl", "path to JSON-lines event file")
	lateness := flag.Duration("allowed-lateness", 10*time.Second, "how long windows wait for late events")
	dedup := flag.Duration("dedup-window", 5*time.Minute, "default alert dedup sliding window")
	stream := flag.Bool("stream", false, "ingest events in file order (watermark) instead of sorted batch")
	flag.Parse()

	loader := rules.NewLoader()
	snap, err := loader.LoadFile(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load rules: %v\n", err)
		os.Exit(1)
	}
	for _, rej := range snap.Rejections() {
		fmt.Fprintf(os.Stderr, "REJECTED entry #%d (id=%q): %s — %s\n",
			rej.Index, rej.RawID, rej.Reason, rej.Detail)
	}
	if len(snap.Rules()) == 0 {
		fmt.Fprintln(os.Stderr, "no valid rules loaded; aborting")
		os.Exit(1)
	}
	fmt.Printf("loaded %d rule(s) (snapshot v%d)\n", len(snap.Rules()), snap.Version())

	events, err := loadEvents(*eventsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load events: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("loaded %d event(s)\n\n", len(events))

	eng := engine.New(snap, engine.Config{
		AllowedLateness:    *lateness,
		DefaultDedupWindow: *dedup,
	})
	now := time.Now()

	if *stream {
		for _, ev := range events {
			o := eng.Ingest(ev, now)
			printOutcome(o)
		}
		eng.Flush(now)
	} else {
		for _, o := range eng.IngestBatch(events, now) {
			printOutcome(o)
		}
	}

	fmt.Println("\n=== findings ===")
	for _, f := range eng.Findings() {
		fmt.Printf("rule=%-14s window=[%s,%s) count=%d events=%v\n",
			f.RuleID,
			f.WindowStart.UTC().Format(time.RFC3339),
			f.WindowEnd.UTC().Format(time.RFC3339),
			f.Count, f.EventIDs)
	}

	fmt.Println("\n=== alerts ===")
	for _, a := range eng.Alerts() {
		state := "ACTIVE"
		if a.Resolved {
			state = "RESOLVED"
		}
		supp := ""
		if a.Suppressed != model.SuppressNone {
			supp = fmt.Sprintf(" suppressed=%s", a.Suppressed)
		}
		fmt.Printf("[%s] %s rule=%s hits=%d first=%s last=%s%s\n  events=%v\n",
			state, a.Severity, a.RuleID, a.Count,
			a.FirstSeen.Format(time.RFC3339), a.LastSeen.Format(time.RFC3339),
			supp, a.EventIDs)
	}
}

func printOutcome(o engine.IngestOutcome) {
	switch {
	case o.LateDropped:
		fmt.Printf("event %-4s LATE(dropped)\n", o.EventID)
	case o.Duplicate:
		fmt.Printf("event %-4s DUPLICATE(ignored)\n", o.EventID)
	default:
		fmt.Printf("event %-4s matched=%v fired=%d newAlerts=%d suppressed=%d\n",
			o.EventID, o.Matched, len(o.Fired), len(o.NewAlerts), len(o.Suppressed))
	}
}

// loadEvents reads JSON Lines. Lines may be separated by newlines; blank
// lines are skipped; a malformed line aborts with its line number.
func loadEvents(path string) ([]*model.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []*model.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(bytesTrim(b)) == 0 {
			continue
		}
		var raw struct {
			ID      string                 `json:"id"`
			Source  string                 `json:"source"`
			TS      string                 `json:"ts"`
			Message string                 `json:"message"`
			Fields  map[string]interface{} `json:"fields"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		ts, err := time.Parse(time.RFC3339, raw.TS)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid ts %q: %w", line, raw.TS, err)
		}
		out = append(out, &model.Event{
			ID: raw.ID, Source: raw.Source, Timestamp: ts,
			Message: raw.Message, Fields: raw.Fields,
		})
	}
	return out, sc.Err()
}

func bytesTrim(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}
