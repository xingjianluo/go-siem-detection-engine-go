// siem 是本地验证入口：读取规则文件与日志文件（JSON Lines），
// 输出被拒绝的规则、规则命中与最终告警。
//
// 三种用法：
//
// 1) 一口气跑完（无状态，原始语义）：
//
//	go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl
//
// 2) 可暂停续跑：进程重启后从上次偏移继续，判定状态与告警计数不丢：
//
//	go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl \
//	    -state-dir ./.siem-state -resume
//
// 3) 历史回放对账：用当前规则重跑历史日志，现场与实时链路物理隔离：
//
//	go run ./cmd/siem -rules rules/rules.json -logs data/events.jsonl \
//	    -state-dir ./.siem-state -replay audit-1008
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/alert"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
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

	stateDir := flag.String("state-dir", "", "directory for checkpoint state; empty = stateless one-shot run")
	resume := flag.Bool("resume", false, "resume realtime pipeline from checkpoint (requires -state-dir)")
	replay := flag.String("replay", "", "replay logs under current rules with an isolated state key named NAME")
	fresh := flag.Bool("fresh", false, "ignore any existing checkpoint and start a new state")
	maxAge := flag.Duration("state-max-age", state.DefaultMaxAge, "retention for resolved alerts and old checkpoints (0 = forever)")
	maxBytes := flag.Int("state-max-bytes", state.DefaultMaxBytes, "soft size limit per state file in bytes (0 = unlimited)")
	checkpointEvery := flag.Int("checkpoint-every", 100, "flush checkpoint every N newly read lines (0 = only at end)")
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

	switch {
	case *replay != "" && *resume:
		fmt.Fprintln(os.Stderr, "-replay and -resume are mutually exclusive")
		os.Exit(2)
	case *stateDir == "" && (*resume || *replay != "" || *fresh):
		fmt.Fprintln(os.Stderr, "-resume/-replay/-fresh require -state-dir")
		os.Exit(2)
	}

	if *stateDir == "" {
		runStateless(*logsPath, res.Rules, *lateness, *dedup)
		return
	}

	store, err := state.NewStore(*stateDir, state.Policy{MaxAge: *maxAge, MaxBytes: *maxBytes})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open state store: %v\n", err)
		os.Exit(1)
	}

	if *replay != "" {
		runReplay(store, *replay, *logsPath, res.Rules, *lateness, *dedup)
		return
	}
	runRealtime(store, *logsPath, res.Rules, *lateness, *dedup, *resume, *fresh, *checkpointEvery)
}

// runStateless 保持无 -state-dir 时的原始行为。
func runStateless(logsPath string, rs []rules.Rule, lateness, dedupWindow time.Duration) {
	events, err := loadEvents(logsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load events: %v\n", err)
		os.Exit(1)
	}

	corr := engine.NewCorrelator(rs, lateness)
	mgr := alert.NewManager(dedupWindow)

	fmt.Printf("\n== ingesting %d events (stateless) ==\n", len(events))
	for _, e := range events {
		report(corr.Ingest(e), mgr)
	}
	report(corr.Flush(), mgr)
	printSummary(corr.Stats(), mgr)
}

func runRealtime(store *state.Store, logsPath string, rs []rules.Rule,
	lateness, dedupWindow time.Duration, resume, fresh bool, every int,
) {
	cfg := state.Config{Rules: rs, Lateness: lateness, DedupWindow: dedupWindow}
	var p *state.Pipeline

	if resume && !fresh {
		st, err := store.Load(state.RealtimeKey)
		switch {
		case err == nil:
			if st.Cursor.Path != "" && st.Cursor.Path != logsPath {
				fmt.Fprintf(os.Stderr, "checkpoint tracks %q but -logs is %q; point -logs at the same file or use -fresh\n",
					st.Cursor.Path, logsPath)
				os.Exit(1)
			}
			p, err = state.RestorePipeline(st, rs, store, state.RealtimeKey)
			if err != nil {
				fatalState("restore realtime checkpoint", err)
			}
			fmt.Printf("== resumed realtime pipeline from offset %d (file=%s) ==\n",
				st.Cursor.Offset, st.Cursor.Path)
		case errors.Is(err, os.ErrNotExist):
			fmt.Println("== no checkpoint found, starting fresh realtime pipeline ==")
			p = state.NewPipeline(cfg)
			p.BindStore(store, state.RealtimeKey)
			p.BindCursor(logsPath)
		default:
			fatalState("load realtime checkpoint", err)
		}
	} else {
		if fresh && store.Exists(state.RealtimeKey) {
			fmt.Println("== -fresh: discarding existing realtime checkpoint ==")
			if err := store.Delete(state.RealtimeKey); err != nil {
				fmt.Fprintf(os.Stderr, "delete old checkpoint: %v\n", err)
				os.Exit(1)
			}
		}
		p = state.NewPipeline(cfg)
		p.BindStore(store, state.RealtimeKey)
		p.BindCursor(logsPath)
	}

	fmt.Printf("\n== tailing %s from offset %d ==\n", logsPath, p.Cursor().Offset())
	runner := state.Runner{
		CheckpointEvery: every,
		OnResult: func(e engine.Event, r state.IngestResult) {
			for _, o := range r.Outcomes {
				verb := "MERGED"
				if o.IsNew {
					verb = "NEW   "
				}
				fmt.Printf("  %s rule=%s group=%s count=%d window_end=%s alert_hits=%d (%s)\n",
					verb, o.Match.RuleID, o.Match.GroupKey, o.Match.Count,
					o.Match.WindowEnd.Format(time.RFC3339), o.Alert.Hits, o.Alert.Reason)
			}
		},
		OnBadLine: func(n int, line []byte, err error) {
			fmt.Fprintf(os.Stderr, "  WARN skip bad line %d: %v\n", n, err)
		},
	}
	rr, err := runner.RunFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		os.Exit(1)
	}
	fr, cp, err := runner.FinishAndCheckpoint(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "final checkpoint: %v\n", err)
		os.Exit(1)
	}
	for _, o := range fr.Outcomes {
		fmt.Printf("  FLUSH rule=%s group=%s count=%d window_end=%s alert_hits=%d\n",
			o.Match.RuleID, o.Match.GroupKey, o.Match.Count,
			o.Match.WindowEnd.Format(time.RFC3339), o.Alert.Hits)
	}

	fmt.Printf("\n== batch: lines=%d bad=%d checkpoints=%d resolved_pruned=%d state_bytes=%d ==\n",
		rr.LinesRead, rr.BadLines, rr.Checkpoints+1, rr.ResolvedPruned+cp.ResolvedPruned, cp.Bytes)
	printSummary(p.Stats(), snapshotManager{p.Alerts()})
}

func runReplay(store *state.Store, name, logsPath string, rs []rules.Rule,
	lateness, dedupWindow time.Duration,
) {
	key := state.ReplayKey(name)
	fmt.Printf("== historical replay %q (isolated key=%s), cannot touch realtime state ==\n", name, key)

	p := state.NewPipeline(state.Config{Rules: rs, Lateness: lateness, DedupWindow: dedupWindow})
	p.BindStore(store, key)
	p.BindCursor(logsPath) // 回放永远从历史文件开头读

	runner := state.Runner{
		OnResult: func(e engine.Event, r state.IngestResult) {
			for _, o := range r.Outcomes {
				verb := "MERGED"
				if o.IsNew {
					verb = "NEW   "
				}
				fmt.Printf("  %s rule=%s group=%s count=%d window_end=%s alert_hits=%d\n",
					verb, o.Match.RuleID, o.Match.GroupKey, o.Match.Count,
					o.Match.WindowEnd.Format(time.RFC3339), o.Alert.Hits)
			}
		},
		OnBadLine: func(n int, line []byte, err error) {
			fmt.Fprintf(os.Stderr, "  WARN skip bad line %d: %v\n", n, err)
		},
	}
	rr, err := runner.RunFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		os.Exit(1)
	}
	fr, cp, err := runner.FinishAndCheckpoint(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay checkpoint: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n== replay done: lines=%d bad=%d new_alerts=%d merged=%d flush_matches=%d state_bytes=%d key=%s ==\n",
		rr.LinesRead, rr.BadLines, rr.NewAlerts, rr.MergedHits, len(fr.Outcomes), cp.Bytes, key)
	printSummary(p.Stats(), snapshotManager{p.Alerts()})
}

// alertView 抽象 stateless 的 *alert.Manager 与 pipeline 的快照，
// 让 summary 打印共用一段代码。
type alertView interface {
	Snapshot() []alert.Alert
}

type snapshotManager struct{ a []alert.Alert }

func (s snapshotManager) Snapshot() []alert.Alert { return s.a }

func report(ms []engine.Match, mgr *alert.Manager) {
	for _, m := range ms {
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

func printSummary(stats engine.Stats, view alertView) {
	fmt.Printf("\n== stats: ingested=%d duplicates=%d late_dropped=%d ==\n",
		stats.Ingested, stats.Duplicates, stats.LateDropped)

	fmt.Println("\n== alerts ==")
	for _, a := range view.Snapshot() {
		fmt.Printf("  [%s] rule=%s group=%s hits=%d suppressed=%d last=%s\n      reason: %s\n",
			a.Status, a.RuleID, a.GroupKey, a.Hits, a.Suppressed,
			a.LastSeen.Format(time.RFC3339), a.Reason)
	}
}

func fatalState(what string, err error) {
	var kind error
	var detail string
	if le, ok := err.(*state.LoadError); ok {
		kind, detail = le.Kind, le.Detail
	} else {
		switch {
		case errors.Is(err, state.ErrRulesChanged):
			kind = state.ErrRulesChanged
		case errors.Is(err, state.ErrProgressTruncated):
			kind = state.ErrProgressTruncated
		case errors.Is(err, state.ErrCapacityExceeded):
			kind = state.ErrCapacityExceeded
		case errors.Is(err, state.ErrLockBusy):
			kind = state.ErrLockBusy
		}
		detail = err.Error()
	}
	if kind != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n  detail: %s\n  hint: %s\n", what, kind, detail, recoveryHint(kind))
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

func recoveryHint(kind error) string {
	switch {
	case errors.Is(kind, state.ErrVersionIncompatible):
		return "checkpoint written by another engine version; move the file aside and use -replay to rebuild"
	case errors.Is(kind, state.ErrCorrupt):
		return "checkpoint content is damaged; move the file aside, then use -replay for reconciliation and -fresh to restart realtime"
	case errors.Is(kind, state.ErrExpired):
		return "checkpoint is older than -state-max-age; use -replay for historical reconciliation, -fresh to restart realtime"
	case errors.Is(kind, state.ErrRulesChanged):
		return "rules changed since the checkpoint; keep old state with -resume using old rules, or run -replay with current rules into an isolated key"
	case errors.Is(kind, state.ErrProgressTruncated):
		return "the log file was truncated/rotated since the checkpoint; archive old state with -fresh after confirming the new file"
	case errors.Is(kind, state.ErrCapacityExceeded):
		return "minimum required state exceeds -state-max-bytes; raise the limit or narrow the rule set"
	case errors.Is(kind, state.ErrLockBusy):
		return "another process holds this state key; stop it or choose a different state directory"
	default:
		return "inspect the state directory and decide whether to rebuild via -fresh"
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
