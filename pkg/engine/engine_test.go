package engine

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/model"
	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/rules"
)

// testDoc: rule "burst" fires at 3 failures per 1-minute tumbling window;
// "panic" is an immediate per-event rule used for dedup checks.
const testDoc = `{
  "rules": [
    {"version":2,"id":"burst","name":"Failed logins burst","severity":"high",
     "match":{"field":"message","op":"contains","value":"Failed password"},
     "window":"1m","threshold":3,"dedup_window":"5m"},
    {"version":2,"id":"panic","name":"Kernel panic","severity":"critical",
     "match":{"field":"message","op":"eq","value":"kernel panic"},
     "window":"0s","threshold":1,"dedup_window":"5m"}
  ]
}`

func mustSnapshot(t *testing.T, doc string) *rules.Snapshot {
	t.Helper()
	snap, err := rules.NewLoader().Load([]byte(doc))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(snap.Rejections()) != 0 {
		t.Fatalf("unexpected rule rejections: %+v", snap.Rejections())
	}
	return snap
}

func mkEvent(id string, sec int64, msg string) *model.Event {
	return &model.Event{
		ID: id, Source: "auth",
		Timestamp: time.Unix(sec, 0).UTC(),
		Message:   msg,
		Fields:    map[string]interface{}{},
	}
}

func signature(fs []*model.Finding) string {
	out := ""
	for _, f := range fs {
		out += fmt.Sprintf("%s@%d/%v;", f.RuleID, f.WindowStart.Unix(), f.EventIDs)
	}
	return out
}

// TestOrderIndependence is the headline property: the same event set fed
// in time order and shuffled (batch mode) produces identical findings.
func TestOrderIndependence(t *testing.T) {
	events := []*model.Event{
		mkEvent("e3", 30, "Failed password"),
		mkEvent("e1", 0, "Failed password"),
		mkEvent("e6", 125, "Failed password"), // [120,180): only 1, below threshold
		mkEvent("e2", 20, "Failed password"),
		mkEvent("e5", 110, "Failed password"),
		mkEvent("e4", 65, "Failed password"), // window [60,120): only 2 below threshold
	}
	now := time.Unix(1000, 0).UTC()

	eng1 := New(mustSnapshot(t, testDoc), DefaultConfig())
	out1 := eng1.IngestBatch(events, now)

	shuffled := []*model.Event{
		events[5], events[0], events[3], events[1], events[4], events[2],
	}
	eng2 := New(mustSnapshot(t, testDoc), DefaultConfig())
	out2 := eng2.IngestBatch(shuffled, now)

	for _, o := range out1 {
		t.Logf("[in-order] event=%s dup=%v late=%v matched=%v fired=%v",
			o.EventID, o.Duplicate, o.LateDropped, o.Matched, ruleIDs(o.Fired))
	}
	t.Logf("[in-order] findings: %s", signature(eng1.Findings()))
	for _, o := range out2 {
		t.Logf("[shuffled] event=%s dup=%v late=%v matched=%v fired=%v",
			o.EventID, o.Duplicate, o.LateDropped, o.Matched, ruleIDs(o.Fired))
	}
	t.Logf("[shuffled] findings: %s", signature(eng2.Findings()))

	if signature(eng1.Findings()) != signature(eng2.Findings()) {
		t.Fatalf("findings differ by input order:\n%s\n%s",
			signature(eng1.Findings()), signature(eng2.Findings()))
	}

	fs := eng1.Findings()
	// Only window [0,60) reaches threshold 3; [60,120) has 2 events and
	// [120,180) has 1, so neither fires.
	if len(fs) != 1 {
		t.Fatalf("expected only window [0,60) to fire, got %d: %s", len(fs), signature(fs))
	}
	if fs[0].Count != 3 || fmt.Sprint(fs[0].EventIDs) != "[e1 e2 e3]" {
		t.Errorf("firing window wrong: %+v", fs[0])
	}
	if fs[0].WindowStart.Unix() != 0 || fs[0].WindowEnd.Unix() != 60 {
		t.Errorf("window boundaries wrong: %v..%v", fs[0].WindowStart, fs[0].WindowEnd)
	}
}

// TestDuplicatesCountedOnce: the same Event.ID arriving repeatedly, in any
// position, never contributes twice.
func TestDuplicatesCountedOnce(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	events := []*model.Event{
		mkEvent("e1", 1, "Failed password"),
		mkEvent("e2", 2, "Failed password"),
		mkEvent("e1", 1, "Failed password"), // exact repeat
		mkEvent("e1", 1, "Failed password"), // repeat again
		mkEvent("e3", 3, "Failed password"),
		mkEvent("e2", 2, "Failed password"), // repeat after a gap
	}
	eng := New(mustSnapshot(t, testDoc), DefaultConfig())
	outs := eng.IngestBatch(events, now)
	dups := 0
	for _, o := range outs {
		t.Logf("event=%s duplicate=%v matched=%v decision=%s",
			o.EventID, o.Duplicate, o.Matched, decide(o))
		if o.Duplicate {
			dups++
		}
	}
	if dups != 3 {
		t.Errorf("expected 3 duplicate outcomes, got %d", dups)
	}
	fs := eng.Findings()
	if len(fs) != 1 || fs[0].Count != 3 || fmt.Sprint(fs[0].EventIDs) != "[e1 e2 e3]" {
		t.Fatalf("duplicate double-counted: %+v", fs)
	}
}

// TestLateEventDropped: under streaming watermark semantics an event older
// than watermark (maxTs - allowedLateness) is flagged and cannot revive a
// finalized window.
func TestLateEventDropped(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	eng := New(mustSnapshot(t, testDoc), Config{
		AllowedLateness: 10 * time.Second, DefaultDedupWindow: 5 * time.Minute,
	})
	// First complete the [0,60) window with 3 events; e3 at t=30 pushes the
	// watermark to 20, but the window closes only once WM >= 60.
	eng.Ingest(mkEvent("e1", 0, "Failed password"), now)
	eng.Ingest(mkEvent("e2", 5, "Failed password"), now)
	eng.Ingest(mkEvent("e3", 30, "Failed password"), now)
	// Jump far ahead: watermark = 70, so window [0,60) finalizes.
	eng.Ingest(mkEvent("e4", 80, "Failed password"), now)
	before := len(eng.Findings())
	// A late arrival into the already-finalized window must be dropped.
	o := eng.Ingest(mkEvent("e5", 5, "Failed password"), now)
	t.Logf("late event outcome: %s", decide(o))
	if !o.LateDropped {
		t.Fatalf("expected late drop, got %+v", o)
	}
	if len(eng.Findings()) != before {
		t.Fatal("late event must not create or alter a finding")
	}
	// Repeating that same late ID is a duplicate, not a late acceptance.
	o2 := eng.Ingest(mkEvent("e5", 5, "Failed password"), now)
	if !o2.Duplicate || o2.LateDropped {
		t.Fatalf("repeat of late event must be duplicate, got %+v", o2)
	}
}

// TestReloadDoesNotChangePast: findings and alerts produced under an old
// snapshot survive a reload untouched, and the new rule only applies after.
func TestReloadDoesNotChangePast(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	eng := New(mustSnapshot(t, testDoc), DefaultConfig())
	eng.IngestBatch([]*model.Event{
		mkEvent("e1", 1, "kernel panic"),
		mkEvent("e2", 2, "kernel panic"),
	}, now)
	oldFindings := signature(eng.Findings())
	oldAlerts := len(eng.Alerts())

	const newDoc = `{"rules":[
	  {"version":2,"id":"totally-different","name":"X","severity":"low",
	   "match":{"field":"message","op":"contains","value":"anything"},"window":"0s","threshold":1}
	]}`
	eng.ReplaceRules(mustSnapshot(t, newDoc))

	if signature(eng.Findings()) != oldFindings {
		t.Fatal("reload retroactively changed findings")
	}
	if len(eng.Alerts()) != oldAlerts {
		t.Fatal("reload retroactively changed alerts")
	}
	// Events after the reload are judged by the new rule only.
	o := eng.Ingest(mkEvent("e3", 3, "kernel panic"), now)
	if len(o.Matched) != 0 {
		t.Fatalf("old rule must no longer match after reload, got %v", o.Matched)
	}
	t.Logf("post-reload decision for pre-reload-style event: %s", decide(o))
}

// TestAlertDedupAcrossWindows: repeated firings in sliding dedup window
// merge into one alert carrying total hit count and a suppression reason.
func TestAlertDedupAcrossWindows(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	eng := New(mustSnapshot(t, testDoc), DefaultConfig())
	// Two adjacent windows each reach the threshold.
	eng.IngestBatch([]*model.Event{
		mkEvent("a1", 1, "Failed password"),
		mkEvent("a2", 2, "Failed password"),
		mkEvent("a3", 3, "Failed password"),
		mkEvent("b1", 61, "Failed password"),
		mkEvent("b2", 62, "Failed password"),
		mkEvent("b3", 63, "Failed password"),
	}, now)
	alerts := eng.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("expected ONE merged alert, got %d", len(alerts))
	}
	a := alerts[0]
	t.Logf("merged alert rule=%s hits=%d suppressed=%s events=%v (basis: two tumbling windows, one sliding dedup window)",
		a.RuleID, a.Count, a.Suppressed, a.EventIDs)
	if a.Count != 6 {
		t.Errorf("hit count = %d, want 6", a.Count)
	}
	if a.Suppressed != model.SuppressDedupWindow {
		t.Errorf("expected suppression reason recorded, got %q", a.Suppressed)
	}
}

// TestConcurrentWritersNoRace: many goroutines writing concurrently must
// not lose events, race, or panic. Run with -race.
func TestConcurrentWritersNoRace(t *testing.T) {
	eng := New(mustSnapshot(t, testDoc), Config{
		AllowedLateness: 0, DefaultDedupWindow: 5 * time.Minute,
	})
	const writers = 8
	const perWriter = 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				id := fmt.Sprintf("w%d-e%d", w, i)
				// Spread across distinct windows so ordering races cannot
				// cause late drops between writers (allowed lateness 0).
				ev := mkEvent(id, int64(w*3600+i), "kernel panic")
				eng.Ingest(ev, time.Now())
			}
		}(w)
	}
	wg.Wait()

	// Every unique ID must have been recorded exactly once: the same event
	// set processed again yields no new accepted events.
	var wg2 sync.WaitGroup
	reAccepted := 0
	var mu sync.Mutex
	for w := 0; w < writers; w++ {
		wg2.Add(1)
		go func(w int) {
			defer wg2.Done()
			for i := 0; i < perWriter; i++ {
				id := fmt.Sprintf("w%d-e%d", w, i)
				ev := mkEvent(id, int64(w*3600+i), "kernel panic")
				o := eng.Ingest(ev, time.Now())
				if !o.Duplicate {
					mu.Lock()
					reAccepted++
					mu.Unlock()
				}
			}
		}(w)
	}
	wg2.Wait()
	if reAccepted != 0 {
		t.Fatalf("%d events lost or double-accepted under concurrency", reAccepted)
	}
	t.Logf("concurrent writes: %d unique events, all repeats detected as duplicates",
		writers*perWriter)
}

func ruleIDs(fs []*model.Finding) []string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	return ids
}

// decide renders the final judgment basis for an event, for test logs.
func decide(o IngestOutcome) string {
	switch {
	case o.Duplicate:
		return "DENY: duplicate event id, counted zero times"
	case o.LateDropped:
		return "DENY: behind watermark, window already finalized"
	case len(o.NewAlerts) > 0:
		return fmt.Sprintf("FIRE: matched=%v -> new alert %v", o.Matched, alertIDs(o.NewAlerts))
	case len(o.Suppressed) > 0:
		return fmt.Sprintf("FIRE: matched=%v -> suppressed(dedup_window) into %v",
			o.Matched, alertIDs(o.Suppressed))
	case len(o.Matched) > 0:
		return fmt.Sprintf("MATCH(no fire yet): matched=%v, accumulating in window", o.Matched)
	default:
		return "NO MATCH"
	}
}

func alertIDs(as []*model.Alert) []string {
	var ids []string
	for _, a := range as {
		ids = append(ids, a.RuleID)
	}
	return ids
}
