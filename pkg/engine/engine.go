// Package engine ties rules, stateful windowed correlation and alert
// deduplication together. It is safe for concurrent use by multiple writers.
//
// # Semantics
//
// Event time vs processing time: every Event carries its own timestamp
// (event time); the "now" argument is wall-clock processing time and only
// drives alert dedup/lifecycle, never window assignment.
//
// Tumbling windows: for a rule with window W, event time t belongs to the
// half-open window [floor(t/W)*W, +W). Window assignment is therefore
// independent of arrival order.
//
// Watermark: WM = max(event timestamp seen so far) - AllowedLateness.
//   - An event with timestamp < WM is LATE: it is recorded as such and
//     dropped; it can never change a window that has already been finalized.
//     This is the only stable choice under arbitrary stream ordering.
//   - When WM reaches a window's end, the window is FINALIZED exactly once:
//     if its match count reached the rule threshold it emits one Finding,
//     which is submitted to the alert manager.
//   - IngestBatch stable-sorts events by (timestamp, id) before processing
//     and flushes all windows at the end, so feeding the same set of events
//     in-order or shuffled yields identical findings and alerts.
//
// Duplicate events: a given Event.ID is counted at most once, ever; repeats
// are flagged Duplicate=true and never double-counted, regardless of order.
//
// Rule reload: ReplaceRules swaps an immutable snapshot. Findings/alerts
// already produced under the old snapshot are never re-evaluated.
package engine

import (
	"sort"
	"sync"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/alert"
	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/matcher"
	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/model"
	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/rules"
)

// Config controls engine semantics.
type Config struct {
	// AllowedLateness bounds how far behind the watermark an event may
	// arrive and still be accepted. Must be >= 0; zero means strict order.
	AllowedLateness time.Duration
	// DefaultDedupWindow is used when a rule omits its dedup window.
	DefaultDedupWindow time.Duration
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		AllowedLateness:    10 * time.Second,
		DefaultDedupWindow: 5 * time.Minute,
	}
}

// IngestOutcome tells the caller what happened to an ingested event.
type IngestOutcome struct {
	EventID     string
	Duplicate   bool
	Late        bool
	LateDropped bool
	Matched     []string // rule IDs the event matched
	Fired       []*model.Finding
	NewAlerts   []*model.Alert
	Suppressed  []*model.Alert
}

// windowState accumulates matches for one rule window.
type windowState struct {
	ruleID   string
	start    time.Time
	end      time.Time
	eventIDs []string
}

// Engine processes events against an immutable rule snapshot.
type Engine struct {
	mu       sync.Mutex
	cfg      Config
	snapshot *rules.Snapshot
	alerts   *alert.Manager

	seen        map[string]struct{}
	windows     map[string]*windowState // key: ruleID + "|" + start.UnixNano()
	findings    []*model.Finding
	maxEvTime   time.Time
	watermark   time.Time
	initialized bool
}

// New creates an engine from a rule snapshot.
func New(snap *rules.Snapshot, cfg Config) *Engine {
	if cfg.AllowedLateness < 0 {
		cfg.AllowedLateness = 0
	}
	if cfg.DefaultDedupWindow <= 0 {
		cfg.DefaultDedupWindow = 5 * time.Minute
	}
	return &Engine{
		cfg:      cfg,
		snapshot: snap,
		alerts:   alert.NewManager(cfg.DefaultDedupWindow),
		seen:     map[string]struct{}{},
		windows:  map[string]*windowState{},
	}
}

// ReplaceRules atomically swaps the rule set. Existing findings and alerts
// produced under the old snapshot are never re-evaluated or changed.
func (e *Engine) ReplaceRules(snap *rules.Snapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.snapshot = snap
}

// Alerts exposes the underlying alert manager (for sweep/history).
func (e *Engine) AlertManager() *alert.Manager { return e.alerts }

// Ingest feeds one event into the engine at processing time now.
func (e *Engine) Ingest(ev *model.Event, now time.Time) IngestOutcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ingestLocked(ev, now)
}

func (e *Engine) ingestLocked(ev *model.Event, now time.Time) IngestOutcome {
	out := IngestOutcome{EventID: ev.ID}

	// 1) Duplicate detection first: repeats never count twice, ever.
	if _, dup := e.seen[ev.ID]; dup {
		out.Duplicate = true
		return out
	}

	// 2) Watermark / late-event check against the max BEFORE this event.
	wm := e.watermarkLocked()
	if e.initialized && ev.Timestamp.Before(wm) {
		out.Late = true
		out.LateDropped = true
		// A late event still proves event time progressed this far at most;
		// it is not registered in `seen` as accepted... actually register it
		// so a later repeat is also a duplicate, never a late re-accept.
		e.seen[ev.ID] = struct{}{}
		return out
	}

	e.seen[ev.ID] = struct{}{}
	if !e.initialized || ev.Timestamp.After(e.maxEvTime) {
		e.maxEvTime = ev.Timestamp
		e.initialized = true
	}

	// 3) Match against the current snapshot and accumulate into windows.
	for _, r := range e.snapshot.Rules() {
		if !matcher.Matches(r, ev) {
			continue
		}
		out.Matched = append(out.Matched, r.ID)
		if r.Window == 0 {
			// Immediate rule: fire on the spot.
			f := &model.Finding{
				RuleID:      r.ID,
				WindowStart: ev.Timestamp,
				WindowEnd:   ev.Timestamp,
				EventIDs:    []string{ev.ID},
				Count:       1,
				CreatedAt:   now,
			}
			e.emitFinding(f, r, now, &out)
			continue
		}
		start := ev.Timestamp.Truncate(r.Window)
		key := r.ID + "|" + keyTime(start)
		w, ok := e.windows[key]
		if !ok {
			w = &windowState{ruleID: r.ID, start: start, end: start.Add(r.Window)}
			e.windows[key] = w
		}
		w.eventIDs = append(w.eventIDs, ev.ID)
	}

	// 4) Advance watermark and finalize any closed windows.
	out.Fired = append(out.Fired, e.finalizeLocked(now)...)
	return out
}

// IngestBatch feeds multiple events; they are stable-sorted by (timestamp,
// id) before processing, so shuffled and in-order batches yield identical
// conclusions. All alerts created by the batch share processing time now.
// Returned outcomes are aligned with the input slice order.
func (e *Engine) IngestBatch(evs []*model.Event, now time.Time) []IngestOutcome {
	e.mu.Lock()
	defer e.mu.Unlock()

	order := make([]int, len(evs))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ea, eb := evs[order[a]], evs[order[b]]
		if !ea.Timestamp.Equal(eb.Timestamp) {
			return ea.Timestamp.Before(eb.Timestamp)
		}
		return ea.ID < eb.ID
	})

	outs := make([]IngestOutcome, len(evs))
	for _, idx := range order {
		outs[idx] = e.ingestLocked(evs[idx], now)
	}
	// Flush everything remaining so conclusions are independent of whether
	// a future higher-timestamp event exists.
	flushed := e.finalizeAllLocked(now)
	if len(flushed) > 0 {
		// Attach flush findings to the last-processed (latest) event outcome
		// for visibility; they are also always available via Findings().
		last := order[len(order)-1]
		outs[last].Fired = append(outs[last].Fired, flushed...)
	}
	return outs
}

// Flush finalizes every still-open window at processing time now,
// regardless of watermark. Used after a stream is fully replayed.
func (e *Engine) Flush(now time.Time) []*model.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.finalizeAllLocked(now)
}

// Watermark returns the current watermark.
func (e *Engine) Watermark() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.watermarkLocked()
}

func (e *Engine) watermarkLocked() time.Time {
	if !e.initialized {
		return time.Time{}
	}
	return e.maxEvTime.Add(-e.cfg.AllowedLateness)
}

// finalizeLocked closes every window ending at or before the watermark.
func (e *Engine) finalizeLocked(now time.Time) []*model.Finding {
	wm := e.watermarkLocked()
	var fired []*model.Finding
	for key, w := range e.windows {
		if !w.end.After(wm) { // end <= watermark
			if f := e.closeWindow(key, w, now); f != nil {
				fired = append(fired, f)
			}
		}
	}
	e.sortFindings(fired)
	return fired
}

// finalizeAllLocked closes every open window (batch end / explicit flush).
func (e *Engine) finalizeAllLocked(now time.Time) []*model.Finding {
	var fired []*model.Finding
	for key, w := range e.windows {
		if f := e.closeWindow(key, w, now); f != nil {
			fired = append(fired, f)
		}
	}
	e.sortFindings(fired)
	return fired
}

func (e *Engine) closeWindow(key string, w *windowState, now time.Time) *model.Finding {
	delete(e.windows, key)
	r, ok := e.snapshot.Lookup(w.ruleID)
	if !ok {
		// Rule removed by a reload: its open window is dropped without
		// producing anything; prior findings are untouched.
		return nil
	}
	sort.Strings(w.eventIDs)
	if len(w.eventIDs) < r.Threshold {
		return nil
	}
	f := &model.Finding{
		RuleID:      r.ID,
		WindowStart: w.start,
		WindowEnd:   w.end,
		EventIDs:    append([]string(nil), w.eventIDs...),
		Count:       len(w.eventIDs),
		CreatedAt:   now,
	}
	e.recordFinding(f)
	e.submitToAlertManager(f, r, now, nil)
	return f
}

func (e *Engine) emitFinding(f *model.Finding, r *model.Rule, now time.Time, out *IngestOutcome) {
	e.recordFinding(f)
	e.submitToAlertManager(f, r, now, out)
	out.Fired = append(out.Fired, f)
}

func (e *Engine) recordFinding(f *model.Finding) {
	e.findings = append(e.findings, f)
}

func (e *Engine) submitToAlertManager(f *model.Finding, r *model.Rule, now time.Time, out *IngestOutcome) {
	res := e.alerts.Submit(f, r, now)
	if out == nil {
		return
	}
	if res.Suppressed {
		out.Suppressed = append(out.Suppressed, res.Alert)
	} else {
		out.NewAlerts = append(out.NewAlerts, res.Alert)
	}
}

// Findings returns all produced findings ordered by (window start, rule id).
func (e *Engine) Findings() []*model.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*model.Finding, len(e.findings))
	copy(out, e.findings)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].WindowStart.Equal(out[j].WindowStart) {
			return out[i].WindowStart.Before(out[j].WindowStart)
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// Alerts delegates to the alert manager.
func (e *Engine) Alerts() []*model.Alert { return e.alerts.Alerts() }

func (e *Engine) sortFindings(fs []*model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if !fs[i].WindowStart.Equal(fs[j].WindowStart) {
			return fs[i].WindowStart.Before(fs[j].WindowStart)
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}

func keyTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}
