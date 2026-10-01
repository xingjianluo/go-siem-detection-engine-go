// Package rules loads and validates rule definition files and normalizes
// accepted entries into model.Rule values.
//
// Rule document format (JSON):
//
//	{
//	  "rules": [
//	    {
//	      "version": 2,
//	      "id": "failed-ssh",
//	      "name": "Failed SSH logins",
//	      "description": "optional",
//	      "severity": "high",
//	      "match": {"field": "message", "op": "contains", "value": "Failed password"},
//	      "window": "1m",
//	      "threshold": 5,
//	      "dedup_window": "10m"
//	    }
//	  ]
//	}
//
// Every entry is either accepted into the snapshot or recorded as a
// rejection carrying a distinguishable reason. Nothing is skipped silently.
package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/model"
)

// rawDocument is the on-disk rule document.
type rawDocument struct {
	Rules []json.RawMessage `json:"rules"`
}

// rawRule is one entry before validation/normalization.
type rawRule struct {
	Version     *int          `json:"version"`
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Severity    string        `json:"severity"`
	Match       *rawCondition `json:"match"`
	Window      string        `json:"window"`
	Threshold   *int          `json:"threshold"`
	DedupWindow string        `json:"dedup_window"`
}

type rawCondition struct {
	Field string      `json:"field"`
	Op    string      `json:"op"`
	Value interface{} `json:"value"`
}

// Snapshot is an immutable, versioned set of compiled rules.
type Snapshot struct {
	version    int64
	rules      []*model.Rule
	byID       map[string]*model.Rule
	loadedAt   time.Time
	rejections []model.RuleRejection
}

// Version returns the monotonically increasing snapshot version.
func (s *Snapshot) Version() int64 { return s.version }

// LoadedAt returns when the snapshot was compiled.
func (s *Snapshot) LoadedAt() time.Time { return s.loadedAt }

// Rules returns the accepted rules in definition order.
func (s *Snapshot) Rules() []*model.Rule {
	out := make([]*model.Rule, len(s.rules))
	copy(out, s.rules)
	return out
}

// Lookup returns a rule by ID.
func (s *Snapshot) Lookup(id string) (*model.Rule, bool) {
	r, ok := s.byID[id]
	return r, ok
}

// Rejections returns the rejected entries with distinguishable reasons.
func (s *Snapshot) Rejections() []model.RuleRejection {
	out := make([]model.RuleRejection, len(s.rejections))
	copy(out, s.rejections)
	return out
}

// Loader validates and compiles raw rule documents into snapshots.
type Loader struct {
	snapshotVersion int64
}

// NewLoader creates a Loader.
func NewLoader() *Loader { return &Loader{} }

// LoadFile loads a rule definition document from the given path.
// A missing/unreadable file or malformed top-level document is an error.
// Invalid *entries* inside an otherwise well-formed document are recorded
// as rejections, not returned as an error.
func (l *Loader) LoadFile(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file %q: %w", path, err)
	}
	return l.Load(data)
}

// Load parses and validates a raw rule document.
func (l *Loader) Load(data []byte) (*Snapshot, error) {
	var doc rawDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse rule document: %w", err)
	}
	if doc.Rules == nil {
		return nil, fmt.Errorf("parse rule document: %w", errMissingRulesArray)
	}

	l.snapshotVersion++
	snap := &Snapshot{
		version:  l.snapshotVersion,
		byID:     map[string]*model.Rule{},
		loadedAt: time.Now(),
	}

	for i, raw := range doc.Rules {
		r, rej := compileEntry(i, raw)
		if rej != nil {
			snap.rejections = append(snap.rejections, *rej)
			continue
		}
		if _, dup := snap.byID[r.ID]; dup {
			snap.rejections = append(snap.rejections, model.RuleRejection{
				Index:  i,
				RawID:  r.ID,
				Reason: model.RejectDuplicateRuleID,
				Detail: fmt.Sprintf("rule id %q already defined earlier in this document", r.ID),
			})
			continue
		}
		snap.rules = append(snap.rules, r)
		snap.byID[r.ID] = r
	}
	return snap, nil
}

var errMissingRulesArray = fmt.Errorf("missing \"rules\" array")

// compileEntry validates and normalizes a single raw entry.
func compileEntry(index int, raw json.RawMessage) (*model.Rule, *model.RuleRejection) {
	var rr rawRule
	if err := json.Unmarshal(raw, &rr); err != nil {
		return nil, &model.RuleRejection{
			Index:  index,
			Reason: model.RejectMalformed,
			Detail: fmt.Sprintf("entry is not a valid JSON object: %v", err),
		}
	}

	reject := func(reason model.RejectReason, detail string) *model.RuleRejection {
		return &model.RuleRejection{Index: index, RawID: rr.ID, Reason: reason, Detail: detail}
	}

	if rr.Version == nil {
		return nil, reject(model.RejectMissingField, "missing required field \"version\"")
	}
	v := *rr.Version
	if v < model.MinRuleVersion || v > model.MaxRuleVersion {
		return nil, reject(model.RejectVersionUnsupported,
			fmt.Sprintf("rule version %d is not supported (supported: %d..%d)", v, model.MinRuleVersion, model.MaxRuleVersion))
	}
	if rr.ID == "" {
		return nil, reject(model.RejectMissingField, "missing required field \"id\"")
	}
	if rr.Name == "" {
		return nil, reject(model.RejectMissingField, "missing required field \"name\"")
	}
	if rr.Match == nil {
		return nil, reject(model.RejectMissingField, "missing required field \"match\"")
	}
	if rr.Match.Field == "" {
		return nil, reject(model.RejectMissingField, "match.field must not be empty")
	}
	if rr.Match.Op == "" {
		return nil, reject(model.RejectMissingField, "match.op must not be empty")
	}
	op := model.Operator(rr.Match.Op)
	if !knownOperator(op) {
		return nil, reject(model.RejectInvalidCondition, fmt.Sprintf("unknown operator %q", rr.Match.Op))
	}
	if err := validateConditionValue(op, rr.Match); err != nil {
		return nil, reject(model.RejectInvalidCondition, err.Error())
	}

	severity := model.Severity(rr.Severity)
	if rr.Severity == "" {
		severity = model.SeverityMedium
	} else if !knownSeverity(severity) {
		return nil, reject(model.RejectMalformed, fmt.Sprintf("unknown severity %q", rr.Severity))
	}

	var window time.Duration
	if rr.Window != "" {
		w, err := time.ParseDuration(rr.Window)
		if err != nil {
			return nil, reject(model.RejectInvalidWindow, fmt.Sprintf("invalid window duration %q: %v", rr.Window, err))
		}
		if w < 0 {
			return nil, reject(model.RejectInvalidWindow, "window must be >= 0")
		}
		window = w
	}
	threshold := 1
	if rr.Threshold != nil {
		threshold = *rr.Threshold
	}
	if threshold < 1 {
		return nil, reject(model.RejectInvalidWindow, "threshold must be >= 1")
	}
	if window == 0 && threshold > 1 {
		return nil, reject(model.RejectInvalidWindow, "threshold > 1 requires a non-zero window")
	}
	var dedup time.Duration
	if rr.DedupWindow != "" {
		d, err := time.ParseDuration(rr.DedupWindow)
		if err != nil {
			return nil, reject(model.RejectInvalidWindow, fmt.Sprintf("invalid dedup_window duration %q: %v", rr.DedupWindow, err))
		}
		if d < 0 {
			return nil, reject(model.RejectInvalidWindow, "dedup_window must be >= 0")
		}
		dedup = d
	}

	return &model.Rule{
		ID:          rr.ID,
		Version:     v,
		Name:        rr.Name,
		Description: rr.Description,
		Severity:    severity,
		Condition: model.Condition{
			Field: rr.Match.Field,
			Op:    op,
			Value: rr.Match.Value,
		},
		Window:      window,
		Threshold:   threshold,
		DedupWindow: dedup,
	}, nil
}

func knownOperator(op model.Operator) bool {
	switch op {
	case model.OpEquals, model.OpNotEquals, model.OpContains, model.OpPrefix,
		model.OpSuffix, model.OpRegex, model.OpGreaterThan, model.OpGreaterOrEqual,
		model.OpLessThan, model.OpLessOrEqual, model.OpExists:
		return true
	}
	return false
}

func knownSeverity(s model.Severity) bool {
	switch s {
	case model.SeverityInfo, model.SeverityLow, model.SeverityMedium,
		model.SeverityHigh, model.SeverityCritical:
		return true
	}
	return false
}

// validateConditionValue enforces operator/value compatibility and, for
// regex, that the pattern compiles. Field values in events are not checked
// here: a non-matching field type at runtime simply yields no match.
func validateConditionValue(op model.Operator, c *rawCondition) error {
	switch op {
	case model.OpExists:
		return nil
	case model.OpContains, model.OpPrefix, model.OpSuffix, model.OpRegex:
		if _, ok := c.Value.(string); !ok {
			return fmt.Errorf("operator %q requires a string value", op)
		}
		if op == model.OpRegex {
			if _, err := regexp.Compile(c.Value.(string)); err != nil {
				return fmt.Errorf("invalid regex: %v", err)
			}
		}
	case model.OpGreaterThan, model.OpGreaterOrEqual, model.OpLessThan, model.OpLessOrEqual:
		if _, ok := c.Value.(float64); !ok {
			return fmt.Errorf("operator %q requires a numeric value", op)
		}
	case model.OpEquals, model.OpNotEquals:
		if c.Value == nil {
			return fmt.Errorf("operator %q requires a value", op)
		}
	}
	return nil
}
