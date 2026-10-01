// Package model defines the unified domain types shared across the engine:
// events, normalized rules, rule-loading errors, findings and alerts.
package model

import "time"

// Severity levels.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Supported rule definition versions: "1" and "2".
const (
	MinRuleVersion = 1
	MaxRuleVersion = 2
)

// Operators supported by a rule condition.
type Operator string

const (
	OpEquals         Operator = "eq"
	OpNotEquals      Operator = "ne"
	OpContains       Operator = "contains"
	OpPrefix         Operator = "prefix"
	OpSuffix         Operator = "suffix"
	OpRegex          Operator = "regex"
	OpGreaterThan    Operator = "gt"
	OpGreaterOrEqual Operator = "gte"
	OpLessThan       Operator = "lt"
	OpLessOrEqual    Operator = "lte"
	OpExists         Operator = "exists"
)

// Event is the normalized representation of an input log line.
type Event struct {
	ID        string                 `json:"id"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"ts"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields"`
}

// Condition is a single predicate over an event.
type Condition struct {
	Field string      `json:"field"`
	Op    Operator    `json:"op"`
	Value interface{} `json:"value,omitempty"`
}

// Rule is the normalized, validated detection rule.
type Rule struct {
	ID          string
	Version     int
	Name        string
	Description string
	Severity    Severity
	Condition   Condition
	// Window is the tumbling correlation window; 0 means evaluate immediately.
	Window time.Duration
	// Threshold is the number of matching events inside one window required to fire.
	Threshold int
	// DedupWindow is the sliding window during which repeated fires merge into one alert.
	DedupWindow time.Duration
}

// RejectReason explains why a raw rule entry was rejected during loading.
type RejectReason string

const (
	RejectVersionUnsupported RejectReason = "version_unsupported"
	RejectMalformed          RejectReason = "malformed_entry"
	RejectMissingField       RejectReason = "missing_field"
	RejectInvalidCondition   RejectReason = "invalid_condition"
	RejectInvalidWindow      RejectReason = "invalid_window"
	RejectDuplicateRuleID    RejectReason = "duplicate_rule_id"
)

// RuleRejection describes one rejected raw rule entry.
type RuleRejection struct {
	Index  int
	RawID  string
	Reason RejectReason
	Detail string
}

// Finding is the deterministic conclusion that a rule fired for a window.
type Finding struct {
	RuleID      string
	WindowStart time.Time
	WindowEnd   time.Time
	EventIDs    []string
	Count       int
	CreatedAt   time.Time
}

// SuppressReason explains why a fire was merged into an existing alert.
type SuppressReason string

const (
	SuppressNone        SuppressReason = ""
	SuppressDedupWindow SuppressReason = "dedup_window"
)

// Alert is the user-facing deduplicated alert with its lifecycle.
type Alert struct {
	Key         string
	RuleID      string
	Severity    Severity
	Title       string
	Count       int
	FirstSeen   time.Time
	LastSeen    time.Time
	WindowStart time.Time
	WindowEnd   time.Time
	EventIDs    []string
	Resolved    bool
	Suppressed  SuppressReason
	UpdatedAt   time.Time
}
