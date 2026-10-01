// Package matcher evaluates a compiled model.Rule condition against events.
package matcher

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/model"
)

// Matches reports whether the event satisfies the rule condition.
func Matches(r *model.Rule, e *model.Event) bool {
	ok, err := MatchCondition(r.Condition, e)
	return err == nil && ok
}

// fieldValue extracts a condition field from an event.
// The built-in names "id", "source", "message", "ts" address the event's
// top-level fields; any other name addresses event.fields[name].
// The second return value reports whether the field was present.
func fieldValue(c model.Condition, e *model.Event) (interface{}, bool) {
	switch c.Field {
	case "id":
		return e.ID, true
	case "source":
		return e.Source, true
	case "message":
		return e.Message, true
	case "ts":
		return e.Timestamp, true
	default:
		v, ok := e.Fields[c.Field]
		return v, ok
	}
}

// MatchCondition evaluates a single condition against an event.
// A missing field never matches, except for "eq"/"ne" with null semantics
// handled by the caller: here missing => (false, nil) for all operators
// other than exists, which returns false.
func MatchCondition(c model.Condition, e *model.Event) (bool, error) {
	v, present := fieldValue(c, e)
	if !present {
		// Missing field: only exists=false meaningfully applies; every
		// other comparison is false.
		return false, nil
	}
	switch c.Op {
	case model.OpExists:
		return true, nil
	case model.OpEquals:
		return looseEquals(v, c.Value), nil
	case model.OpNotEquals:
		return !looseEquals(v, c.Value), nil
	case model.OpContains:
		s, ok := asString(v)
		if !ok {
			return false, nil
		}
		return strings.Contains(s, c.Value.(string)), nil
	case model.OpPrefix:
		s, ok := asString(v)
		if !ok {
			return false, nil
		}
		return strings.HasPrefix(s, c.Value.(string)), nil
	case model.OpSuffix:
		s, ok := asString(v)
		if !ok {
			return false, nil
		}
		return strings.HasSuffix(s, c.Value.(string)), nil
	case model.OpRegex:
		s, ok := asString(v)
		if !ok {
			return false, nil
		}
		re, err := regexp.Compile(c.Value.(string))
		if err != nil {
			return false, fmt.Errorf("invalid regex: %w", err)
		}
		return re.MatchString(s), nil
	case model.OpGreaterThan, model.OpGreaterOrEqual,
		model.OpLessThan, model.OpLessOrEqual:
		f, okF := asFloat(v)
		g, okG := asFloat(c.Value)
		if !okF || !okG {
			return false, nil
		}
		switch c.Op {
		case model.OpGreaterThan:
			return f > g, nil
		case model.OpGreaterOrEqual:
			return f >= g, nil
		case model.OpLessThan:
			return f < g, nil
		case model.OpLessOrEqual:
			return f <= g, nil
		}
	}
	return false, fmt.Errorf("unsupported operator %q", c.Op)
}

// asString accepts actual strings and string-typed values only.
func asString(v interface{}) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// asFloat accepts float64/int variants and numeric strings.
func asFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// looseEquals compares an event value with a rule value. JSON numbers are
// compared numerically; bools and strings strictly.
func looseEquals(a, b interface{}) bool {
	if af, ok := asFloat(a); ok {
		if bf, ok := asFloat(b); ok {
			return af == bf
		}
	}
	if ab, ok := a.(bool); ok {
		if bb, ok := b.(bool); ok {
			return ab == bb
		}
		return false
	}
	if as1, ok := a.(string); ok {
		if bs, ok := b.(string); ok {
			return as1 == bs
		}
	}
	return false
}
