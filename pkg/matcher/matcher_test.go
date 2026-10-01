package matcher

import (
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/model"
)

func ev(fields map[string]interface{}) *model.Event {
	return &model.Event{
		ID:        "e1",
		Source:    "auth",
		Timestamp: time.Unix(0, 0),
		Message:   "Failed password for root from 10.0.0.1",
		Fields:    fields,
	}
}

func rule(field string, op model.Operator, val interface{}) *model.Rule {
	return &model.Rule{ID: "r", Condition: model.Condition{Field: field, Op: op, Value: val}}
}

func TestOperators(t *testing.T) {
	e := ev(map[string]interface{}{
		"bytes_out": float64(2500000),
		"user":      "root",
		"ok":        true,
	})
	cases := []struct {
		field string
		op    model.Operator
		val   interface{}
		want  bool
	}{
		{"message", model.OpContains, "Failed password", true},
		{"message", model.OpContains, "success", false},
		{"message", model.OpPrefix, "Failed", true},
		{"message", model.OpSuffix, "10.0.0.1", true},
		{"message", model.OpRegex, `Failed \w+ for (\w+)`, true},
		{"message", model.OpRegex, `^Accepted`, false},
		{"bytes_out", model.OpGreaterThan, float64(1000), true},
		{"bytes_out", model.OpGreaterOrEqual, float64(2500000), true},
		{"bytes_out", model.OpLessThan, float64(100), false},
		{"bytes_out", model.OpLessOrEqual, float64(2500000), true},
		{"user", model.OpEquals, "root", true},
		{"user", model.OpEquals, "admin", false},
		{"user", model.OpNotEquals, "admin", true},
		{"ok", model.OpEquals, true, true},
		{"missing", model.OpExists, nil, false},
		{"user", model.OpExists, nil, true},
		{"source", model.OpEquals, "auth", true},
		{"id", model.OpEquals, "e1", true},
	}
	for _, c := range cases {
		got := Matches(rule(c.field, c.op, c.val), e)
		if got != c.want {
			t.Errorf("%s %s %v: got %v want %v", c.field, c.op, c.val, got, c.want)
		}
	}
}

func TestMissingFieldNeverMatches(t *testing.T) {
	e := ev(nil)
	for _, op := range []model.Operator{
		model.OpEquals, model.OpContains, model.OpRegex, model.OpGreaterThan,
	} {
		if Matches(rule("nope", op, "x"), e) {
			t.Errorf("missing field matched for op %s", op)
		}
	}
}

func TestTypeMismatchIsFalseNotError(t *testing.T) {
	e := ev(map[string]interface{}{"user": "root"})
	ok, err := MatchCondition(model.Condition{Field: "user", Op: model.OpGreaterThan, Value: float64(3)}, e)
	if err != nil || ok {
		t.Fatalf("type mismatch should be (false,nil), got (%v,%v)", ok, err)
	}
}
