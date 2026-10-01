package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFileRejectsMalformedRulesWithDistinctReasons(t *testing.T) {
	path := writeTemp(t, `{
	  "rules": [
	    {"id":"OK","version":1,"window":"5m","threshold":2,
	     "conditions":[{"field":"action","op":"eq","value":"login_failed"}]},
	    {"id":"TOO-NEW","version":99,"window":"5m","threshold":1,
	     "conditions":[{"field":"action","op":"eq","value":"x"}]},
	    {"id":"BAD-OP","version":1,"window":"5m","threshold":1,
	     "conditions":[{"field":"action","op":"regex","value":"x"}]},
	    {"id":"BAD-NUM","version":1,"window":"5m","threshold":1,
	     "conditions":[{"field":"amount","op":"gt","value":"not-a-number"}]},
	    {"id":"NO-WINDOW","version":1,"threshold":1,
	     "conditions":[{"field":"action","op":"eq","value":"x"}]},
	    {"id":"NO-CONDS","version":1,"window":"5m","threshold":1},
	    {"version":1,"window":"5m","threshold":1,
	     "conditions":[{"field":"action","op":"eq","value":"x"}]}
	  ]
	}`)

	res, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	t.Logf("loaded rules: %d", len(res.Rules))
	for _, r := range res.Rules {
		t.Logf("  loaded: %s window=%s threshold=%d", r.ID, r.Window, r.Threshold)
	}
	for _, rj := range res.Rejections {
		t.Logf("  rejected: %s", rj)
	}

	if len(res.Rules) != 1 || res.Rules[0].ID != "OK" {
		t.Fatalf("expected only rule OK to load, got %+v", res.Rules)
	}
	if len(res.Rejections) != 6 {
		t.Fatalf("expected 6 rejections, got %d", len(res.Rejections))
	}

	want := map[string]RejectReason{
		"TOO-NEW":   ReasonVersionTooNew,
		"BAD-OP":    ReasonInvalidCondition,
		"BAD-NUM":   ReasonInvalidCondition,
		"NO-WINDOW": ReasonMissingField,
		"NO-CONDS":  ReasonMissingField,
		"":          ReasonMissingField, // 空 id
	}
	got := map[string]RejectReason{}
	for _, rj := range res.Rejections {
		got[rj.RuleID] = rj.Reason
	}
	for id, reason := range want {
		if got[id] != reason {
			t.Errorf("rule %q: want reason %s, got %s", id, reason, got[id])
		}
	}
}

func TestLoadFileNormalizesNumericCondition(t *testing.T) {
	path := writeTemp(t, `{"rules":[
	  {"id":"R","version":1,"window":"10m","threshold":1,
	   "conditions":[{"field":"amount","op":"gt","value":"10000"}]}
	]}`)
	res, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(res.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d (rejections: %v)", len(res.Rules), res.Rejections)
	}
	c := res.Rules[0].Conditions[0]
	t.Logf("normalized condition: %+v", c)
	if !c.IsNumber || c.Number != 10000 {
		t.Errorf("numeric condition not normalized: %+v", c)
	}
}
