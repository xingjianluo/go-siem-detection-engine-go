package rules

import (
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/pkg/model"
)

func validRule(id string) string {
	return `{
	  "version": 2,
	  "id": "` + id + `",
	  "name": "n",
	  "severity": "high",
	  "match": {"field": "message", "op": "contains", "value": "boom"},
	  "window": "1m",
	  "threshold": 3,
	  "dedup_window": "2m"
	}`
}

func doc(entries ...string) []byte {
	body := ""
	for i, e := range entries {
		if i > 0 {
			body += ","
		}
		body += e
	}
	return []byte(`{"rules":[` + body + `]}`)
}

func TestLoadAcceptsAndNormalizes(t *testing.T) {
	l := NewLoader()
	snap, err := l.Load(doc(validRule("r1")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.Rejections()) != 0 {
		t.Fatalf("expected no rejections, got %+v", snap.Rejections())
	}
	r, ok := snap.Lookup("r1")
	if !ok {
		t.Fatal("rule r1 missing")
	}
	if r.Version != 2 || r.Severity != model.SeverityHigh ||
		r.Window != time.Minute || r.Threshold != 3 || r.DedupWindow != 2*time.Minute {
		t.Fatalf("normalization wrong: %+v", r)
	}

	// Loading again produces a new, strictly higher snapshot version.
	snap2, _ := l.Load(doc(validRule("r1")))
	if snap2.Version() <= snap.Version() {
		t.Fatalf("snapshot version must increase: %d -> %d", snap.Version(), snap2.Version())
	}
}

func TestLoadRejectionReasonsAreDistinguishable(t *testing.T) {
	l := NewLoader()
	snap, err := l.Load(doc(
		`{"version":99,"id":"future","name":"n","match":{"field":"message","op":"contains","value":"x"}}`,
		`{"version":2,"name":"no-id","match":{"field":"message","op":"contains","value":"x"}}`,
		`{"version":2,"id":"bad-op","name":"n","match":{"field":"message","op":"nope","value":"x"}}`,
		`{"version":2,"id":"bad-regex","name":"n","match":{"field":"message","op":"regex","value":"("}}`,
		`{"version":2,"id":"bad-window","name":"n","match":{"field":"message","op":"contains","value":"x"},"window":"banana"}`,
		validRule("dup"),
		validRule("dup"),
		`{"version":2,"id":"bad-shape","name":123,"match":{"field":"message","op":"contains","value":"x"}}`,
	))
	if err != nil {
		t.Fatalf("document-level error: %v", err)
	}
	got := map[model.RejectReason]bool{}
	for _, r := range snap.Rejections() {
		got[r.Reason] = true
		t.Logf("entry #%d id=%q rejected: %s (%s)", r.Index, r.RawID, r.Reason, r.Detail)
	}
	want := []model.RejectReason{
		model.RejectVersionUnsupported,
		model.RejectMissingField,
		model.RejectInvalidCondition,
		model.RejectInvalidWindow,
		model.RejectDuplicateRuleID,
		model.RejectMalformed,
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("expected rejection reason %q to be present", w)
		}
	}
	if len(snap.Rules()) != 1 || snap.Rules()[0].ID != "dup" {
		t.Fatalf("only one valid dup rule expected, got %+v", snap.Rules())
	}
}

func TestLoadMalformedDocument(t *testing.T) {
	l := NewLoader()
	if _, err := l.Load([]byte(`{"rules":`)); err == nil {
		t.Fatal("expected error for truncated document")
	}
	if _, err := l.Load([]byte(`{}`)); err == nil {
		t.Fatal("expected error for missing rules array")
	}
}

func TestLoadDefaults(t *testing.T) {
	l := NewLoader()
	snap, err := l.Load(doc(
		`{"version":1,"id":"immediate","name":"n","match":{"field":"x","op":"eq","value":1}}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	r := snap.Rules()[0]
	if r.Severity != model.SeverityMedium || r.Window != 0 || r.Threshold != 1 {
		t.Fatalf("unexpected defaults: %+v", r)
	}
}
