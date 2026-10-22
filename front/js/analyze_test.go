package js_test

import (
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/js"
)

func TestAnalyzeOpaqueSource(t *testing.T) {
	reason := js.Analyze("").Reason
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"empty", ""},
		{"whitespace", " \t\r\n"},
		{"malformed", "const PRIVATE_JS_SOURCE = '"},
		{"valid", "const PRIVATE_JS_SOURCE = 1;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := js.Analyze(tc.src)
			if len(got.Effects) != 1 {
				t.Fatalf("got %d effects, want one", len(got.Effects))
			}
			e := got.Effects[0]
			if e.Kind != engine.KindCodeExec || !e.Target.IsTop() {
				t.Fatalf("expected CodeExec over top, got %+v", e)
			}
			if e.Mode != engine.ModeDirect || e.Certainty != engine.CertaintyCertain {
				t.Fatalf("unexpected mode or certainty: %+v", e)
			}
			if !e.Taint.IsBottom() || e.Reversible {
				t.Fatalf("unexpected taint or reversibility: %+v", e)
			}
			if !got.Top || !got.Conservative {
				t.Fatalf("expected top and conservative, got %+v", got)
			}
			if got.Reason == "" || got.Reason != reason || strings.Contains(got.Reason, "PRIVATE_JS_SOURCE") {
				t.Fatalf("expected a fixed, source-free reason, got %q", got.Reason)
			}
		})
	}
}

func TestAnalyzeResultsAreIndependent(t *testing.T) {
	first := js.Analyze("first")
	second := js.Analyze("second")
	first.Effects[0].Kind = engine.KindFSRead
	if second.Effects[0].Kind != engine.KindCodeExec {
		t.Fatal("mutating one result changed another")
	}
	if js.Analyze("third").Effects[0].Kind != engine.KindCodeExec {
		t.Fatal("mutating one result changed later analyses")
	}
}
