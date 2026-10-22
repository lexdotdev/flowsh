package analysis

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

func TestJavaScriptPureReports(t *testing.T) {
	a := mustAnalyzer(t)
	for _, tc := range []struct{ name, src string }{
		{"empty", ""}, {"pure", "const x=1;"}, {"finite loop", "let x=0;for(let i=0;i<3;i++)x+=i;"}, {"dormant body", "function f(){unknown()}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := a.AnalyzeWith(LangJavaScript, tc.src, Options{Root: "input.js"})
			if err := r.Validate(); err != nil {
				t.Fatal(err)
			}
			if r.Root != "input.js" || r.Input != tc.src || r.Lang != "js" {
				t.Fatalf("lost report identity: %+v", r)
			}
			if r.Effects == nil || len(r.Effects) != 0 || r.Top || r.Conservative || r.HasTop() || r.Covered() || r.Canonical != nil {
				t.Fatalf("fabricated effect/coverage: %+v", r)
			}
			if r.Commands != 0 || len(r.CommandCalls) > 0 || len(r.Destructive) > 0 {
				t.Fatalf("fabricated binding metadata: %+v", r)
			}
		})
	}
}

func TestJavaScriptDegradationLocations(t *testing.T) {
	a := mustAnalyzer(t)
	r := a.AnalyzeWith(LangJavaScript, "const x=1;\nunknown();", Options{Root: "input.js"})
	if r.Top || !r.Conservative || !r.HasTop() || !r.Covered() {
		t.Fatalf("wrong partial degradation: %+v", r)
	}
	if gaps := engine.WhyGaps(r.Effects, r.Why); len(gaps) > 0 {
		t.Fatalf("unexplained effects: %v", gaps)
	}
	found := false
	for _, trace := range r.Why {
		for _, step := range trace.Because {
			if step.Loc != nil && step.Loc.File == "input.js" && step.Loc.Line == 2 {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("missing reached-call location: %+v", r.Why)
	}
	for _, src := range []string{"const = (", "while(true){}"} {
		r = a.Analyze(LangJavaScript, src)
		if !r.Top || !r.Conservative || !r.HasTop() || r.Reason == "" {
			t.Fatalf("whole-program failure must be top: %+v", r)
		}
	}
}
