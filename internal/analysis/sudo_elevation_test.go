package analysis

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestSudoElevationReachedFromFrontend pins the end-to-end routing of the
// sudo elevation: the two interpreter paths that never reach the ordinary
// binding flow — a wrapper that consumed the whole command line (`sudo -i`)
// and a wrapper over a dynamically-named command (`sudo $X`) — must still
// carry the binder's PrivEsc effect in the composed report, while
// non-privilege wrappers (`timeout 5`, `env -S`) and the refined -u
// suppression (`sudo -u nobody …`) stay elevation-free.
func TestSudoElevationReachedFromFrontend(t *testing.T) {
	a := mustAnalyzer(t)

	tests := []struct {
		name string
		src  string
		want bool
	}{
		{"bare sudo -i", `sudo -i`, true},
		{"sudo over dynamic command", `sudo $X`, true},
		{"sudo over dynamic quoted command", `sudo "$X"`, true},
		{"plain sudo command", `sudo whoami`, true},
		{"timeout consumed the line", `timeout 5`, false},
		{"env -S consumed the line", `env -S "cmd"`, false},
		{"sudo -u nobody -i", `sudo -u nobody -i`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := a.Analyze(LangBash, tc.src)
			if rep == nil {
				t.Fatal("nil report")
			}
			n := 0
			for _, e := range rep.Effects {
				if e.Kind == engine.KindPrivEsc {
					n++
				}
			}
			if tc.want && n == 0 {
				t.Errorf("%q: no PrivEsc effect in report (%d effects)", tc.src, len(rep.Effects))
			}
			if !tc.want && n > 0 {
				t.Errorf("%q: unexpected PrivEsc effect(s): %d", tc.src, n)
			}
		})
	}
}
