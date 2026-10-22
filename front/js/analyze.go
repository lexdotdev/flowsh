// Package js provides the opaque JavaScript frontend.
package js

import "github.com/v0lka/flowsh/engine"

// Result holds effects and the frontend's analysis status.
type Result struct {
	Effects      []engine.Effect
	Top          bool
	Conservative bool
	Reason       string
}

// Analyze returns one top effect for every source.
func Analyze(_ string) *Result {
	return &Result{
		Effects: []engine.Effect{{
			Kind:      engine.KindCodeExec,
			Target:    engine.ScopeTop(),
			Mode:      engine.ModeDirect,
			Certainty: engine.CertaintyCertain,
		}},
		Top:          true,
		Conservative: true,
		Reason:       "JavaScript parsing and evaluation are not implemented: treating source as ⊤",
	}
}
