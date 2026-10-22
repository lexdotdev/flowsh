// Package policy evaluates reports using trusted caller rules.
package policy

import (
	"fmt"
	"maps"
	"slices"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
)

// Action is Allow, Review, or Deny; its zero value is invalid.
type Action string

const (
	Allow  Action = "allow"
	Review Action = "review"
	Deny   Action = "deny"
)

// Config sets signal, effect-kind, and exact-grade rules.
type Config struct {
	Unknown      Action
	Conservative Action
	Exfiltration Action
	Cradle       Action
	Ingest       Action
	Effects      map[engine.EffectKind]Action
	Grades       map[engine.Destructiveness]Action
}

// Policy holds immutable rules; its nil and zero values deny.
type Policy struct {
	config Config
}

// Match names a restrictive rule without copying command text.
type Match struct {
	Code   string `json:"code"`
	Action Action `json:"action"`
}

// Decision contains the strongest action and sorted matches.
type Decision struct {
	Action  Action  `json:"action"`
	Matches []Match `json:"matches,omitempty"`
}

// Allowed reports whether the decision explicitly grants permission.
func (d Decision) Allowed() bool { return d.Action == Allow }

// New applies defaults, validates rules, and copies their maps.
func New(c Config) (*Policy, error) {
	for _, field := range []struct {
		name       string
		value      *Action
		fallback   Action
		incomplete bool
	}{
		{"unknown", &c.Unknown, Deny, true},
		{"conservative", &c.Conservative, Review, true},
		{"exfiltration", &c.Exfiltration, Deny, false},
		{"cradle", &c.Cradle, Review, false},
		{"ingest", &c.Ingest, Allow, false},
	} {
		if *field.value == "" {
			*field.value = field.fallback
		}
		if !validAction(*field.value) || (field.incomplete && *field.value == Allow) {
			return nil, fmt.Errorf("policy: invalid %s action", field.name)
		}
	}
	for kind, action := range c.Effects {
		if !kind.Valid() || !validAction(action) {
			return nil, fmt.Errorf("policy: invalid effect rule")
		}
	}
	for grade, action := range c.Grades {
		if !grade.Valid() || !validAction(action) {
			return nil, fmt.Errorf("policy: invalid grade rule")
		}
	}
	c.Effects = maps.Clone(c.Effects)
	c.Grades = maps.Clone(c.Grades)
	return &Policy{config: c}, nil
}

// Evaluate applies rules to r without changing it.
func (p *Policy) Evaluate(r *api.Report) Decision {
	// New fills Unknown; an empty value marks a zero policy.
	if p == nil || p.config.Unknown == "" {
		return denied("invalid_policy")
	}
	if r == nil || r.Tool != api.ToolName || r.ToolVersion != api.ToolVersion ||
		r.SchemaVersion != api.SchemaVersion || r.Validate() != nil ||
		!r.Score.Grade.Valid() {
		return denied("invalid_report")
	}
	switch api.Lang(r.Lang) {
	case api.LangBash, api.LangPOSIX, api.LangPowerShell, api.LangJavaScript:
	default:
		return denied("invalid_report")
	}
	if !r.Covered() {
		return denied("uncovered_report")
	}
	matched := make(map[string]Action)
	add := func(code string, action Action, applies bool) {
		if applies && (action == Review || action == Deny) {
			matched[code] = action
		}
	}
	add("unknown", p.config.Unknown, r.Top || r.HasTop())
	add("conservative", p.config.Conservative, r.Conservative)
	add("exfiltration", p.config.Exfiltration, len(r.Score.ExfilPairs) > 0)
	add("cradle", p.config.Cradle, len(r.Score.CradleFlows) > 0)
	add("ingest", p.config.Ingest, len(r.Score.IngestFlows) > 0)
	add("grade:"+r.Score.Grade.String(), p.config.Grades[r.Score.Grade], true)
	for _, effect := range r.Effects {
		add("effect:"+string(effect.Kind), p.config.Effects[effect.Kind], true)
	}
	result := Decision{Action: Allow}
	for _, code := range slices.Sorted(maps.Keys(matched)) {
		action := matched[code]
		result.Matches = append(result.Matches, Match{Code: code, Action: action})
		if result.Action == Allow || action == Deny {
			result.Action = action
		}
	}
	return result
}

func denied(code string) Decision {
	return Decision{Action: Deny, Matches: []Match{{Code: code, Action: Deny}}}
}

func validAction(action Action) bool {
	return action == Allow || action == Review || action == Deny
}
