# ADR-0017: Report policy package

## Status

Accepted

Amends [ADR-0010](0010-public-embedding-api.md) by superseding its framing of
`api` as the sole public embedding surface. Its type-alias analysis API,
report-contract versioning, and separation from the CLI remain in force.
ADR-0010's status records this amendment; its decision text is otherwise
unchanged.

## Context

Embedding applications consume analysis reports to decide whether a command
can proceed or needs review. Each application otherwise repeats the same
checks for uncertainty, credential exfiltration, download-to-execution flows,
effect kinds, and score grades. Inconsistent checks can lose the analyser's
deny-or-inspect requirement.

ADR-0010 deliberately made `api` a small, auditable re-export of
`internal/analysis` with no behaviour of its own. Configurable decision rules
add behaviour and a second public contract. They need a layer above analysis
that preserves the existing report and lets callers choose rules appropriate
to their environment.

## Decision

Publish `github.com/v0lka/flowsh/policy` as an optional public package in the
existing Go module. It consumes `api.Report` and trusted caller-owned Go
configuration, returning `Allow`, `Review`, or `Deny` with deterministic
reason codes. `api` remains the public analysis entry point; `policy` is the
public decision layer.

The package's only intra-module dependencies are `api` for reports and
`engine` for effect-kind and score-grade types. No analysis package imports
`policy`. Policy adds no frontend, binder, or knowledge-base dependency of its
own, and performs no runtime I/O or command execution. It leaves parsing,
effects, scoring, CLI behaviour, and report versions unchanged.

`New` validates configuration and copies its maps. `Evaluate` validates the
report before applying rules; all matching restrictions combine with
`Deny > Review > Allow`. Unknown and conservative reports always require
Review or Deny. Missing, invalid, and incompatible reports deny with
`invalid_report`; otherwise-valid uncovered reports deny with
`uncovered_report`. This includes authentic no-effect reports for Bash `true`
and `:`, whose `Covered()` value is false. Nil and zero policies deny.

Configuration comes from the embedding application, independently of analysed
source. Execution, human approval, authorisation, and runtime isolation remain
the caller's responsibility. An Allow decision means that a valid, compatible,
covered report matched no configured restriction; it is not a proof of safety
or confinement.

## Consequences

- Embedders share deterministic decision rules without changing analysis or
  coupling the analyser to an application's enforcement mechanism.
- `api` retains its thin re-export contract, and all dependencies continue to
  point down toward the frozen core.
- The supported embedding surface now includes two packages. Policy actions,
  defaults, configuration validation, and reason codes require documentation,
  regression tests, and compatibility review independently of report versions.
- The coverage gate denies benign no-op commands as well as analysis misses;
  the distinct `uncovered_report` code exposes this limitation without calling
  their reports malformed.
- Defaults cannot express every application's threat model, and policy cannot
  recover effects missing from a report or authenticate caller-supplied reports.

## Alternatives Considered

- **Keep policy entirely in each consumer.** Preserves a single public package,
  but duplicates uncertainty checks, precedence, and diagnostics across
  integrations.
- **Add policy behaviour to `api`.** Mixes report production with configurable
  decisions and abandons the type-alias-only contract of ADR-0010.
- **Add policy to `engine` or `internal/analysis`.** Couples report production
  to consumer decisions and risks making effect or score computation depend on
  application rules.
- **Publish a separate Go module.** Adds release and version coordination for
  rules that consume this module's report and effect types; the single-module
  decision in [ADR-0008](0008-single-go-module.md) remains sufficient.

## Related Specs

- [Report Policy](../domains/policy.md) — configuration and decision contract.
- [Layer Architecture](../architecture/layers.md) — one-way dependencies.
- [Analysis Report](../domains/analysis-report.md) — input reports and coverage.
- [Embedding guide](../../docs/embedding.md) — consumer workflow and limits.
