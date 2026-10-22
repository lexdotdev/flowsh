# JavaScript Frontend

## Purpose

`front/js` establishes JavaScript source targeting Node.js as an input dialect. It is a conservative foundation stub: every source is opaque and produces one top-element effect. Registration and report integration are available; parsing, evaluation, and Node API effect recognition are future milestones.

## Key Files

- `front/js/analyze.go` — `Result` and the unconditional `Analyze` stub.
- `front/js/analyze_test.go` — opaque-input contract and independent results.
- `internal/analysis/analyze.go` — `LangJavaScript`, alias parsing, `analyzeJS`, and report assembly.
- `api/api.go` — public language constant and forwarding analysis surface.
- `api/api_test.go` — shared dialect and report-contract checks.
- `cmd/flowsh/smoke_test.go` — JavaScript CLI report smoke check.
- `policy/policy_test.go` — JS reports pass language validation and retain uncertainty restrictions.
- `testdata/corpus/guardfall_js.json` — five original A–E conservative-coverage cases.

## Core Types

```go
type Result struct {
	Effects      []engine.Effect
	Top          bool
	Conservative bool
	Reason       string
}

func Analyze(src string) *Result
```

`Analyze` accepts the source without inspecting it. It returns a fresh result containing one `CodeExec` effect over `ScopeTop()`, in `ModeDirect`, with `CertaintyCertain`, `TaintBottom()`, and `Reversible:false`. Both status flags are true. The fixed reason explains that parsing and evaluation are not implemented; it contains no source text.

## Flow

```text
--lang js/javascript/node/nodejs (trimmed, case-insensitive)
    -> ParseLang -> LangJavaScript ("js")
    -> Analyzer.AnalyzeWith -> analyzeJS
    -> js.Analyze(src) -> Result{one CodeExec(top), Top, Conservative, Reason}
    -> normalizeEffects -> ComputeDestructiveness -> buildWhy -> ScoreEffects
    -> buildCanonical -> Report{lang:"js", input, root, ...}
```

The shared engine determines the Critical grade. The facade supplies the normal report identity, input/root, explanation, and canonical form. `commands` stays zero, `resolution` stays its zero value, and `commandCalls` and `destructive` are omitted because the stub discovers no calls or destructive-table matches. The explanation uses the fixed `literal:js-opaque` fallback marker with no source location. It identifies opaque analysis without claiming a source token was parsed; the explanatory sentence stays in `reason`. Report fields and version tags retain their existing shapes/values.

## Invariants

- Every library input, including empty, whitespace-only, malformed, and valid source, yields exactly one top-element effect with a nonempty reason.
- Reports have `Top`, `HasTop()`, `Conservative`, and `Covered()` true.
- `Covered()` expresses conservative no-silent-miss coverage; semantic JavaScript coverage remains unimplemented.
- Each analysis owns its result and effect slice; calls are deterministic and independent.
- `front/js` imports only `engine`; the analysis path remains offline and side-effect-free.
- The policy package recognizes canonical `"js"` and applies its normal unknown/conservative rules: Deny by default, optionally Review, with uncertainty always restricting Allow.
- Every registered language exercises GuardFall classes A–E; corpus growth updates the baseline case count while preserving the existing latency and recall limits.

## Configuration

`Options.Root` is stamped into `Report.Root`. `Options.Vars` remains bash/POSIX-only, and `Options.Windows` remains PowerShell-only; JavaScript ignores both. The stub reads no host variables, files, or Node runtime state.

The CLI requires an explicit JS language selection. `--lang auto` continues to choose bash or PowerShell. Existing CLI empty-input errors and batch line splitting apply before the frontend runs.

## Extension Points

Add bounded parsing, evaluation, and effect mappings behind `Analyze` as JavaScript support grows. Unsupported constructs continue to degrade to top. Expand the corpus with each effect family; the initial A–E cases establish conservative coverage without claiming benign precision.

## Related Specs

- [Analysis Report](analysis-report.md) — registration, routing, options, and public API.
- [Frontend/Engine Contract](../contracts/frontend-engine.md) — effect boundary and degradation.
- [Layers](../architecture/layers.md) — dependency direction.
- [Conservatism](../architecture/conservatism.md) — the shared top shape.
- [CLI](cli.md) — input sources, aliases, and automatic language selection.
- [Report Policy](policy.md) — fail-closed report decisions.
