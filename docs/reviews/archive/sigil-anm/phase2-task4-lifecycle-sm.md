# Phase 2 Task 4 Review: Plugin Lifecycle State Machine

**Bead:** sigil-anm.4
**Verdict:** PASS
**Files:** `internal/plugin/lifecycle.go` (124 lines), `internal/plugin/lifecycle_test.go` (54 lines)

## Spec Compliance -- PASS

All requirements met:
- 8 states in correct order (iota-based enum)
- `ValidTransition(from, to) bool` with adjacency map
- `Instance` struct (named `Instance` not `PluginInstance` -- justified Go convention to avoid stutter)
- `TransitionTo(state) error` validates and updates atomically
- 9 valid + 3 invalid transitions tested
- Instance creation + invalid transition test present

## Important Issues

1. **Missing draining/stopping -> error transitions** -- Design doc hot-reload flow implies these for timeout/failure cases. Spec doesn't list them, so implementation is spec-compliant but should be filed as follow-up.

2. **No concurrency test** -- Implementation uses `sync.RWMutex` but no test spawns goroutines to exercise concurrent access. Example: 100 goroutines racing to transition, assert exactly one succeeds.

## Suggestions

| # | Finding | Recommendation | Resolution |
|---|---------|----------------|------------|
| S1 | `ValidTransition` safe for out-of-range states | Nil map lookup returns zero value. Correct but worth documenting. | **Closed:** sigil-anm.19 (doc comment added) |
| S2 | No recovery path from error state | By design -- new `Instance` created instead. Document on `StateError` entry. | **Closed:** sigil-anm.19 (doc comment on StateError) |
| S3 | `String()` method hand-written | Consider `//go:generate stringer -type=PluginState` for auto-sync. Low priority. | **Closed:** sigil-anm.19 (documented preference for hand-written) |
