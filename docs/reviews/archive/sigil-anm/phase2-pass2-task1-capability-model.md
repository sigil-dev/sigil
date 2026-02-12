# Phase 2 Task 1 Review (Pass 2): Capability Model and Glob Matching

**Bead:** sigil-anm.1
**Files:** `internal/security/capability.go` (147 lines), `internal/security/capability_test.go` (130 lines)
**Verdict:** PASS
**Tests:** 33/33 passing (with `-race`)

## Spec Compliance

All required API surface present and correct:

- `MatchCapability(pattern, cap string) bool` -- glob matching on dot-separated segments
- `CapabilitySet` with `NewCapabilitySet`, `Contains`, `AllowedBy`
- All 12 spec test cases covered (11 directly in TestMatchCapability, 1 via CapabilitySet)

## Design Doc Alignment

Matches `docs/design/03-security-model.md`:

- Additive model (starts with nothing)
- Fail-closed (unknown = denied)
- Glob-based matching for all design doc capability examples
- Intersection semantics via `AllowedBy`

## Security Analysis

- No bypass vectors found
- Memoized recursion prevents DoS on pathological inputs
- Immutable sets (constructor copies input slice)
- No string concatenation or format-string injection

## Test Coverage

33 test cases across 3 functions covering exact match, wildcard (single/multi segment), in-segment globs, path-scoped, self-scoped, input validation, set operations.

## Open Items

5 suggestions tracked in sigil-anm.16 (P3): test traceability for spec case #5, testify consistency, conditional logic in tests, input length bounds, package-level docs.
