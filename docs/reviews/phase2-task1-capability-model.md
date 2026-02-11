# Phase 2 Task 1 Review: Capability Model and Glob Matching

**Bead:** sigil-anm.1
**Verdict:** STRONG PASS
**Files:** `internal/security/capability.go` (146 lines), `internal/security/capability_test.go` (129 lines)

## Spec Compliance -- PASS

All required API elements present and correct:
- `MatchCapability(pattern, cap string) bool`
- `CapabilitySet` type with `NewCapabilitySet` constructor
- `Contains(cap string) bool`
- `AllowedBy(other CapabilitySet, cap string) bool`
- `*` matches one or more segments (line 61: loop starts at `ci + 1`)

### Beneficial Deviations
1. **Input validation** (`isValidDottedString`): Rejects malformed inputs with leading/trailing dots or consecutive dots.
2. **In-segment glob matching** (`matchInSegmentGlob`): When `*` appears within a segment (e.g., `foo*bar`), it acts as an in-segment character glob. Consistent with design doc examples like `filesystem.read./data/*`.

## Test Coverage

All spec test cases present except one minor gap:
- Missing: `sessions.*` vs `messages.send` (cross-prefix mismatch with wildcard)
- 33 test cases across 3 test functions (14 beyond spec)
- Tests use `t.Fatalf` instead of testify assertions (minor inconsistency with project conventions)

## Security Analysis

**Strengths:**
- Memoized recursion prevents O(2^n) matching on pathological patterns
- Fail-closed: empty patterns and empty capabilities return `false`
- Immutable CapabilitySet via slice copy in constructor

**No critical or important issues found.**

## Suggestions

| # | Finding | Recommendation |
|---|---------|----------------|
| S1 | Missing spec test: `sessions.*` vs `messages.send` | Add test case |
| S2 | Tests use `t.Fatalf` instead of testify | Switch to `assert.Equal` for consistency |
| S3 | Conditional logic in `TestCapabilitySetContains` loop | Move `CapabilitySet` into test table struct |
| S4 | No input length bounds on `MatchCapability` | Add max segment count check if exposed to untrusted input |
| S5 | No docs that only `*` glob syntax is supported | Add package-level comment clarifying glob subset |
