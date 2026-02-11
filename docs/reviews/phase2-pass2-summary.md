# Phase 2 Core Runtime -- Independent Review Pass 2 Summary

**Branch:** `feat/anm-phase2-subagents`
**Epic:** `sigil-anm`
**Reviewer:** Claude Opus 4.6 (8 independent parallel agents)
**Date:** 2026-02-11
**Spec:** `docs/plans/02-phase-2-core-runtime.md`
**Design docs:** `docs/design/02-plugin-system.md`, `docs/design/03-security-model.md`

## Overview

Second independent review pass after all bug fixes from pass 1 were applied. Each of the 8 tasks was reviewed by a separate Opus agent running in parallel, reading source, running tests with `-race`, cross-referencing the spec and design docs, and verifying all prior bug fix commits.

**Overall verdict: ALL 8 TASKS PASS. No new critical or important issues found.**

## Summary by Task

| Task | Bead | Verdict | Bug Fixes Verified | New Issues | Open Suggestions |
|------|-------|---------|--------------------|------------|------------------|
| 1. Capability Model | sigil-anm.1 | PASS | -- (none needed) | 0 | 5 (sigil-anm.16) |
| 2. Security Enforcer | sigil-anm.2 | PASS | sigil-anm.11 (3 missing tests) | 0 | 3 (sigil-anm.17) |
| 3. Plugin Manifest | sigil-anm.3 | PASS | sigil-anm.14 (semver validation) | 0 | 3 (sigil-anm.18) |
| 4. Lifecycle State Machine | sigil-anm.4 | PASS | sigil-anm.15 (transitions + concurrency) | 0 | 3 (sigil-anm.19) |
| 5. Plugin Manager | sigil-anm.5 | PASS | sigil-anm.13 (logging) | 0 | 4 (sigil-anm.20) |
| 6. go-plugin Host | sigil-anm.6 | PASS | sigil-anm.12 (slice mutation + NetRPC) | 0 | 0 |
| 7. Sandbox Config | sigil-anm.7 | PASS | sigil-anm.9 (5 security fixes) | 2 (info) | 7 (sigil-anm.21) |
| 8. Wasm Host | sigil-anm.8 | PASS | D035 design change (timeout replaces fuel) | 3 (minor) | 0 |

## Test Results

All tests pass across all packages with `-race` flag:

| Package | Tests | Status |
|---------|-------|--------|
| `internal/security` | 46 (33 capability + 13 enforcer) | PASS |
| `internal/plugin` | 27 (8 manifest + 15 lifecycle + 4 instance) | PASS |
| `internal/plugin/goplugin` | 6 | PASS |
| `internal/plugin/sandbox` | 24 (1 SKIP on Darwin) | PASS |
| `internal/plugin/wasm` | 4 | PASS |
| `pkg/plugin` | 46 (SDK validation) | PASS |

## Bug Fix Verification

All 12 bug fixes from pass 1 were verified as correctly implemented:

| # | Fix | Bead | Commit | Pass 2 Verification |
|---|-----|------|--------|---------------------|
| 1 | Seatbelt path injection + syntax | sigil-anm.9 | `536d051` | Regex blocklist correct, per-path rules, tests thorough |
| 2 | Network host:port enforcement | sigil-anm.9 | `536d051` | Per-entry port-specific rules with validation |
| 3 | `/lib64` conditional mount | sigil-anm.9 | `536d051` | `checkDirExists` guard with test stubbing |
| 4 | bwrap path validation | sigil-anm.9 | `536d051` | Dash-prefix rejection + `--` separator |
| 5 | Missing sandbox content tests | sigil-anm.9 | `536d051` | 21 internal tests added |
| 6 | 3 missing enforcer spec tests | sigil-anm.11 | `a29834c` | AllowThreeWayIntersection, UserWithNoPermissions, AuditLogging all solid |
| 7 | Silent manifest skip logging | sigil-anm.13 | `c69d090`, `a9189b8` | slog.Warn on parse error and ReadFile error, both tested |
| 8 | Missing semver validation | sigil-anm.14 | `0b67f3a` | Regex matches pkg/plugin, 13 test cases |
| 9 | Missing draining/stopping→error | sigil-anm.15 | `bc92ddf` | Both transitions in table, tested with full lifecycle path |
| 10 | Missing concurrency test | sigil-anm.15 | `bc92ddf` | 50-goroutine race test, exactly 1 winner |
| 11 | Slice mutation in buildCommand | sigil-anm.12 | `ca34ce2` | `slices.Clone` fix, regression test with spare capacity |
| 12 | NetRPCUnsupportedPlugin embedding | sigil-anm.12 | `ca34ce2` | All 4 wrappers return error on Server() |

## New Findings (This Pass)

### Task 7: Sandbox Config (Informational)

- **N1:** Seatbelt network rules allow any host on permitted ports (`*:443`). This is a Seatbelt platform limitation, not a code bug. Hostname filtering requires userspace proxy (anticipated by `Proxy` field).
- **N2:** `expandPath` handles `~` prefix but not `~user` syntax. Unlikely to trigger since manifest schema doesn't document `~user`.

### Task 8: Wasm Host (Minor)

- **M1:** Error code `CodePluginRuntimeStartFailure` reused for call-time missing-function error. A dedicated call error code would be more precise.
- **M2:** `fn.Call` error not wrapped with `sigilerr.Wrapf`. Raw Wazero errors pass through.
- **M3:** No documented procedure for recompiling `.wat` to `.wasm` test fixtures.

None of these are blocking. All are suggestions for future improvement.

## Remaining Open Items

| Bead | Title | Priority | Items |
|------|-------|----------|-------|
| sigil-anm.16 | Capability: test + doc suggestions | P3 | 5 items (test traceability, testify, length bounds, package docs) |
| sigil-anm.17 | Enforcer: nil guard + ID counter | P3 | 3 items (nil audit store, global counter, actor semantics) |
| sigil-anm.18 | Manifest: design doc fields + timeout | P4 | 3 items (test isolation, field tracking, timeout parsing) |
| sigil-anm.19 | Lifecycle: documentation + stringer | P4 | 3 items (ValidTransition docs, error state docs, stringer) |
| sigil-anm.20 | Manager: unused ctx + ordering | P3 | 4 items (ctx, List ordering, Get/List tests, duplicate names) |
| sigil-anm.21 | Sandbox: hardening pass | P3 | 7 items (seccomp, unshare-pid, profile file, binaryPath validation) |

All are tracked, prioritized, and non-blocking for Phase 2 gate.

## Conclusion

The Phase 2 Core Runtime implementation is complete and correct. All spec requirements are met. All critical and important issues from the first review pass have been resolved with proper fixes and regression tests. The security model is solid with fail-closed enforcement, no bypass paths, and comprehensive input validation. Code quality is consistently high across all 8 tasks.

**Recommendation: Phase 2 gate checklist is satisfied. Epic is ready for closure.**

## Individual Reports

Detailed findings for each task are in the pass 2 review files:
- [Task 1: Capability Model](phase2-pass2-task1-capability-model.md)
- [Task 2: Security Enforcer](phase2-pass2-task2-security-enforcer.md)
- [Task 3: Plugin Manifest](phase2-pass2-task3-plugin-manifest.md)
- [Task 4: Lifecycle State Machine](phase2-pass2-task4-lifecycle-sm.md)
- [Task 5: Plugin Manager](phase2-pass2-task5-plugin-manager.md)
- [Task 6: go-plugin Host](phase2-pass2-task6-goplugin-host.md)
- [Task 7: Sandbox Config](phase2-pass2-task7-sandbox-config.md)
- [Task 8: Wasm Host](phase2-pass2-task8-wasm-host.md)
