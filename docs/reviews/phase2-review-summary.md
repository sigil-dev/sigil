# Phase 2 Core Runtime -- Independent Review Summary

**Branch:** `feat/anm-phase2-subagents`
**Epic:** `sigil-anm`
**Reviewer:** Claude Opus 4.6 (independent agent context)
**Date:** 2026-02-11
**Spec:** `docs/plans/02-phase-2-core-runtime.md`
**Design docs:** `docs/design/02-plugin-system.md`, `docs/design/03-security-model.md`

## Overview

All 8 tasks in the epic were reviewed by independent Opus agents running in parallel. Each agent read the source files, ran tests via `task test`, cross-referenced the spec and design docs, and produced a detailed findings report.

**Overall verdict:** 6 of 8 tasks PASS, 1 PASS with important fixes recommended, 1 INCOMPLETE (missing spec features).

## Summary by Task

| Task | Bead | Verdict | Critical | Important | Suggestions |
|------|-------|---------|----------|-----------|-------------|
| 1. Capability Model | sigil-anm.1 | STRONG PASS | 0 | 0 | 5 |
| 2. Security Enforcer | sigil-anm.2 | PASS | 0 | 1 | 3 |
| 3. Plugin Manifest | sigil-anm.3 | PASS | 0 | 1 | 3 |
| 4. Lifecycle State Machine | sigil-anm.4 | PASS | 0 | 2 | 3 |
| 5. Plugin Manager | sigil-anm.5 | PASS | 0 | 1 | 4 |
| 6. go-plugin Host | sigil-anm.6 | PASS (with fixes) | 0 | 2 | 0 |
| 7. Sandbox Config | sigil-anm.7 | PASS (with gaps) | 2 | 4 | 7 |
| 8. Wasm Host | sigil-anm.8 | INCOMPLETE | 2 | 2 | 4 |

## Critical Issues (Must Fix)

### Task 7: Sandbox Config
1. **Seatbelt profile path injection** -- Manifest-supplied paths are interpolated unsanitized into the Seatbelt profile string. A crafted path can inject arbitrary sandbox rules including `(allow default)`, disabling all sandboxing.
2. **Invalid Seatbelt `(path ...)` syntax** -- Lines 105-106 pass multiple paths to a single `(path ...)` filter. Seatbelt's `path` filter accepts only a single argument. Rules will not match correctly.

### Task 8: Wasm Host
1. **`WithFuelLimit` and `FuelLimit` entirely absent** -- The spec explicitly requires these. The `Option` function type is defined but `NewHost` discards all options via blank identifier `_`. Fuel metering is a core design goal of the Wasm tier.
2. **`TestWasmHost_FuelMeteringEnforced` missing** -- Only 2 of 3 required spec tests are implemented.

## Important Issues (Should Fix)

### Task 2: Security Enforcer
- **3 missing spec test cases**: `AllowThreeWayIntersection`, `UserWithNoPermissions`, `AuditLogging` are explicitly listed in the spec but absent. `UserWithNoPermissions` (empty permission set edge case) is security-critical.

### Task 3: Plugin Manifest
- **No semver validation on Version field** -- Internal manifest accepts any non-empty string while public SDK enforces strict semver.

### Task 4: Lifecycle State Machine
- **Missing draining/stopping -> error transitions** -- Design doc implies these for timeout/failure cases during drain and graceful shutdown.
- **No concurrency test** -- Implementation uses `sync.RWMutex` but no test exercises concurrent access.

### Task 5: Plugin Manager
- **No logging when skipping invalid manifests** -- Spec says invalid manifests should be "logged" when skipped. Current implementation silently continues.

### Task 6: go-plugin Host
- **Slice mutation bug in `buildCommand`** -- `append(sandboxCmd, binaryPath)` may mutate the caller's slice if it has spare capacity.
- **Should embed `plugin.NetRPCUnsupportedPlugin`** instead of `plugin.Plugin` interface -- Prevents nil-interface panics if net/RPC methods are ever called.

### Task 7: Sandbox Config
- **Network rule ignores specific host:port restrictions** -- Seatbelt profile allows all TCP when `Network.Allow` is non-empty, ignoring actual hosts/ports.
- **No test for unsupported OS error path, empty sandbox config, or Seatbelt profile content.**
- **`/lib64` unconditionally mounted** in bwrap -- Will fail on systems without `/lib64`.
- **bwrap path validation missing** -- Paths from manifest could start with `--` and confuse argument parser.

### Task 8: Wasm Host
- **`NewHost` silently discards options** via blank identifier `_`.
- **Runtime created with defaults** -- Should use `wazero.NewRuntimeWithConfig` for future configuration support.

## What Was Done Well

- **Security model is solid**: Four-way enforcement logic in the Enforcer is correct, fail-closed, and impossible to bypass. Deny-set properly overrides allow-set.
- **Capability matching is excellent**: Memoized recursion prevents algorithmic complexity attacks. Dual-mode wildcard (segment-level + in-segment) correctly handles both `sessions.*` and `filesystem.read./data/*`.
- **Lifecycle state machine is exact**: All 9 valid transitions and 3 invalid transitions match the spec precisely.
- **Plugin manager integrates cleanly**: Discovery, manifest parsing, capability registration, and enforcer integration all work correctly.
- **go-plugin host is clean**: Correct gRPC-only protocol, proper proto references, all four plugin wrappers implemented.
- **Code quality is consistently high**: Structured errors, SPDX headers, table-driven tests, proper mutex usage, idiomatic Go throughout.
- **Test coverage exceeds spec in most tasks**: Tasks 1 and 2 in particular add many beyond-spec test cases.

## Recommended Actions

### Blocking (before epic closure)
1. Fix Seatbelt profile syntax errors (Task 7)
2. Add path sanitization to Seatbelt profile generation (Task 7)
3. Implement `WithFuelLimit`, `FuelLimit()`, and apply options in `NewHost` (Task 8)
4. Add `TestWasmHost_FuelMeteringEnforced` test (Task 8)

### Should fix (before merge to main)
5. Add 3 missing enforcer test cases (Task 2)
6. Fix `buildCommand` slice mutation (Task 6)
7. Embed `NetRPCUnsupportedPlugin` instead of `plugin.Plugin` interface (Task 6)
8. Add logging for skipped invalid manifests (Task 5)

### Nice to have (can be follow-up issues)
9. Add semver validation to internal manifest (Task 3)
10. Add draining/stopping -> error transitions (Task 4)
11. Add concurrency test for lifecycle state machine (Task 4)
12. File issue for seccomp filter support (Task 7)

## Individual Reports

Detailed findings for each task are in separate files:
- [Task 1: Capability Model](phase2-task1-capability-model.md)
- [Task 2: Security Enforcer](phase2-task2-security-enforcer.md)
- [Task 3: Plugin Manifest](phase2-task3-plugin-manifest.md)
- [Task 4: Lifecycle State Machine](phase2-task4-lifecycle-sm.md)
- [Task 5: Plugin Manager](phase2-task5-plugin-manager.md)
- [Task 6: go-plugin Host](phase2-task6-goplugin-host.md)
- [Task 7: Sandbox Config](phase2-task7-sandbox-config.md)
- [Task 8: Wasm Host](phase2-task8-wasm-host.md)
