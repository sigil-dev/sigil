# Phase 2 Task 8 Review: Wasm Host (Wazero)

**Bead:** sigil-anm.8
**Verdict:** INCOMPLETE -- requires fixes before passing gate review
**Files:** `internal/plugin/wasm/host.go`, `internal/plugin/wasm/host_test.go`

## Spec Compliance

Module loading and basic lifecycle (create/load/close) work correctly. Code quality is good.

**However, fuel metering is entirely missing:**

| Requirement | Status |
|---|---|
| `Host` struct wrapping `wazero.Runtime` | PASS |
| `NewHost(opts ...Option)` | PARTIAL -- options silently discarded |
| `LoadModule(ctx, name, wasmBytes)` | PASS |
| `Close()` | PASS |
| `WithFuelLimit(n uint64) Option` | **MISSING** |
| `FuelLimit() uint64` | **MISSING** |
| `TestWasmHost_Create` | PASS |
| `TestWasmHost_LoadModule` | PASS |
| `TestWasmHost_FuelMeteringEnforced` | **MISSING** |

## Critical Issues

1. **`WithFuelLimit` and `FuelLimit` entirely absent** -- The `Option` function type is defined but serves no purpose. `NewHost` uses blank identifier `_` to discard all options. The `Host` struct has no `fuelLimit` field. Fuel metering is a core design goal of the Wasm tier.

2. **`TestWasmHost_FuelMeteringEnforced` not implemented** -- Only 2 of 3 required spec tests present.

## Important Issues

3. **`NewHost` silently discards options** -- Callers passing `WithFuelLimit(1000)` get no error and no effect. Should iterate and apply options.

4. **Runtime created with defaults** -- Uses `wazero.NewRuntime(ctx)`. Should use `wazero.NewRuntimeWithConfig(ctx, cfg)` to support configuration threading.

## Required Actions Before Task Completion

1. Add `fuelLimit uint64` field to `Host` struct
2. Implement `WithFuelLimit(n uint64) Option`
3. Implement `FuelLimit() uint64` getter
4. Apply options in `NewHost` (replace `_`, iterate and apply)
5. Add `TestWasmHost_FuelMeteringEnforced` test
6. Use `wazero.NewRuntimeWithConfig` instead of `wazero.NewRuntime`

## Suggestions

| # | Finding | Recommendation | Resolution |
|---|---------|----------------|------------|
| S1 | Missing `testdata/echo.wasm` | Inline `minimalWasm()` works for now; add fixtures for integration tests later. | Open (backlog) |
| S2 | `Module` type could be richer | Add `Exports()`, `MemorySize()` for introspection. | Open (backlog) |
| S3 | `LoadModule` doesn't validate empty name | Add guard clause. | **Closed:** sigil-anm.22 (empty name validation added) |
| S4 | Commit message says "module loading" not "fuel metering" | Accurately reflects what was implemented, but signals awareness of the omission. | N/A (informational) |
