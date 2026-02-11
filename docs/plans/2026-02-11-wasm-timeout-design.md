# Wasm Host: Context-Based Execution Timeout

**Date:** 2026-02-11
**Issue:** sigil-anm.10
**Decision:** D035

## Summary

Replace the unimplemented fuel metering in the Wazero-based Wasm host with context-based execution timeout. Keep Wazero as the runtime — do not switch to a CGO-based alternative.

## Background

Phase 2 Task 8 specified a Wasm host with `WithFuelLimit(n uint64)` for instruction-level gas metering. The initial implementation omitted fuel metering entirely (`NewHost` discarded all options via blank identifier). An independent code review flagged this as CRITICAL.

The original issue (sigil-anm.10) proposed replacing Wazero with a CGO-based runtime (Wasmer-go or Wasmtime-go) to get native fuel metering. A brainstorming session evaluated this approach and rejected it.

## Alternatives Evaluated

### A: Wasmtime-go (CGO)

- Full fuel metering API (`SetConsumeFuel`, `SetFuel`, `GetFuel`)
- **Rejected:** No precompiled arm64/darwin binaries — requires building Wasmtime C library from source on Apple Silicon. Adds CI complexity for a feature we don't need at instruction granularity.

### B: Wasmer-go (CGO)

- **Rejected:** Last release v1.0.4 in August 2021. Effectively unmaintained. arm64/darwin support never fully shipped. No clear fuel metering API.

### C: Wasm bytecode injection (go-wasm-metering)

- Transforms `.wasm` binaries at load time to inject gas-counting calls into every basic block. Runtime-agnostic (works with Wazero).
- **Rejected:** go-wasm-metering abandoned (2019, 19 commits). Rolling our own Wasm binary transformer is high complexity for a property we don't need. Bytecode injection is designed for blockchain/smart-contract deterministic billing — Sigil plugins don't need this.

### D: Keep Wazero + context-based timeout (chosen)

- `context.WithTimeout` + Wazero's `WithCloseOnContextDone(true)` bounds execution time.
- Not instruction-granular, but satisfies the actual security goal: prevent runaway plugin execution.
- Zero new dependencies, idiomatic Go, Wazero-native.

## Design

### Interface

```go
package wasm

type Host struct {
    runtime     wazero.Runtime
    execTimeout time.Duration  // zero = no timeout
}

type Option func(*Host)

// WithExecTimeout sets the maximum execution duration for module function calls.
func WithExecTimeout(d time.Duration) Option

// NewHost creates a Wazero runtime with the given options applied.
func NewHost(opts ...Option) (*Host, error)

// ExecTimeout returns the configured execution timeout (zero if unset).
func (h *Host) ExecTimeout() time.Duration

// LoadModule compiles and instantiates a Wasm module.
// Rejects empty or whitespace-only names.
func (h *Host) LoadModule(ctx context.Context, name string, wasmBytes []byte) (*Module, error)

// Close shuts down the runtime and releases resources.
func (h *Host) Close() error
```

### Module

```go
type Module struct {
    name        string
    compiled    wazero.CompiledModule
    instance    api.Module
    execTimeout time.Duration  // inherited from Host
}

// Name returns the module's registered name.
func (m *Module) Name() string

// Close releases the module instance.
func (m *Module) Close(ctx context.Context) error

// CallWithTimeout invokes an exported function, wrapping the context
// with the host's execTimeout if configured.
func (m *Module) CallWithTimeout(ctx context.Context, fnName string, params ...uint64) ([]uint64, error)
```

### Runtime Configuration

`NewHost` uses `wazero.NewRuntimeWithConfig` (not `wazero.NewRuntime`) with `WithCloseOnContextDone(true)`. This tells Wazero to insert periodic context checks into both interpreter and compiler paths. When a deadline fires, in-flight Wasm execution is interrupted.

### Timeout Boundary

Timeout applies at the **call site** (`CallWithTimeout`), not at `LoadModule`. Compilation and instantiation should complete regardless of timeout configuration. This keeps `LoadModule` a pure load/compile step.

### Input Validation

`LoadModule` rejects empty or whitespace-only module names with a validation error before attempting compilation (review suggestion S3).

## Tests

All tests use real Wasm modules from `testdata/` fixtures (compiled from `.wat` sources).

### Test Fixtures

| File | Source | Exports |
|------|--------|---------|
| `testdata/add.wasm` | `add.wat` | `add(i32, i32) -> i32` |
| `testdata/infinite_loop.wasm` | `infinite_loop.wat` | `loop()` — never terminates |

### Test Cases

| Test | Validates |
|------|-----------|
| `TestWasmHost_LoadAndCallModule` | Create host → load module → call exported function → verify result → close |
| `TestWasmHost_ModuleIsolation` | Two modules on same host have independent state; closing one doesn't affect the other |
| `TestWasmHost_ExecTimeoutEnforced` | Host with `WithExecTimeout(50ms)` → load infinite loop → call → assert error (context deadline exceeded) |
| `TestWasmHost_LoadModule_EmptyName` | `LoadModule("", ...)` and `LoadModule("  ", ...)` return validation error |

## Files Changed

| File | Change |
|------|--------|
| `internal/plugin/wasm/host.go` | Rewrite: apply options, use `NewRuntimeWithConfig`, add `WithExecTimeout`, `ExecTimeout()`, `CallWithTimeout`, empty-name guard |
| `internal/plugin/wasm/host_test.go` | Rewrite: 4 test cases using `testdata/` fixtures |
| `internal/plugin/wasm/testdata/add.wat` | New: minimal add function |
| `internal/plugin/wasm/testdata/add.wasm` | New: compiled fixture |
| `internal/plugin/wasm/testdata/infinite_loop.wat` | New: infinite loop function |
| `internal/plugin/wasm/testdata/infinite_loop.wasm` | New: compiled fixture |
| `docs/decisions/decision-log.md` | Append D035 |

## What Does NOT Change

- Wazero dependency stays in `go.mod`
- Wasm tier's position in the three-tier plugin hierarchy
- Plugin manager's interface to the Wasm host (`NewHost`, `LoadModule`, `Close`)
- Security guarantees: memory-safe, no syscalls, bounded execution
