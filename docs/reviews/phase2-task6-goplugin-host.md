# Phase 2 Task 6 Review: go-plugin Host (Process Tier)

**Bead:** sigil-anm.6
**Verdict:** PASS with two recommended fixes
**Files:** `internal/plugin/goplugin/host.go` (126 lines), `internal/plugin/goplugin/host_test.go` (47 lines)

## Spec Compliance -- PASS

All required elements present:
- `HandshakeConfig()` with magic cookie (ProtocolVersion=1, key="SIGIL_PLUGIN")
- `PluginMap()` with all 4 types: "lifecycle", "channel", "tool", "provider"
- `ClientConfig(binary, sandbox)` creates `plugin.ClientConfig` with gRPC-only protocol
- All 4 gRPC plugin wrappers implement `GRPCServer` and `GRPCClient`
- All 3 spec tests present + 1 bonus (`TestHost_ClientConfig_WithSandbox`)

## Important Issues

1. **Slice mutation in `buildCommand`** (`host.go:55`):
   ```go
   args := append(sandboxCmd, binaryPath)  // may mutate caller's slice
   ```
   Fix: `args := append([]string(nil), sandboxCmd...)` then `args = append(args, binaryPath)`.

2. **Embed `plugin.NetRPCUnsupportedPlugin` instead of `plugin.Plugin`** (lines 59-61, 76-78, 93-95, 110-112):
   Embedding the `Plugin` interface means calling `Server()` or `Client()` on a nil-embedded interface panics. `NetRPCUnsupportedPlugin` returns proper errors instead.

## What Was Done Well

- Clean, focused API surface (3 exported functions)
- Correct proto references verified against `internal/gen/proto/plugin/v1/`
- Server-side stubs embed `Unimplemented*Server` for forward compatibility
- SPDX headers present
