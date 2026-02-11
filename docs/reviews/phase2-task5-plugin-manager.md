# Phase 2 Task 5 Review: Plugin Manager

**Bead:** sigil-anm.5
**Verdict:** PASS
**Files:** `internal/plugin/manager.go` (97 lines), `internal/plugin/manager_test.go` (109 lines)

## Spec Compliance -- PASS

All 3 required test cases present and passing:
- `TestManager_DiscoverPlugins`
- `TestManager_DiscoverSkipsInvalidManifest`
- `TestManager_RegisterCapabilities`

API surface complete: `Manager` struct, `NewManager`, `Discover(ctx)`, `Get(name)`, `List()`.

## Important Issues

1. **No logging when skipping invalid manifests** -- Spec says "logged" when skipped. Current implementation silently `continue`s on both read errors and parse errors. Recommendation: `slog.Debug` for missing files, `slog.Warn` for invalid manifests.

## Suggestions

| # | Finding | Recommendation |
|---|---------|----------------|
| S1 | Unused `ctx` parameter in `Discover` | Wire up for cancellation support as I/O grows |
| S2 | `List()` non-deterministic order | Map iteration is random. Sort by name for stable ordering. |
| S3 | No tests for `Get` and `List` | Add: Get known plugin, Get unknown (verify error), List after discovery |
| S4 | No duplicate name detection | Two subdirs with same manifest `name` silently overwrite. Add warning. |
