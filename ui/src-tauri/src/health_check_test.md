# Sidecar Error Visibility Testing Guide

This document describes how to test the sidecar error visibility implementation.

## What Was Implemented

Per PR #16 review feedback, we implemented BOTH approaches for sidecar error visibility:

### Part 1: UI Event Listener (SvelteKit)
- Location: `ui/src/routes/+layout.svelte`
- Listens for `sidecar-error` and `sidecar-ready` events from Tauri
- Displays a prominent red error banner when sidecar fails to start
- Error banner can be dismissed by user

### Part 2: Tauri Health Check (Rust)
- Location: `ui/src-tauri/src/main.rs`
- After spawning sidecar, waits 1 second then checks `/health` endpoint
- Makes HTTP request to `http://localhost:18789/health`
- Emits `sidecar-error` event if health check fails
- Emits `sidecar-ready` event if health check succeeds

## How They Work Together

1. Tauri spawns the sidecar process
2. Health check thread starts, waits 1 second
3. Health check makes HTTP request to `/health` endpoint
4. If request succeeds (200 OK):
   - Emits `sidecar-ready` event
   - UI clears any error state
5. If request fails (connection refused, timeout, non-200):
   - Emits `sidecar-error` event with descriptive message
   - UI displays red error banner with message

## Testing Scenarios

### Scenario 1: Normal Startup
1. Build and run Tauri app with sidecar binary in place
2. Expected: No error banner, sidecar starts normally
3. Check console for "Sigil gateway health check passed"

### Scenario 2: Sidecar Binary Missing
1. Remove or rename sidecar binary
2. Run Tauri app
3. Expected: Red error banner appears immediately
4. Message: "Failed to start gateway: [error details]"

### Scenario 3: Port Already in Use
1. Manually start Sigil on port 18789: `sigil start`
2. Run Tauri app (which tries to start another instance)
3. Expected: Red error banner after 1 second
4. Message: "Sigil gateway failed health check - service not responding"

### Scenario 4: Delayed Startup
1. Modify health check delay if needed to test timing
2. Expected: Error banner only appears if health check fails after delay
3. This tests that the health check waits for gateway to start

## Files Changed

### Rust (Tauri)
- `ui/src-tauri/Cargo.toml`: Added `ureq = "2"` dependency, fixed features
- `ui/src-tauri/src/main.rs`:
  - Added `health_check_sidecar()` function
  - Modified `start_sidecar()` to spawn health check thread
  - Emits `sidecar-error` or `sidecar-ready` events

### SvelteKit (UI)
- `ui/src/routes/+layout.svelte`:
  - Added event listeners for `sidecar-error` and `sidecar-ready`
  - Added error banner UI component with styling
  - Error banner is dismissable

## Known Limitations

### Build Issue
The Tauri app currently requires the sidecar binary to be present at build time. The binary path is defined in `ui/src-tauri/tauri.conf.json`:

```json
"externalBin": [
  "binaries/sigil"
]
```

Tauri expects this to expand to `binaries/sigil-<target>` (e.g., `binaries/sigil-aarch64-apple-darwin`).

**To build successfully:**
1. First build the Sigil binary: `task build` from repo root
2. Copy binary to Tauri expected location:
   ```bash
   mkdir -p ui/src-tauri/binaries
   cp target/release/sigil ui/src-tauri/binaries/sigil-aarch64-apple-darwin
   ```
3. Then build Tauri app

This is a normal requirement for sidecar-based Tauri apps.

## Implementation Notes

### Why Both Approaches?

1. **Immediate Spawn Errors**: The existing error handler (line 181 in original) catches immediate failures (binary missing, permissions)
2. **Silent Startup Failures**: The health check catches cases where spawn succeeds but the process fails to start properly (port in use, config error, crash during init)

Both are necessary for comprehensive error coverage.

### Health Check Details

- **URL**: `http://localhost:18789/health` (matches `client.ts` default port)
- **Timeout**: 3 seconds for HTTP request
- **Delay**: 1 second after spawn before checking
- **Library**: `ureq` for simple synchronous HTTP (no async runtime needed)

### Event Flow

```
start_sidecar()
    ├─> spawn sidecar process
    │   └─> if spawn fails: emit sidecar-error immediately
    │
    └─> spawn health check thread
        ├─> sleep 1 second
        └─> HTTP GET /health
            ├─> if 200 OK: emit sidecar-ready
            └─> if error: emit sidecar-error
```

## Future Enhancements

1. **Retry Logic**: Could add automatic retry with backoff
2. **User Action**: Add "Restart Gateway" button in error banner
3. **Diagnostics**: Include more diagnostic info in error messages
4. **Logs**: Link to log file location in error banner
5. **Health Check Interval**: Periodic health checks after startup

