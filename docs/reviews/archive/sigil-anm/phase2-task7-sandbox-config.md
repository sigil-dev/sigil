# Phase 2 Task 7 Review: Process-Tier Sandbox Configuration

**Bead:** sigil-anm.7
**Verdict:** PASS with gaps
**Files:** `internal/plugin/sandbox/sandbox.go` (148 lines), `internal/plugin/sandbox/sandbox_test.go` (80 lines)

## Spec Compliance

Core requirements met: correct function signature, platform switching, nil return for non-process tiers. All 3 spec test cases present.

## Critical Issues

1. **Seatbelt profile path injection** (`sandbox.go:114`): Manifest-supplied paths interpolated unsanitized into Seatbelt profile via `fmt.Sprintf`. A crafted path like `/data") (allow default) (version 1) ("` can inject `(allow default)`, disabling all sandboxing.
   - **Fix:** Sanitize paths (reject `"`, `(`, `)`, non-printable chars) or write profile to temp file and use `-f` instead of `-p`.

2. **Invalid Seatbelt `(path ...)` syntax** (lines 105-106): Multiple paths passed to a single `(path ...)` filter. Seatbelt's `path` filter accepts only a single argument. Rules will not match correctly.
   - **Fix:** Separate rules per path, or use `(subpath ...)` for directory trees.

## Important Issues

3. **Network rule ignores specific host:port** (line 131): `(allow network* (remote tcp))` allows ALL TCP when any `Allow` entry exists. Should respect the specific hosts/ports in the manifest.

4. **Missing test coverage:**
   - Unsupported OS error path (line 42)
   - Empty sandbox config
   - Seatbelt profile content validation (Darwin test only checks `args[0]`)
   - Path injection testing

5. **`/lib64` unconditionally mounted** (line 51): Not all Linux distros have `/lib64`. Bwrap will fail on systems without it.

6. **bwrap path validation**: Manifest paths starting with `--` could confuse bwrap's argument parser.

## Suggestions

| # | Finding | Recommendation | Resolution |
|---|---------|----------------|------------|
| S1 | Seccomp filters absent | Design doc mentions them for Linux. File follow-up issue. | TODO comment in sandbox.go (deferred — needs per-arch BPF filter work) |
| S2 | No `--unshare-pid` | Standard bwrap hardening measure. | **Closed:** sigil-anm.21 |
| S3 | ReadDeny mapped to `--tmpfs` | Document this design choice (hides content vs permission denied). | **Closed:** sigil-anm.21 (block comment explaining tmpfs overlay design) |
| S4 | `expandPath` error handling | Silently swallows `os.UserHomeDir()` errors. Log warning. | **Closed:** sigil-anm.21 + sigil-anm.24 (returns error, ~user syntax documented) |
| S5 | No `binaryPath` validation | Empty string or spaces produce broken args. | **Closed:** sigil-anm.21 (empty check + validateSandboxPath) |
| S6 | Write profile to file | Avoids argument-length limits and shell-escaping. | **Closed:** sigil-anm.21 (temp file via -f, lifecycle documented) |
| S7 | Container tier returns nil silently | Could mask configuration errors. | **Closed:** sigil-anm.21 (returns descriptive error) |
