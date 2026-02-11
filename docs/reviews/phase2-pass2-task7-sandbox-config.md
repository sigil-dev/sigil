# Phase 2 Task 7 Review (Pass 2): Process-Tier Sandbox Configuration

**Bead:** sigil-anm.7
**Files:** `internal/plugin/sandbox/sandbox.go` (224 lines), `sandbox_test.go` (81 lines), `sandbox_internal_test.go` (371 lines)
**Verdict:** PASS
**Tests:** 24/24 passing (1 SKIP: Linux-only on Darwin)

## Critical Bug Fix Verification (sigil-anm.9)

All 5 fixes from commit `536d051` verified solid:

1. **Seatbelt path injection:** `validateSandboxPath` regex blocklist (`"`, `\`, `(`, `)`, `;`, control chars, dash prefix). Applied in all 4 code paths. 15 test cases for path validation.
2. **Single-path Seatbelt syntax:** One `(subpath ...)` rule per path. Tested by `TestSeatbeltProfile_SinglePathPerFilter`.
3. **Network host:port enforcement:** Per-entry port-specific rules via `net.SplitHostPort` with range validation. 5 network tests.
4. **Conditional `/lib64`:** `checkDirExists` guard with test stubbing. Both scenarios tested.
5. **bwrap path validation:** Dash-prefix rejection + `--` separator before binary path. 3 test cases.

## Security Analysis

Character blocklist is complete for Seatbelt injection prevention. bwrap argument injection prevented by `--` separator and dash-prefix rejection.

**Known limitation:** Seatbelt network rules use `*:port` (any host on port). This is a Seatbelt platform limitation, not a code bug. Hostname filtering requires userspace proxy.

## New Findings (Informational)

- **N1:** Seatbelt `*:port` allows any host (platform limitation)
- **N2:** `expandPath` handles `~` but not `~user` syntax (unlikely to trigger)

## Open Items

7 suggestions tracked in sigil-anm.21 (P3): seccomp filters, `--unshare-pid`, ReadDeny docs, expandPath error handling, binaryPath validation, profile to file, container tier nil return.
