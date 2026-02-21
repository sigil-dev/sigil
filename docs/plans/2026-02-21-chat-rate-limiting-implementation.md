# Chat Endpoint Rate Limiting Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement dedicated chat endpoint rate limiting (per-user with IP fallback) with request-start throttling and concurrent stream caps for `/api/v1/chat` and `/api/v1/chat/stream`.

**Architecture:** Keep the existing global per-IP limiter intact and add a separate chat limiter used only by chat handlers. The chat limiter enforces a token bucket on request starts plus a per-key active-stream semaphore. Keys resolve to authenticated user IDs when available and fallback to remote IP when auth is disabled.

**Tech Stack:** Go, chi/huma server stack, testify, Taskfile (`task test`, `task lint`)

---

## Task 1: Add Chat Rate Limit Config Schema and Validation

**Files:**

- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `internal/config/sigil.yaml.default`
- Modify: `sigil.yaml.example`

**Step 1: Write failing config validation tests**

Add table-driven tests in `internal/config/config_test.go` for:

- valid defaults: enabled + rpm=30 + burst=10 + max_concurrent=5
- invalid negative rpm
- invalid zero burst when rpm > 0
- invalid non-positive max concurrent when enabled
- disabled limiter allows zero values

**Step 2: Run tests to verify failure**

Run: `task test`
Expected: new config validation tests fail because fields/validation do not exist yet.

**Step 3: Add config fields and validation logic**

In `internal/config/config.go`:

- Add networking fields:
  - `chat_rate_limit_enabled`
  - `chat_rate_limit_rpm`
  - `chat_rate_limit_burst`
  - `chat_max_concurrent_streams`
- Set defaults aligned with design.
- Extend `Validate()` with the approved constraints.

**Step 4: Update config templates**

In `internal/config/sigil.yaml.default` and `sigil.yaml.example`:

- Add chat limiter settings with comments.
- Keep existing global rate limiter knobs unchanged.

**Step 5: Run tests and commit**

Run: `task test`
Expected: config tests pass.

Commit:

```bash
git add internal/config/config.go internal/config/config_test.go internal/config/sigil.yaml.default sigil.yaml.example
git commit -m "feat(config): add chat-specific rate limit settings"
```

### Task 2: Implement Chat Limiter Primitive

**Files:**

- Create: `internal/server/chat_ratelimit.go`
- Create: `internal/server/chat_ratelimit_test.go`

**Step 1: Write failing unit tests for limiter behavior**

Add tests in `internal/server/chat_ratelimit_test.go` for:

- key resolution: user key vs IP fallback
- request bucket allow/deny behavior
- concurrent stream acquire/deny/release
- release safety on double-release/no-op paths

**Step 2: Run tests to verify failure**

Run: `task test`
Expected: new server limiter tests fail because implementation is missing.

**Step 3: Implement chat limiter**

In `internal/server/chat_ratelimit.go` implement:

- `ChatRateLimitConfig` (enabled/rpm/burst/maxConcurrent)
- in-memory keyed token buckets
- keyed active stream counters
- methods:
  - request allowance check
  - stream slot acquire/release
  - key resolver from context + request
- bounded in-memory map behavior (follow pattern from existing limiter)

**Step 4: Run tests and commit**

Run: `task test`
Expected: new limiter unit tests pass.

Commit:

```bash
git add internal/server/chat_ratelimit.go internal/server/chat_ratelimit_test.go
git commit -m "feat(server): add chat endpoint limiter with stream concurrency caps"
```

### Task 3: Wire Chat Limiter into Server Construction

**Files:**

- Modify: `internal/server/server.go`
- Modify: `internal/server/server_test.go`

**Step 1: Write failing wiring tests**

In `internal/server/server_test.go`, add tests for:

- server initializes chat limiter from config
- invalid chat limiter config fails server startup
- existing global limiter behavior unchanged

**Step 2: Run tests to verify failure**

Run: `task test`
Expected: server tests fail due missing config wiring.

**Step 3: Implement wiring**

In `internal/server/server.go`:

- add chat limiter config fields to `server.Config` (or mapped embedded struct)
- apply defaults and validation during `New(cfg)`
- initialize chat limiter instance on `Server`

**Step 4: Run tests and commit**

Run: `task test`
Expected: server wiring tests pass.

Commit:

```bash
git add internal/server/server.go internal/server/server_test.go
git commit -m "feat(server): wire chat limiter config into server initialization"
```

### Task 4: Enforce Request-Start Limits on `/api/v1/chat`

**Files:**

- Modify: `internal/server/routes.go`
- Modify: `internal/server/routes_test.go`

**Step 1: Write failing route tests**

In `internal/server/routes_test.go`, add tests that:

- repeated `/api/v1/chat` requests from same key eventually return `429`
- response includes expected error body and `Retry-After`
- separate users do not consume each other’s buckets

**Step 2: Run tests to verify failure**

Run: `task test`
Expected: new chat route rate-limit tests fail.

**Step 3: Add enforcement in `handleSendMessage`**

In `internal/server/routes.go`:

- resolve limiter key using user context/IP fallback
- reject before stream startup when request token not available
- return consistent `429` response format

**Step 4: Run tests and commit**

Run: `task test`
Expected: `/api/v1/chat` limiter tests pass.

Commit:

```bash
git add internal/server/routes.go internal/server/routes_test.go
git commit -m "feat(server): enforce chat request-start rate limits on /api/v1/chat"
```

### Task 5: Enforce Request + Concurrency Limits on `/api/v1/chat/stream`

**Files:**

- Modify: `internal/server/sse.go`
- Modify: `internal/server/sse_test.go`

**Step 1: Write failing SSE tests**

In `internal/server/sse_test.go`, add tests for:

- request-start limit `429` on `/api/v1/chat/stream`
- concurrent stream cap `429`
- stream slot release on normal close and cancellation

**Step 2: Run tests to verify failure**

Run: `task test`
Expected: new SSE limiter tests fail.

**Step 3: Implement SSE enforcement and safe release**

In `internal/server/sse.go`:

- apply request-start check before starting stream goroutine
- acquire stream slot before streaming
- `defer` release slot in stream response body handler
- ensure release runs on all error/early-return paths

**Step 4: Run tests and commit**

Run: `task test`
Expected: SSE limiter tests pass and no goroutine leak regressions.

Commit:

```bash
git add internal/server/sse.go internal/server/sse_test.go
git commit -m "feat(server): enforce chat stream concurrency and request limits"
```

### Task 6: Add Observability and Final Verification

**Files:**

- Modify: `internal/server/chat_ratelimit.go`
- Modify: `internal/server/ratelimit_test.go` (only if shared helper extraction is needed)

**Step 1: Add structured logs for limiter rejects**

Log fields:

- `reason` (`request_rate_exceeded` | `concurrency_exceeded`)
- `endpoint`
- `key_type`
- `key`

**Step 2: Add/adjust tests for logging-sensitive paths as needed**

Prefer behavior assertions; only assert logs where existing test conventions support it.

**Step 3: Run full verification suite**

Run:

- `task test`
- `task lint`

Expected:

- all tests pass
- lints pass

**Step 4: Commit verification-ready changes**

```bash
git add internal/server/chat_ratelimit.go internal/server/ratelimit_test.go
git commit -m "chore(server): add chat limiter observability and finalize validation"
```

### Task 7: Bead Lifecycle and Integration

**Files:**

- Modify: `.beads/issues.jsonl` (via `bd` CLI)

**Step 1: Link implementation outcome to design bead**

Run:

```bash
bd comment sigil-tn9 --text "Design implemented via approved plan; see commits and tests." --json
```

**Step 2: Close design bead and update implementation bead(s)**

Run:

```bash
bd close sigil-tn9 --reason "Design completed and implemented" --json
bd update sigil-vc0 --status in_progress --json
```

**Step 3: Sync and verify clean state**

Run:

```bash
bd sync --json
git status -sb
```
