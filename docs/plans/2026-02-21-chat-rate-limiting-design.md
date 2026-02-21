# Chat Endpoint Rate Limiting Design (sigil-tn9)

**Date:** 2026-02-21
**Issue:** `sigil-tn9`
**Related:** `sigil-vc0`, `sigil-h7s`, `sigil-6wo`

## Goal

Define a chat-specific rate limiting strategy that protects `/api/v1/chat` and `/api/v1/chat/stream` from abuse (cost exhaustion and SSE goroutine pressure) while preserving good UX for normal users.

## Decisions

1. Use a dedicated chat limiter in addition to the existing global per-IP limiter.
2. Primary key is per authenticated user (`user:<id>`), with IP fallback in auth-disabled mode (`ip:<addr>`).
3. Enforce two layers on chat endpoints:

- request-start token bucket
- concurrent active stream cap

4. Default limits:

- `30` requests/minute per key
- burst `10`
- max concurrent streams `5`

## Current State

- Global per-IP middleware exists (`internal/server/ratelimit.go`) and is applied before auth.
- It is not chat-specific and does not enforce per-user or per-stream concurrency limits.
- Example config defaults are currently disabled for global rate limiting (`rate_limit_rps: 0`, `rate_limit_burst: 0`).

## Architecture

### Components

- Keep existing `rateLimitMiddleware` unchanged for global API protection.
- Add a chat-only limiter component for:
- `POST /api/v1/chat`
- `POST /api/v1/chat/stream`

### Key Resolution

Resolve limiter key for each chat request:

1. If `UserFromContext(ctx)` is non-nil: `user:<user_id>`
2. Else fallback to client IP: `ip:<remote_ip>`

This ensures fair limiting per user in authenticated deployments and safe fallback in dev mode.

### Enforcement Flow

For `POST /api/v1/chat`:

1. Resolve limiter key.
2. Check request-start token bucket.
3. If exceeded, return `429` and do not start stream handler.

For `POST /api/v1/chat/stream`:

1. Resolve limiter key.
2. Check request-start token bucket.
3. Acquire stream concurrency slot.
4. If slot acquisition fails, return `429`.
5. Release slot on all exits (normal completion, cancellation, encode/write failure).

## Config

Add dedicated chat limiter settings under `networking`:

- `chat_rate_limit_enabled` (bool, default `true`)
- `chat_rate_limit_rpm` (int, default `30`)
- `chat_rate_limit_burst` (int, default `10`)
- `chat_max_concurrent_streams` (int, default `5`)

Validation:

- `chat_rate_limit_rpm >= 0`
- if `chat_rate_limit_rpm > 0`, then `chat_rate_limit_burst > 0`
- if `chat_rate_limit_enabled`, then `chat_max_concurrent_streams > 0`

Compatibility:

- Existing global settings (`rate_limit_rps`, `rate_limit_burst`) remain unchanged.
- Chat limiter is separate and only affects chat endpoints.

## Error Behavior

When chat request rate is exceeded:

- HTTP `429 Too Many Requests`
- JSON body: `{"error":"chat rate limit exceeded"}`
- `Retry-After: 1`

When concurrent stream cap is exceeded:

- HTTP `429 Too Many Requests`
- JSON body: `{"error":"too many active chat streams"}`
- `Retry-After: 1`

## Observability

Log structured reject events with:

- `reason`: `request_rate_exceeded` or `concurrency_exceeded`
- `endpoint`
- `key_type`: `user` or `ip`
- `key`

## Alternatives Considered

### A. Extend existing global middleware with path-aware behavior

Pros: less new code.
Cons: mixes per-IP and per-user concerns; harder to test and reason about.

### B. Dedicated chat limiter (chosen)

Pros: explicit behavior, lower regression risk, independent tuning.
Cons: extra limiter component.

### C. Budget-coupled adaptive limiter

Pros: strongest dynamic cost control.
Cons: much larger scope and complexity for this phase.

## Testing Strategy

1. Unit tests for key resolution (auth user vs IP fallback).
2. Unit tests for request-start bucket behavior.
3. Unit tests for stream slot acquire/release, including cancel/error paths.
4. Route tests:

- `/api/v1/chat` returns `429` when over limit
- `/api/v1/chat/stream` returns `429` on rate and concurrency limits
- stream slot is released after disconnect and subsequent request can succeed

## Rollout

1. Introduce config with defaults and validation.
2. Add limiter and apply to chat handlers only.
3. Update `sigil.yaml.example` and `internal/config/sigil.yaml.default` comments.
4. Validate via tests and tune defaults if needed.

## Out of Scope

- Workspace-level quota policies.
- Cost-adaptive or budget-coupled dynamic rate limiting.
- Distributed/shared limiter state across multiple gateway instances.
