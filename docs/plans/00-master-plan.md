# Sigil Implementation Plan — Master Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the full Sigil gateway from scaffold to working system, following the design in `docs/design/` (Sections 0–11).

**Architecture:** Bottom-up build order driven by dependency graph. Storage interfaces and proto definitions are foundational. Security enforcer must exist before plugin host or agent core. Each phase produces a testable, working subsystem before the next phase begins.

**Tech Stack:** Go 1.25+, CGO_ENABLED=1, buf (protobuf), mattn/go-sqlite3, asg017/sqlite-vec, hashicorp/go-plugin, tetratelabs/wazero, huma+chi (HTTP), cobra+viper (CLI), SvelteKit (UI), Tauri v2 (desktop)

---

## TDD Requirement

Every phase follows strict Test-Driven Development:

1. Write the failing test first
2. Run it — confirm it fails for the right reason
3. Write minimal implementation to make it pass
4. Run it — confirm it passes
5. Refactor if needed
6. Commit

Tests live next to implementation: `foo.go` → `foo_test.go`. Use table-driven tests with testify assertions. Integration tests use `//go:build integration` tag.

All test/build/lint operations use `task` commands per CLAUDE.md.

---

## Phase Overview

| Phase | Name                 | Doc                                                                      | Key Deliverables                                                                               | Est. Tasks |
| ----- | -------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- | ---------- |
| 1     | Foundation           | [01-phase-1-foundation.md](01-phase-1-foundation.md)                     | Proto defs, storage interfaces, SQLite backends, config, provider interfaces, plugin SDK types | 14         |
| 2     | Core Runtime         | [02-phase-2-core-runtime.md](02-phase-2-core-runtime.md)                 | Security enforcer, plugin host, sandboxing, Wasm tier                                          | 8          |
| 3     | Agent Core           | [03-phase-3-agent-core.md](03-phase-3-agent-core.md)                     | Agent loop, sessions, tool dispatch, tiered memory, skills                                     | 8          |
| 4     | Platform Integration | [04-phase-4-platform-integration.md](04-phase-4-platform-integration.md) | Workspaces, channels, providers, built-in LLM providers                                        | 7          |
| 5     | Server & API         | [05-phase-5-server-api.md](05-phase-5-server-api.md)                     | HTTP server, REST+SSE endpoints, OpenAPI gen, CLI                                              | 7          |
| 6     | Advanced Features    | [06-phase-6-advanced-features.md](06-phase-6-advanced-features.md)       | Nodes, container tier, memory compaction, Tailscale                                            | 6          |
| 7     | UI & Distribution    | [07-phase-7-ui-distribution.md](07-phase-7-ui-distribution.md)           | SvelteKit UI, Tauri desktop, GoReleaser, doc site                                              | 6          |

---

## Dependency Graph

```text
Phase 1: Foundation
  ├── Proto definitions (no deps)
  ├── Storage interfaces (no deps)
  ├── SQLite implementations (depends on: interfaces)
  ├── Store factory (depends on: interfaces, SQLite impls)
  ├── Config management (no deps)
  ├── Provider interfaces (no deps)
  └── Plugin SDK types (depends on: proto)
        │
        v
Phase 2: Core Runtime
  ├── Capability model (no deps)
  ├── Security enforcer (depends on: capabilities)
  ├── Plugin manifest (depends on: capabilities, plugin SDK)
  ├── Plugin lifecycle (depends on: manifest, enforcer)
  ├── go-plugin host (depends on: lifecycle, proto)
  ├── Sandbox config (depends on: manifest)
  └── Wasm host (depends on: lifecycle)
        │
        v
Phase 3: Agent Core
  ├── Session management (depends on: SessionStore)
  ├── Agent loop (depends on: sessions, enforcer, provider interfaces [Phase 1])
  ├── Tool dispatch (depends on: agent loop, enforcer, plugin host)
  ├── Memory tools (depends on: MemoryStore, VectorStore)
  ├── Skills loading (depends on: workspace config)
  └── Compaction lifecycle (depends on: memory tools)
        │
        v
Phase 4: Platform Integration
  ├── Workspace manager (depends on: store factory, enforcer)
  ├── Channel system (depends on: plugin host, identity)
  ├── Provider registry (depends on: plugin host)
  └── Built-in providers: Anthropic, OpenAI, Google, OpenRouter (depends on: provider registry)
        │
        v
Phase 5: Server & API
  ├── HTTP server (depends on: workspace, agent, channels)
  ├── REST endpoints (depends on: HTTP server)
  ├── SSE streaming (depends on: HTTP server, agent)
  ├── OpenAPI gen (depends on: REST endpoints)
  └── CLI (depends on: HTTP server)
        │
        v
Phase 6: Advanced Features     Phase 7: UI & Distribution
  ├── Node system                 ├── SvelteKit UI
  ├── Container tier              ├── Tauri desktop
  ├── Tailscale integration       ├── GoReleaser config
  └── Memory compaction (full)    └── Doc site
```

Phases 6 and 7 can run in parallel after Phase 5.

---

## Phase Gates

Each phase has exit criteria that MUST pass before moving to the next phase.

### Gate 1: Foundation Complete

- [ ] All proto definitions compile via `buf generate` with no errors
- [ ] Generated Go code exists in `internal/gen/proto/`
- [ ] All four storage interfaces defined with full method signatures
- [ ] All storage domain types defined (Session, Message, Entity, etc.)
- [ ] SQLite SessionStore passes all CRUD + active window tests
- [ ] SQLite MessageStore passes FTS5 search tests
- [ ] SQLite SummaryStore passes store/retrieve tests
- [ ] SQLite KnowledgeStore passes entity/relationship/fact/traversal tests
- [ ] SQLite VectorStore passes store/search/delete tests
- [ ] SQLite GatewayStore (User, Pairing, Audit) passes all CRUD tests
- [ ] Store factory creates correct backends from config
- [ ] Viper config loads, validates, and watches for changes
- [ ] Provider interfaces defined in `internal/provider/` and compile
- [ ] Plugin SDK types compile and are importable from `pkg/plugin/`
- [ ] `task test` passes with zero failures
- [ ] `task lint` passes with zero errors

### Gate 2: Core Runtime Complete

- [ ] Capability glob matching works for all patterns (exact, wildcard, path-scoped)
- [ ] Enforcer correctly allows/denies based on three-way intersection: plugin caps ∩ workspace allow ∩ user permissions
- [ ] All enforcer decisions are audit-logged
- [ ] Plugin manifests parse and validate (capabilities, schema, version constraints)
- [ ] Plugin lifecycle state machine works: discover → validate → load → register → drain → stop
- [ ] go-plugin host starts/stops plugin subprocesses
- [ ] Sandbox config generates correct bwrap/sandbox-exec profiles from manifest
- [ ] Wasm host loads and executes .wasm modules via Wazero
- [ ] `task test` passes, `task lint` passes

### Gate 3: Agent Core Complete

- [ ] Session CRUD works through SessionStore
- [ ] Session lanes serialize concurrent messages per-session
- [ ] Agent loop processes a message through all 6 pipeline stages (mapping to design doc's 7 integrity steps — see Phase 3 Task 3 note for mapping)
- [ ] Tool dispatch validates capabilities before execution
- [ ] Tool results are scanned for injection patterns
- [ ] Memory tools (search, summary, recall, semantic) return correct results
- [ ] Skills load from agentskills.io markdown format
- [ ] Compaction triggers correctly at batch_size threshold
- [ ] `task test` passes, `task lint` passes

### Gate 4: Platform Integration Complete

- [ ] Workspace manager routes messages to correct workspace
- [ ] Workspace tool allowlists are enforced
- [ ] Channel plugins can stream inbound messages and send outbound
- [ ] Identity resolution maps platform users to canonical IDs
- [ ] Pairing modes work (open, allowlist, pair_on_request, pair_with_code, closed)
- [ ] Provider registry discovers and routes to providers
- [ ] Failover chain works when primary provider fails
- [ ] Budget enforcement denies requests exceeding limits
- [ ] Built-in providers (Anthropic, OpenAI, Google, OpenRouter) send/receive streaming chat
- [ ] `task test` passes, `task lint` passes

### Gate 5: Server & API Complete

- [ ] HTTP server starts on configured address
- [ ] REST endpoints for workspaces, plugins, sessions, users respond correctly
- [ ] SSE endpoint streams agent responses in real-time
- [ ] OpenAPI 3.1 spec generates from Go types
- [ ] CLI `sigil start` launches the gateway
- [ ] CLI `sigil status` reports health
- [ ] CLI `sigil chat` sends a message and receives a response
- [ ] CLI `sigil doctor` runs diagnostics
- [ ] `task test` passes, `task lint` passes

### Gate 6: Advanced Features Complete

- [ ] Nodes register with gateway and expose tools
- [ ] Node tools appear with `node:<id>` prefix in workspace
- [ ] Container tier starts plugins in OCI containers
- [ ] Tailscale integration works (tsnet, tag-based auth)
- [ ] Memory compaction runs full lifecycle (active → Tier 1 → summarize → facts → embeddings)
- [ ] `task test` passes, `task lint` passes

### Gate 7: UI & Distribution Complete

- [ ] SvelteKit UI loads in browser with chat, workspace, plugin, settings views
- [ ] OpenAPI TypeScript client generated from spec
- [ ] Tauri app launches with bundled gateway sidecar
- [ ] GoReleaser builds cross-platform binaries
- [ ] Doc site builds and serves
- [ ] Pre-release checklist items from `docs/decisions/pre-release-checklist.md` are addressed
- [ ] `task test` passes, `task lint` passes

---

## Conventions

### File Organization

All new Go files follow the directory structure in `docs/design/10-build-and-distribution.md`. Tests live next to implementation.

### SPDX Headers

All `.go`, `.sh`, `.proto` files MUST include:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors
```

Auto-added by lefthook pre-commit hook. Do NOT add to `*.pb.go` generated files.

### Commits

Conventional commits enforced by Cocogitto: `type(scope): description`

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`

### Error Handling

Use `fmt.Errorf` with `%w` for wrapping. Structured errors at API boundaries.

### Logging

Use `log/slog` with structured fields. Include context: plugin name, workspace ID, session ID.

---

## How to Execute

Each phase document contains tasks broken into TDD steps. Two execution approaches:

**1. Subagent-Driven (recommended):** Use `superpowers:subagent-driven-development` — dispatch a fresh subagent per task, review between tasks.

**2. Sequential:** Work through tasks in order within a single session, using `superpowers:executing-plans`.

Within each phase, tasks are numbered and ordered by dependency. Complete them in order unless explicitly marked as parallelizable.
